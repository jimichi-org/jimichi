package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// records every call; sweep.sh builds the image and runs it, nothing else
const dockerStandIn = `#!/usr/bin/env bash
echo "$*" >>"$DOCKER_CALLS"
`

// a git of its own: no system or user configuration and no repository of the
// environment can reach the test
func gitEnv(t *testing.T) []string {
	t.Helper()
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}
	return append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+filepath.ToSlash(empty))
}

func git(t *testing.T, env []string, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, root, name, text string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// a committed tree with code, scripts, a README and documents, then the change
// the case makes; returns the revision the script names
func sweepRev(t *testing.T, change func(t *testing.T, env []string, root string)) (got, head string) {
	t.Helper()
	shell := bash(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	env := gitEnv(t)
	root, bin := t.TempDir(), t.TempDir()
	for name, text := range map[string]string{
		"go.mod":                 "module example\n",
		"README.md":              "readme\n",
		"pki/cert.go":            "package pki\n",
		"internal/fetch/a.go":    "package fetch\n",
		"cmd/lab/main.go":        "package main\n",
		"scripts/x.sh":           "true\n",
		"docs/ru/ARCH.md":        "doc\n",
		"docs/en/ARCH.md":        "doc\n",
		"deploy/base/relay.yaml": "kind: x\n",
	} {
		write(t, root, name, text)
	}
	git(t, env, root, "init", "-q")
	git(t, env, root, "add", ".")
	git(t, env, root, "commit", "-q", "-m", "tree")
	head = git(t, env, root, "rev-parse", "--short", "HEAD")
	change(t, env, root)

	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(dockerStandIn), 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(bin, "calls")
	cmd := exec.Command(shell, script(t, "sweep.sh"), "-flows", "3")
	cmd.Dir = root
	cmd.Env = append(env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "DOCKER_CALLS="+filepath.ToSlash(calls))
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("sweep.sh: %v\n%s", err, errOut.String())
	}
	recorded, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(recorded)), "\n")
	if len(lines) != 2 || lines[0] != "build -q --build-arg TARGET=lab -t jimichi/lab:dev ." {
		t.Fatalf("docker calls:\n%s", recorded)
	}
	f := strings.Fields(lines[1])
	if len(f) < 4 || f[0] != "run" || f[len(f)-4] != "-rev" || f[len(f)-2] != "-flows" || f[len(f)-1] != "3" {
		t.Fatalf("docker run: %s", lines[1])
	}
	return f[len(f)-3], head
}

// any change in the tree makes the revision dirty, staged or not, tracked or
// new, in a directory the script never heard of as well; reports in artifacts
// and the documentation in docs leave it clean
func TestSweepMarksAnyChangeOutsideArtifactsAndDocsDirty(t *testing.T) {
	edit := func(name string) func(t *testing.T, env []string, root string) {
		return func(t *testing.T, env []string, root string) { write(t, root, name, "changed\n") }
	}
	for _, c := range []struct {
		name   string
		change func(t *testing.T, env []string, root string)
		dirty  bool
	}{
		{"nothing", func(*testing.T, []string, string) {}, false},
		{"a document changed", edit("docs/ru/ARCH.md"), false},
		{"a new document", edit("docs/en/GLOSSARY.md"), false},
		{"a report", edit("artifacts/summary-main.json"), false},
		{"a package changed", edit("pki/cert.go"), true},
		{"a new file in a package", edit("internal/fetch/b.go"), true},
		{"a new package", edit("conversation/conversation.go"), true},
		{"go.mod changed", edit("go.mod"), true},
		{"the README changed", edit("README.md"), true},
		{"a script changed", edit("scripts/x.sh"), true},
		{"a manifest changed", edit("deploy/base/relay.yaml"), true},
		{"a change staged", func(t *testing.T, env []string, root string) {
			write(t, root, "cmd/lab/main.go", "package main\n\nfunc main() {}\n")
			git(t, env, root, "add", "cmd/lab/main.go")
		}, true},
		{"a file deleted", func(t *testing.T, env []string, root string) {
			if err := os.Remove(filepath.Join(root, "pki", "cert.go")); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a document and a package changed", func(t *testing.T, env []string, root string) {
			write(t, root, "docs/ru/ARCH.md", "changed\n")
			write(t, root, "pki/cert.go", "changed\n")
		}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, head := sweepRev(t, c.change)
			want := head
			if c.dirty {
				want += "-dirty"
			}
			if got != want {
				t.Fatalf("-rev %s, want %s", got, want)
			}
		})
	}
}
