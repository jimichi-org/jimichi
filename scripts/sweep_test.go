package scripts

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
// the case makes; runs sweep.sh on it and returns the docker calls it made and
// the revision HEAD names
func sweep(t *testing.T, change func(t *testing.T, env []string, root string)) (calls []string, head, stderr string, err error) {
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
		"lab/metrics/auc.go":     "package metrics\n",
		"relay/relay.go":         "package relay\n",
		// the patterns the repository once had, wide enough to hide sources,
		// and the notes kept out of it
		".gitignore": "artifacts/\n*.test\ncore.*\ncoverage.*\n.dev/\n",
		// deploy and scripts stay out of the image; Docker trims the blanks
		// around lab and e2e
		".dockerignore": "# the module only\n*\n!go.mod\n!go.sum\n!cmd\n!e2e\r\n!internal\n  ! lab \t\n!pki\n!relay\n**/*.md\n**/*_test.go\n",
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
	recorded := filepath.Join(bin, "calls")
	cmd := exec.Command(shell, script(t, "sweep.sh"), "-flows", "3")
	cmd.Dir = root
	cmd.Env = append(env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "DOCKER_CALLS="+filepath.ToSlash(recorded))
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err = cmd.Run()
	text, readErr := os.ReadFile(recorded)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	if trimmed := strings.TrimSpace(string(text)); trimmed != "" {
		calls = strings.Split(trimmed, "\n")
	}
	return calls, head, errOut.String(), err
}

// the revision sweep.sh names after the change
func sweepRev(t *testing.T, change func(t *testing.T, env []string, root string)) (got, head string) {
	t.Helper()
	calls, head, stderr, err := sweep(t, change)
	if err != nil {
		t.Fatalf("sweep.sh: %v\n%s", err, stderr)
	}
	if len(calls) != 2 || calls[0] != "build -q --build-arg TARGET=lab -t jimichi/lab:dev ." {
		t.Fatalf("docker calls:\n%s", strings.Join(calls, "\n"))
	}
	f := strings.Fields(calls[1])
	if len(f) < 4 || f[0] != "run" || f[len(f)-4] != "-rev" || f[len(f)-2] != "-flows" || f[len(f)-1] != "3" {
		t.Fatalf("docker run: %s", calls[1])
	}
	return f[len(f)-3], head
}

// without .dockerignore the image would take the whole tree and sweep.sh could
// not tell which hidden files it holds
func TestSweepStopsWithoutDockerignore(t *testing.T) {
	calls, _, _, err := sweep(t, func(t *testing.T, _ []string, root string) {
		if err := os.Remove(filepath.Join(root, ".dockerignore")); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil {
		t.Error("sweep.sh succeeded")
	}
	if len(calls) != 0 {
		t.Errorf("docker calls:\n%s", strings.Join(calls, "\n"))
	}
}

// any change in the tree makes the revision dirty, staged or not, tracked or
// new, in a directory the script never heard of as well, and a Go, assembly or
// system object file that .gitignore hides inside a directory the image takes;
// reports in artifacts, the documentation in docs, ignored files that are not
// sources and ignored sources outside the image context leave it clean
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
		{"a metric changed", edit("lab/metrics/auc.go"), true},
		{"a new file in lab", edit("lab/scenario/deny.go"), true},
		{"a relay file changed", edit("relay/relay.go"), true},
		{"a Go file .gitignore hides", edit("lab/metrics/coverage.go"), true},
		{"a Go file .gitignore hides in a new package", edit("relay/core/core.go"), true},
		{"a Go file .gitignore hides in a directory named with a digit", edit("e2e/coverage.go"), true},
		{"an assembly file .gitignore hides", edit("relay/core.s"), true},
		{"a system object .gitignore hides", edit("cmd/lab/coverage.syso"), true},
		{"an assembly file .gitignore hides outside the image", edit("deploy/core.s"), false},
		{"a C file .gitignore hides, the module has no cgo", edit("relay/core.c"), false},
		{"a test binary .gitignore hides", edit("relay/relay.test"), false},
		{"a core dump .gitignore hides", edit("relay/core.1234"), false},
		{"a Go file in an ignored .dev", edit(".dev/tools/e2eref/gocomp/main.go"), false},
		{"an ignored .dev that is a repository of its own", func(t *testing.T, env []string, root string) {
			dev := filepath.Join(root, ".dev")
			write(t, dev, "tools/e2eref/gocomp/main.go", "package main\n")
			git(t, env, dev, "init", "-q")
			git(t, env, dev, "add", ".")
			git(t, env, dev, "commit", "-q", "-m", "notes")
		}, false},
		{"a Go file .gitignore hides outside the image", edit("deploy/base/coverage.go"), false},
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

// the repository ignores build and run output, never a name a source could take
func TestGitignoreHidesNoSource(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	env := gitEnv(t)
	ignored := func(path string) bool {
		cmd := exec.Command("git", "check-ignore", "-q", "--no-index", path)
		cmd.Dir, cmd.Env = root, env
		err := cmd.Run()
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
			return false
		}
		if err != nil {
			t.Fatalf("git check-ignore %s: %v", path, err)
		}
		return true
	}
	for _, path := range []string{"relay/core.go", "lab/metrics/coverage.go", "core/core.go", "crypto/secmem/core_linux.go", "lab/output.go", "client/test.go", "relay/core_amd64.s", "cmd/relay/rsrc_windows_amd64.syso"} {
		if ignored(path) {
			t.Errorf("%s is ignored", path)
		}
	}
	for _, path := range []string{"artifacts/summary.json", "core.1234", "relay/core.77", "dump.core", "coverage.out", "coverage.html", "relay.test", ".dev/DECISIONS.md", "CLAUDE.local.md"} {
		if !ignored(path) {
			t.Errorf("%s is not ignored", path)
		}
	}
}

var byteOrderMark = string(rune(0xfeff))

// sweep.sh checks for hidden sources only in the directories .dockerignore lets
// back in, so the file has to stay an allow-list and name each of them as a
// lowercase word; the lines are read as Docker reads them: a comment is a line
// that starts with #, the rest is trimmed, and so is the pattern after !
func dockerignoreFaults(text string) []string {
	dir := regexp.MustCompile(`^[a-z0-9]+$`)
	var faults []string
	patterns, dirs := 0, 0
	for _, raw := range strings.Split(strings.TrimPrefix(text, byteOrderMark), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(raw, "#") || line == "" {
			continue
		}
		if patterns++; patterns == 1 && line != "*" {
			faults = append(faults, fmt.Sprintf("the first pattern is %q, not *", line))
		}
		name, ok := strings.CutPrefix(line, "!")
		name = strings.TrimSpace(name)
		switch {
		case !ok || name == "go.mod" || name == "go.sum":
		case dir.MatchString(name):
			dirs++
		default:
			faults = append(faults, fmt.Sprintf("sweep.sh does not read %q", raw))
		}
	}
	if patterns == 0 {
		faults = append(faults, "no pattern, the image takes everything")
	}
	if dirs == 0 {
		faults = append(faults, "no directory let in")
	}
	return faults
}

func TestDockerignoreLetsInOnlyWhatSweepReads(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("..", ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range dockerignoreFaults(string(text)) {
		t.Error(fault)
	}
}

func TestDockerignoreFaults(t *testing.T) {
	for _, c := range []struct {
		name, text string
		faults     int
	}{
		{"an allow-list", "*\n!go.mod\n!go.sum\n!lab\n**/*_test.go\n", 0},
		{"blanks Docker trims", "# notes\n\n  *\t\n  !lab  \n!\trelay\r\n", 0},
		{"a byte order mark", byteOrderMark + "*\n!lab\n", 0},
		{"a commented directory", "*\n!lab\n#!relay\n", 0},
		{"a directory with a slash", "*\n!lab\n!relay/\n", 1},
		{"a nested directory", "*\n!lab\n!relay/core\n", 1},
		{"a pattern", "*\n!lab\n!relay*\n", 1},
		{"a file", "*\n!lab\n!Makefile\n", 1},
		{"no directory", "*\n!go.mod\n", 1},
		{"not an allow-list", "artifacts\n!lab\n", 1},
		{"the allow-list after a comment that is not one", " #notes\n*\n!lab\n", 1},
		{"nothing", "", 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := dockerignoreFaults(c.text); len(got) != c.faults {
				t.Fatalf("faults %q, want %d", got, c.faults)
			}
		})
	}
}
