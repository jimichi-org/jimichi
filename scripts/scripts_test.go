// Package scripts holds the testbed scripts; its tests run them with bash
// against stand-ins for kubectl and go.
package scripts

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// answers the one request the scripts make before they check the number of
// relays, the list of relay deployments, and records every call; the client
// deployments exist as CLIENT_A and CLIENT_B say, and client-a selects the
// label client=CLIENT_A_SELECTOR
const kubectlStandIn = `#!/usr/bin/env bash
echo "$*" >>"$KUBECTL_CALLS"
case "$*" in
  *"get deployment -l app=relay"*)
    for i in $(seq 1 "$RELAY_COUNT"); do echo "relay-$i"; done ;;
  *"get deployment client-a -o jsonpath"*)
    [ -n "${CLIENT_A:-}" ] || exit 1
    printf '%s' "${CLIENT_A_SELECTOR:-}" ;;
  *"get deployment client-a"*)
    [ -n "${CLIENT_A:-}" ] || exit 1 ;;
  *"get deployment client-b"*)
    [ -n "${CLIENT_B:-}" ] || exit 1 ;;
esac
`

// enroll.sh builds cmd/jimichi before it looks at the relays
const goStandIn = `#!/usr/bin/env bash
exit 0
`

func bash(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash to run the scripts with")
	}
	// on a Windows host the bash of WSL shares neither the paths nor the
	// environment of this process
	if runtime.GOOS == "windows" {
		kernel, err := exec.Command(path, "-c", "uname -s").Output()
		if err != nil || !strings.HasPrefix(string(kernel), "MINGW") && !strings.HasPrefix(string(kernel), "MSYS") {
			t.Skip("the bash found is not Git Bash")
		}
	}
	return path
}

func script(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(filepath.Join(dir, name))
}

// runs bash in an empty directory with the stand-ins first in PATH and the
// testbed holding the given number of relays
func run(t *testing.T, relays int, args ...string) (status int, stderr, calls string) {
	t.Helper()
	return runEnv(t, relays, nil, args...)
}

func runEnv(t *testing.T, relays int, env []string, args ...string) (status int, stderr, calls string) {
	t.Helper()
	shell := bash(t)
	bin, work := t.TempDir(), t.TempDir()
	for name, text := range map[string]string{"kubectl": kubectlStandIn, "go": goStandIn} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(bin, "calls")
	cmd := exec.Command(shell, args...)
	cmd.Dir = work
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"KUBECTL_CALLS="+filepath.ToSlash(log),
		"RELAY_COUNT="+strconv.Itoa(relays),
	)
	cmd.Env = append(cmd.Env, env...)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile(log)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), errOut.String(), string(recorded)
}

// relay 100 would be forwarded to the base + 100, which reaches the next port
// base: 19100 + 100 for the counters, 19200 + 100 for enrollment. Places start
// at 1, so that port is not yet one another relay is forwarded to and the
// bound of 99 leaves one port of margin. Both scripts refuse after listing the
// relays and before they forward anything
func TestScriptsRefuseMoreRelaysThanTheirPortsHold(t *testing.T) {
	for _, name := range []string{"stats.sh", "enroll.sh"} {
		status, stderr, calls := run(t, 100, script(t, name))
		if status != 1 || !strings.Contains(stderr, "more than 99 relays") {
			t.Errorf("%s with 100 relays: status %d, stderr %q; want 1 and the refusal", name, status, stderr)
		}
		if !strings.Contains(calls, "get deployment -l app=relay") || strings.Count(calls, "\n") != 1 {
			t.Errorf("%s with 100 relays asked the cluster for more than the list of relays:\n%s", name, calls)
		}
	}
}

func TestPortsFitUpToNinetyNineRelays(t *testing.T) {
	check := `. "$1"; ports_fit "$(relays)"`
	for _, c := range []struct{ relays, status int }{{1, 0}, {99, 0}, {100, 1}, {250, 1}} {
		status, stderr, _ := run(t, c.relays, "-c", check, "bash", script(t, "lib.sh"))
		if status != c.status || (c.status != 0) != strings.Contains(stderr, "more than 99 relays") {
			t.Errorf("%d relays: status %d, stderr %q; want status %d", c.relays, status, stderr, c.status)
		}
	}
}

// the selector of a deployment cannot change: a client-a that selects only
// app=client is deleted before the manifest of two clients is applied, one
// that selects client=a stays, and the two count as deployed only together
func TestOldClientGoesBeforeTheTwoClients(t *testing.T) {
	check := `. "$1"; drop_old_client; if peers_deployed; then echo deployed >&2; fi`
	for _, c := range []struct {
		name     string
		env      []string
		deleted  bool
		deployed bool
	}{
		{"no clients", nil, false, false},
		{"the old client-a", []string{"CLIENT_A=yes"}, true, false},
		{"the old client-a and a client-b", []string{"CLIENT_A=yes", "CLIENT_B=yes"}, true, false},
		{"the new client-a alone", []string{"CLIENT_A=yes", "CLIENT_A_SELECTOR=a"}, false, false},
		{"both new clients", []string{"CLIENT_A=yes", "CLIENT_A_SELECTOR=a", "CLIENT_B=yes"}, false, true},
	} {
		status, stderr, calls := runEnv(t, 5, c.env, "-c", check, "bash", script(t, "lib.sh"))
		if status != 0 {
			t.Fatalf("%s: status %d, stderr %q", c.name, status, stderr)
		}
		if deleted := strings.Contains(calls, "delete deployment client-a"); deleted != c.deleted {
			t.Errorf("%s: deleted %v, want %v:\n%s", c.name, deleted, c.deleted, calls)
		}
		if deployed := strings.Contains(stderr, "deployed"); deployed != c.deployed {
			t.Errorf("%s: deployed %v, want %v", c.name, deployed, c.deployed)
		}
	}
}
