package scripts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// the two clients as the checks of e2e.sh see them: one running pod each, the
// log and the restart count of client-b in files under $STAND, and the admin
// port of every client behind a forward that prints its line and waits
const checksKubectl = `#!/usr/bin/env bash
echo "$*" >>"$KUBECTL_CALLS"
args="$*"
which=""
case "$args" in
  *client-a*|*client=a*) which=a ;;
  *client-b*|*client=b*) which=b ;;
esac
case "$args" in
  *"get deployment client-"*) printf 'app=client,client=%s,' "$which" ;;
  *" get rs "*) printf '1 hash%s\n' "$which" ;;
  *" get pods "*) printf 'client-%s-1\n' "$which" ;;
  *restartCount*) cat "$STAND/$which.restarts" 2>/dev/null || printf 0 ;;
  *startedAt*) printf '2026-10-08T12:00:00Z' ;;
  *" logs "*) cat "$STAND/$which.log" 2>/dev/null || true ;;
  *" port-forward "*)
    port=$(printf '%s\n' "$args" | sed -n 's/.* \([0-9]*\):9201$/\1/p')
    echo "Forwarding from 127.0.0.1:$port -> 9201"
    trap 'exit 0' TERM
    while :; do sleep 0.1; done ;;
esac
`

// GET /card hands out the card of client-a. The first PUT /contact is the
// card of a key nobody holds: client-b answers FOREIGN_CODE (409 by default),
// logs the refusal unless NO_REFUSAL=yes and shows a restart with RESTARTS=yes;
// every later PUT answers PINNED_CODE (409 by default). The bodies are kept
const checksCurl = `#!/usr/bin/env bash
echo "curl $*" >>"$KUBECTL_CALLS"
url="${!#}"
case "$url" in
  */card) printf 'c25519:card-a\n' ;;
  */contact)
    cat >>"$STAND/bodies"
    echo >>"$STAND/bodies"
    n=$(( $(cat "$STAND/puts" 2>/dev/null || echo 0) + 1 ))
    echo "$n" >"$STAND/puts"
    if [ "$n" = 1 ]; then
      if [ "${NO_REFUSAL:-}" != yes ]; then
        echo "2026/10/08 12:00:01 contact card changed, refusing: pinned card_hash=$(printf 'c25519:card-a' | sha256sum | cut -c1-64)" >>"$STAND/b.log"
      fi
      if [ "${RESTARTS:-}" = yes ]; then echo 1 >"$STAND/b.restarts"; fi
      printf '%s' "${FOREIGN_CODE:-409}"
    else
      printf '%s' "${PINNED_CODE:-409}"
    fi ;;
esac
`

const checksJimichi = `#!/usr/bin/env bash
echo "jimichi $*" >>"$KUBECTL_CALLS"
[ "$1" = keygen-card ] || exit 2
echo c25519:foreign
`

// runs the given lines in bash with lib.sh and checks.sh sourced, under the
// options of e2e.sh, with the five relays of the stand listed and the
// stand-ins first in PATH
func runChecks(t *testing.T, env []string, lines string) (status int, stdout, stderr, calls, bodies string) {
	t.Helper()
	shell := bash(t)
	bin, work, stand := t.TempDir(), t.TempDir(), t.TempDir()
	for name, text := range map[string]string{"kubectl": checksKubectl, "curl": checksCurl, "jimichi": checksJimichi} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	prelude := `set -euo pipefail
. "$1/lib.sh"
. "$1/checks.sh"
trap stop_forwards EXIT
relay_list=$(printf 'relay-%s\n' 1 2 3 4 5)
`
	run := filepath.Join(work, "run.sh")
	if err := os.WriteFile(run, []byte(prelude+lines+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(bin, "calls")
	cmd := exec.Command(shell, filepath.ToSlash(run), filepath.ToSlash(filepath.Dir(script(t, "checks.sh"))))
	cmd.Dir = work
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"KUBECTL_CALLS="+filepath.ToSlash(log),
		"STAND="+filepath.ToSlash(stand),
		"CHECK_PAUSE=0",
	)
	cmd.Env = append(cmd.Env, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return string(b)
	}
	return cmd.ProcessState.ExitCode(), out.String(), errOut.String(), read(log), read(filepath.Join(stand, "bodies"))
}

// the counters of the five relays as scripts/stats.sh prints them, relay-5
// keeping the mailbox; change edits the counters of relay i+1
func standStats(change func(i int, c map[string]int)) string {
	var b strings.Builder
	for i := range 5 {
		c := map[string]int{
			"peers": 4, "descriptor_requests": 10, "mirror_requests": 3,
			"mailbox_requests": 0, "mailbox_puts": 0, "mailbox_put_full": 0, "mailbox_put_refused": 0,
			"mailbox_hits": 0, "mailbox_queues": 0,
		}
		if i == 4 {
			c["mirror_requests"] = 0
			maps.Copy(c, map[string]int{"mailbox_requests": 100, "mailbox_puts": 90, "mailbox_hits": 30, "mailbox_queues": 2})
		}
		if change != nil {
			change(i, c)
		}
		j, err := json.Marshal(c)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(&b, "relay-%d %s\n", i+1, j)
	}
	return b.String()
}

// every relay runs -exit mailbox and shows its counters; only relay-5 took
// requests, it took puts and answered fetches with a record, and it was never
// asked for the descriptors, as an entry would be
func TestMailboxChecksReadEveryRelay(t *testing.T) {
	good := standStats(nil)
	for _, c := range []struct {
		name   string
		after  string
		status int
		why    string
	}{
		{"the mailbox of the stand", good, 0, ""},
		{"a relay without a mailbox", standStats(func(i int, c map[string]int) {
			if i == 2 {
				for k := range c {
					if strings.HasPrefix(k, "mailbox_") {
						delete(c, k)
					}
				}
			}
		}), 1, "relay-3 shows no mailbox counters: every relay runs -exit mailbox"},
		{"no puts at the mailbox", standStats(func(i int, c map[string]int) {
			if i == 4 {
				c["mailbox_puts"] = 0
			}
		}), 1, "the mailbox of relay-5 took 0 puts and answered 30 fetches with a record after a round trip"},
		{"no record fetched", standStats(func(i int, c map[string]int) {
			if i == 4 {
				c["mailbox_hits"] = 0
			}
		}), 1, "the mailbox of relay-5 took 90 puts and answered 0 fetches with a record after a round trip"},
		{"a request at another mailbox", standStats(func(i int, c map[string]int) {
			if i == 1 {
				c["mailbox_requests"] = 4
			}
		}), 1, "relay-2 answered 4 mailbox requests, only relay-5 ends the chains of the clients"},
		{"the mailbox as an entry", standStats(func(i int, c map[string]int) {
			if i == 4 {
				c["mirror_requests"] = 2
			}
		}), 1, "relay-5 answered 2 requests for the descriptors: the mailbox was an entry"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			status, _, stderr, _, _ := runChecks(t, []string{"STATS_0=" + good, "STATS_1=" + c.after},
				`check_mailboxes "$STATS_1" || exit 1
check_mailbox_not_entry "$STATS_0" "$STATS_1" || exit 1`)
			if status != c.status || strings.TrimSpace(stderr) != c.why {
				t.Errorf("status %d, stderr %q; want %d and %q", status, stderr, c.status, c.why)
			}
		})
	}
}

// a put, stored, full or refused, in at least 0.9 of the requests at the
// mailbox between two passes, and at least one request
func TestPutShareNeedsNineTenths(t *testing.T) {
	first := standStats(nil)
	at := func(requests, puts, full, refused int) string {
		return standStats(func(i int, c map[string]int) {
			if i == 4 {
				maps.Copy(c, map[string]int{"mailbox_requests": requests, "mailbox_puts": puts, "mailbox_put_full": full, "mailbox_put_refused": refused})
			}
		})
	}
	for _, c := range []struct {
		name   string
		second string
		status int
		out    string
	}{
		{"nine tenths", at(200, 175, 3, 2), 0, "puts: 90 in 100 requests at the mailbox over 30s"},
		{"every request", at(200, 190, 0, 0), 0, "puts: 100 in 100 requests at the mailbox over 30s"},
		{"one put short", at(200, 175, 3, 1), 1, "the mailbox took 89 puts in 100 requests over 30s, want at least 0.9 of them"},
		{"no request", at(100, 90, 0, 0), 1, "the mailbox took 0 puts in 0 requests over 30s, want at least 0.9 of them"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			status, stdout, stderr, _, _ := runChecks(t, []string{"STATS_0=" + first, "STATS_1=" + c.second},
				`put_share_between "$STATS_0" "$STATS_1" 30 || exit 1`)
			if got := strings.TrimSpace(stdout + stderr); status != c.status || got != c.out {
				t.Errorf("status %d, output %q; want %d and %q", status, got, c.status, c.out)
			}
		})
	}
}

// the stopped state as e2e.sh checks it: client-b answers 409 to the card of a
// key nobody holds, logs the refusal, answers 409 to the card it had pinned
// and does not restart; the cards reach curl on standard input only
func TestRefusalCheckNeedsTheStoppedState(t *testing.T) {
	for _, c := range []struct {
		name string
		env  []string
		why  string
	}{
		{"the stopped state", nil, ""},
		{"the foreign card taken", []string{"FOREIGN_CODE=204"}, "client-b answered 204 to the card of a key nobody holds, want 409"},
		{"no line of the refusal", []string{"NO_REFUSAL=yes"}, "client-b did not log the refusal"},
		{"the pinned card taken again", []string{"PINNED_CODE=204"}, "the stopped client-b answered 204 to the card it had pinned, want 409"},
		{"a restart after the refusal", []string{"RESTARTS=yes"}, "client-b restarted after the refusal; it must stay stopped until the operator restarts it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			status, stdout, stderr, calls, bodies := runChecks(t, append([]string{"SUITE=c25519"}, c.env...),
				`jimichi=jimichi
refuse_other_cards || exit 1`)
			if c.why != "" {
				if status != 1 || strings.TrimSpace(stderr) != c.why {
					t.Errorf("status %d, stderr %q; want 1 and %q", status, stderr, c.why)
				}
				return
			}
			if status != 0 || stdout != "refusal: client-b answered 409 to another card and to the card it had pinned, and stays stopped\n" {
				t.Fatalf("status %d, stdout %q, stderr:\n%s", status, stdout, stderr)
			}
			if bodies != "c25519:foreign\nc25519:card-a\n" {
				t.Fatalf("the bodies of the puts were %q", bodies)
			}
			for _, want := range []string{
				"jimichi keygen-card -suite c25519 -mailbox relay-5.jimichi.svc.cluster.local:9000",
				"port-forward --address 127.0.0.1 pod/client-a-1 19411:9201",
				"port-forward --address 127.0.0.1 pod/client-b-1 19412:9201",
				`curl -sS -w \n%{http_code} -X PUT --data-binary @- http://127.0.0.1:19412/contact`,
			} {
				if !strings.Contains(calls, want) {
					t.Fatalf("no %q in:\n%s", want, calls)
				}
			}
			if strings.Contains(calls, "c25519:") {
				t.Fatalf("a card on a command line:\n%s", calls)
			}
		})
	}
}

// e2e.sh runs each of these checks at the top level and stops on its failure,
// the introduction that brings the conversation back after the refusal
// included
func TestE2ERunsEveryCheck(t *testing.T) {
	text, err := os.ReadFile(script(t, "e2e.sh"))
	if err != nil {
		t.Fatal(err)
	}
	order := []string{
		`check_mailboxes "$stats" || exit 1`,
		`check_mailbox_not_entry "$stats_0" "$stats" || exit 1`,
		`put_share || exit 1`,
		`refuse_other_cards || exit 1`,
		`JIMICHI="$jimichi" bash scripts/introduce.sh || exit 1`,
		`await_round_trip || exit 1`,
		`isolation`,
	}
	at := 0
	for _, line := range order {
		loc := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(line) + `$`).FindIndex(text[at:])
		if loc == nil {
			t.Fatalf("e2e.sh does not run %q at the top level after the checks before it", line)
		}
		at += loc[1]
	}
}
