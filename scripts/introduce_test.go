package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// the cluster as introduce.sh sees it: two client deployments whose state
// lives in files under $STAND. A rollout restart makes a new generation of
// both, and each generation hands out its own card. The log of a client shows
// CARD_LINES card_hash lines (one by default) and the pinned lines its admin
// port wrote; MISMATCH names a client whose logged hash is not that of its
// card in the first generation, or in every one with MISMATCH_ALWAYS=yes;
// RESTARTING names a client whose container shows a later start at every look
// in the first generation. With ADMIN_AFTER=n a client logs its admin listener
// from the n-th look at its log on, and a port-forward to it before that fails
const introduceKubectl = `#!/usr/bin/env bash
echo "$*" >>"$KUBECTL_CALLS"
args="$*"
which=""
case "$args" in
  *client-a*|*client=a*) which=a ;;
  *client-b*|*client=b*) which=b ;;
esac
gen() { cat "$STAND/$1.gen"; }
digest() { printf '%s' "$1" | sha256sum | cut -c1-64; }
case "$args" in
  *"rollout restart"*)
    for c in a b; do echo $(( $(gen $c) + 1 )) >"$STAND/$c.gen"; done ;;
  *"rollout status"*|*" wait "*) ;;
  *"get deployment client-"*)
    printf 'app=client,client=%s,' "$which" ;;
  *" get rs "*)
    printf '1 hash%s\n' "$which" ;;
  *" get pods "*)
    printf 'client-%s-%s\n' "$which" "$(gen "$which")" ;;
  *" get pod "*)
    n=0
    if [ "${RESTARTING:-}" = "$which" ] && [ "$(gen "$which")" = 1 ]; then
      n=$(( $(cat "$STAND/$which.looks" 2>/dev/null || echo 0) + 1 ))
      echo "$n" >"$STAND/$which.looks"
    fi
    printf '2026-10-08T12:00:%02dZ' "$n" ;;
  *" logs "*)
    looks=$(( $(cat "$STAND/$which.logs" 2>/dev/null || echo 0) + 1 ))
    echo "$looks" >"$STAND/$which.logs"
    h=$(digest "c25519:card-$which-$(gen "$which")")
    if [ "${MISMATCH:-}" = "$which" ] && { [ "${MISMATCH_ALWAYS:-}" = yes ] || [ "$(gen "$which")" = 1 ]; }; then
      h=$(digest other)
    fi
    for _ in $(seq 1 "${CARD_LINES:-1}"); do echo "2026/10/08 12:00:00 card_hash=$h"; done
    echo "2026/10/08 12:00:00 circuit of 3 hops among 5 listed nodes to the mailbox, request period 200ms"
    if [ "$looks" -ge "${ADMIN_AFTER:-1}" ]; then
      echo "2026/10/08 12:00:00 admin listening on 127.0.0.1:9201"
    fi
    cat "$STAND/$which.$(gen "$which").pinned" 2>/dev/null || true ;;
  *" port-forward "*)
    if [ "$(cat "$STAND/$which.logs" 2>/dev/null || echo 0)" -lt "${ADMIN_AFTER:-1}" ]; then
      echo "forward to client-$which before its admin listener" >>"$KUBECTL_CALLS"
      echo "error: lost connection to pod" >&2
      exit 1
    fi
    port=$(printf '%s\n' "$args" | sed -n 's/.* \([0-9]*\):9201$/\1/p')
    echo "Forwarding from 127.0.0.1:$port -> 9201"
    trap 'exit 0' TERM
    while :; do sleep 0.1; done ;;
esac
`

// the admin ports behind the forwards: GET /card hands out the card of the
// current generation, PUT /contact writes the pinned line into its log. In the
// first generation PREPINNED names a client that pinned another card through
// some other forward before the script, so it answers 409 and pins nothing,
// and PINNED_OTHER one that answers 204 but logs the pin of another card
const introduceCurl = `#!/usr/bin/env bash
echo "curl $*" >>"$KUBECTL_CALLS"
url="${!#}"
port=${url#http://127.0.0.1:}
port=${port%%/*}
which=a
[ "$port" = 19402 ] && which=b
gen=$(cat "$STAND/$which.gen")
case "$url" in
  */card) printf 'c25519:card-%s-%s\n' "$which" "$gen" ;;
  */contact)
    body=$(cat)
    if [ "${PREPINNED:-}" = "$which" ] && [ "$gen" = 1 ]; then
      printf 409
      exit 0
    fi
    h=$(printf '%s' "$body" | sha256sum | cut -c1-64)
    if [ "${PINNED_OTHER:-}" = "$which" ] && [ "$gen" = 1 ]; then
      h=$(printf other | sha256sum | cut -c1-64)
    fi
    echo "2026/10/08 12:00:01 contact pinned card_hash=$h role=initiator" >>"$STAND/$which.$gen.pinned"
    printf 204 ;;
esac
`

const introduceJimichi = `#!/usr/bin/env bash
[ "$1" = card-hash ] || exit 2
printf '%s' "$2" | sha256sum | cut -c1-64
`

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// runs introduce.sh against the stand-ins with the given variables set
func introduce(t *testing.T, env ...string) (status int, stdout, stderr, calls string) {
	t.Helper()
	shell := bash(t)
	bin, work, stand := t.TempDir(), t.TempDir(), t.TempDir()
	for name, text := range map[string]string{"kubectl": introduceKubectl, "curl": introduceCurl, "jimichi": introduceJimichi, "go": goStandIn} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(stand, c+".gen"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(bin, "calls")
	cmd := exec.Command(shell, script(t, "introduce.sh"))
	cmd.Dir = work
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"KUBECTL_CALLS="+filepath.ToSlash(log),
		"STAND="+filepath.ToSlash(stand),
		"JIMICHI="+filepath.ToSlash(filepath.Join(bin, "jimichi")),
		"INTRODUCE_PAUSE=0",
	)
	cmd.Env = append(cmd.Env, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile(log)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), out.String(), errOut.String(), string(recorded)
}

func skipShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("runs introduce.sh several times against the stand-ins")
	}
}

func introduced(gen int) string {
	return fmt.Sprintf("introduced client-a=%s client-b=%s\n",
		digest(fmt.Sprintf("c25519:card-a-%d", gen)), digest(fmt.Sprintf("c25519:card-b-%d", gen)))
}

// each client gets the card of the other, and only through the forward of its
// own admin port, opened once the client logs its admin listener; the card
// goes to curl on standard input
func TestIntroduceHandsEachClientTheOthersCard(t *testing.T) {
	t.Parallel()
	status, stdout, stderr, calls := introduce(t, "RESTART=no", "ADMIN_AFTER=3")
	if status != 0 || stdout != introduced(1) {
		t.Fatalf("status %d, stdout %q, stderr:\n%s", status, stdout, stderr)
	}
	if strings.Contains(calls, "rollout restart") || strings.Contains(calls, "card-") {
		t.Fatalf("restarted the clients or put a card on a command line:\n%s", calls)
	}
	if strings.Contains(calls, "before its admin listener") {
		t.Fatalf("forwarded a port nobody listens on yet:\n%s", calls)
	}
	for _, want := range []string{
		"port-forward --address 127.0.0.1 pod/client-a-1 19401:9201",
		"port-forward --address 127.0.0.1 pod/client-b-1 19402:9201",
		"-X PUT --data-binary @- http://127.0.0.1:19401/contact",
		"-X PUT --data-binary @- http://127.0.0.1:19402/contact",
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("no %q in:\n%s", want, calls)
		}
	}

	skipShort(t)
	status, stdout, stderr, calls = introduce(t)
	if status != 0 || stdout != introduced(2) || strings.Count(calls, "rollout restart") != 1 {
		t.Fatalf("with the default restart: status %d, stdout %q, stderr:\n%s\ncalls:\n%s", status, stdout, stderr, calls)
	}
}

// a log with no card_hash line or with two is no proof of the card: every
// attempt fails, each after a restart, and the script gives up after three
func TestIntroduceNeedsOneCardHashLine(t *testing.T) {
	t.Parallel()
	skipShort(t)
	for _, lines := range []string{"0", "2"} {
		status, stdout, stderr, calls := introduce(t, "RESTART=no", "CARD_LINES="+lines)
		if status != 1 || stdout != "" || !strings.Contains(stderr, lines+" card_hash lines in the log of its current container") {
			t.Fatalf("%s lines: status %d, stdout %q, stderr:\n%s", lines, status, stdout, stderr)
		}
		if !strings.Contains(stderr, "not introduced in 3 attempts") || strings.Count(calls, "rollout restart") != 2 {
			t.Fatalf("%s lines: want three attempts, the last two after a restart:\n%s\n%s", lines, stderr, calls)
		}
	}
}

// a card that does not hash to the line of its client, at either client, is
// not put anywhere; the next attempt restarts both clients and takes their new
// cards
func TestIntroduceRefusesACardOtherThanTheLogged(t *testing.T) {
	t.Parallel()
	skipShort(t)
	for _, which := range []string{"a", "b"} {
		status, stdout, stderr, calls := introduce(t, "RESTART=no", "MISMATCH="+which)
		if status != 0 || stdout != introduced(2) || !strings.Contains(stderr, "client-"+which+": the card on its admin port hashes to") {
			t.Fatalf("client-%s: status %d, stdout %q, stderr:\n%s", which, status, stdout, stderr)
		}
		if strings.Count(calls, "/contact") != 2 || strings.Count(calls, "rollout restart") != 1 {
			t.Fatalf("client-%s: a card was put before both were checked:\n%s", which, calls)
		}
	}

	status, stdout, stderr, calls := introduce(t, "RESTART=no", "MISMATCH=a", "MISMATCH_ALWAYS=yes")
	if status != 1 || stdout != "" || strings.Contains(calls, "/contact") {
		t.Fatalf("always a mismatch: status %d, stdout %q, stderr:\n%s\ncalls:\n%s", status, stdout, stderr, calls)
	}
}

// a client that pinned another card before the script, through a forward of
// someone else in the window of trust on first use, answers 409 and logs no
// pin of the card it got: the attempt fails on the answer, and the next one
// restarts both clients, which ends that window
func TestIntroduceNoticesACardPinnedBeforeIt(t *testing.T) {
	t.Parallel()
	skipShort(t)
	for _, which := range []string{"a", "b"} {
		status, stdout, stderr, calls := introduce(t, "RESTART=no", "PREPINNED="+which)
		if status != 0 || stdout != introduced(2) || !strings.Contains(stderr, "client-"+which+": PUT /contact answered 409, want 204") {
			t.Fatalf("client-%s: status %d, stdout %q, stderr:\n%s", which, status, stdout, stderr)
		}
		if strings.Count(calls, "rollout restart") != 1 {
			t.Fatalf("client-%s: want the second attempt after a restart:\n%s", which, calls)
		}
	}
}

// a 204 is not enough: a client whose log names the pin of another card has
// not pinned the one it was given, and the next attempt restarts both
func TestIntroduceNeedsThePinnedLine(t *testing.T) {
	t.Parallel()
	skipShort(t)
	status, stdout, stderr, calls := introduce(t, "RESTART=no", "PINNED_OTHER=a")
	want := "pod/client-a-1 did not log that it pinned card_hash=" + digest("c25519:card-b-1")
	if status != 0 || stdout != introduced(2) || !strings.Contains(stderr, want) {
		t.Fatalf("status %d, stdout %q, stderr:\n%s", status, stdout, stderr)
	}
	if strings.Count(calls, "rollout restart") != 1 {
		t.Fatalf("want the second attempt after a restart:\n%s", calls)
	}
}

// a container that restarts between the card and the PUT is a new identity:
// the attempt fails and the next one starts over with a restart
func TestIntroduceNoticesARestartUnderIt(t *testing.T) {
	t.Parallel()
	skipShort(t)
	status, stdout, stderr, calls := introduce(t, "RESTART=no", "RESTARTING=b")
	if status != 0 || stdout != introduced(2) || !strings.Contains(stderr, "client-b restarted during the introduction") {
		t.Fatalf("status %d, stdout %q, stderr:\n%s", status, stdout, stderr)
	}
	if strings.Count(calls, "rollout restart") != 1 {
		t.Fatalf("calls:\n%s", calls)
	}
}
