package scripts

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// every program vault.sh and the scripts it sources run outside the shell;
// PATH holds only these shims and the stand-ins, so a program missing here
// fails the run with "command not found"
var vaultTools = []string{
	"awk", "base64", "basename", "bash", "cat", "cut", "dirname", "grep", "head", "mktemp", "ps",
	"rm", "sed", "seq", "sha256sum", "sleep", "sort", "tail", "tr", "uname", "wc",
}

// what each shim and stand-in records of a call: its argv and its environment
const recordCall = `{ printf '=== %s' "${0##*/}"; printf ' %s' "$@"; printf '\n'; export -p; } >>"$VAULT_CALLS"
`

// the cluster as vault.sh sees it, in files under $STAND: the clients run
// deploy/base or deploy/vault, each pod is a generation and each start of its
// container a log of its own, a claim brings a volume and a directory on
// jimichi-worker, and $STAND/order lists the steps that change the testbed.
// CONTEXT replaces the current context, EARLIER leaves the claims and the
// files of a run before
const vaultKubectl = `PATH="$STUB_PATH"
[ "$1" = --context ] && shift 2
args="$*"
which=""
case "$args" in
  *client-a*|*client=a*|*pv-a*) which=a ;;
  *client-b*|*client=b*|*pv-b*) which=b ;;
esac
st() { cat "$STAND/$1" 2>/dev/null || printf '%s' "${2:-}"; }
logfile() { printf '%s/%s.%s.%s.log' "$STAND" "$1" "$(st "$1.gen" 0)" "$(st "$1.restarts" 0)"; }
line() { printf '2026/11/27 12:00:00 %s\n' "$2" >>"$(logfile "$1")"; }
start() {
  local c="$1"
  echo $(( $(st "$c.gen" 0) + 1 )) >"$STAND/$c.gen"
  echo 0 >"$STAND/$c.restarts"
  rm -f "$STAND/$c.vol" "$STAND/$c.paired"
  if [ "$(st mode)" = vault ]; then
    line "$c" "admin listening on 127.0.0.1:9201"
    line "$c" "vault locked"
  else
    line "$c" "card_hash=0000"
    line "$c" "admin listening on 127.0.0.1:9201"
  fi
}
inventory() {
  local i c
  for i in 1 2 3 4 5; do
    echo "Deployment|relay-$i|uidr$i|relay||$i||kubectl-client-side-apply;||relay,,$i|relay,,$i|1,relay,jimichi/relay:dev|0||3"
  done
  for c in a b; do
    [ -e "$STAND/$c.deployed" ] || continue
    echo "Deployment|client-$c|uidd$c|client|$c|||kubectl-client-side-apply;kube-controller-manager;||client,$c,|client,$c,|1,client,jimichi/client:dev|0||7"
    echo "ReplicaSet|client-$c-hash|uidr$c|client|$c||Deployment,client-$c,uidd$c,true;|kube-controller-manager;||client,$c,|client,$c,|1,client,jimichi/client:dev|0||8"
    echo "Pod|client-$c-$(st $c.gen 0)|uidp$c$(st $c.gen 0)|client|$c||ReplicaSet,client-$c-hash,uidr$c,true;|kubelet;||-|-|1,client,jimichi/client:dev|0||9"
  done
}
apply() {
  local c n
  echo "$1" >"$STAND/mode"
  for c in a b; do
    touch "$STAND/$c.deployed"
    if [ "$1" = vault ] && [ ! -e "$STAND/pvc-$c" ]; then
      n=$(( $(st pvs 0) + 1 ))
      echo "$n" >"$STAND/pvs"
      echo "pv-$c-$n" >"$STAND/pvc-$c"
      touch "$STAND/pv.pv-$c-$n" "$STAND/$c.dir"
    fi
    start "$c"
  done
}
case "$args" in
  "config current-context") echo "${CONTEXT:-kind-jimichi}" ;;
  "config view --minify"*) printf 'https://127.0.0.1:16443' ;;
  "get nodes "*) printf 'jimichi-control-plane||True\njimichi-worker||True\njimichi-worker2||True\n' ;;
  *"get configmap jimichi-config "*) printf c25519 ;;
  *"get configmap jimichi-ca "*) printf 'c25519:anchor' ;;
  *"get deployments,replicasets,"*) inventory ;;
  *"delete --raw /apis/apps/v1/namespaces/jimichi/deployments/client-"*)
    cat >/dev/null
    echo "delete deployment client-$which" >>"$STAND/order"
    rm -f "$STAND/$which.deployed" ;;
  *"wait --for=delete "*) ;;
  *"rollout status "*) ;;
  *"apply -f deploy/vault/client.yaml"*) echo "apply vault" >>"$STAND/order"; apply vault ;;
  *"apply -f deploy/base/client.yaml"*) echo "apply base" >>"$STAND/order"; apply base ;;
  *"get pods -l app=relay "*) for i in 1 2 3 4 5; do echo "relay-$i-x"; done ;;
  *"get pods -l app=client "*)
    for c in a b; do [ -e "$STAND/$c.deployed" ] && echo "client-$c-$(st $c.gen 0)"; done; true ;;
  *"get pod relay-"*"-o go-template"*) printf '1|relay|-suite;$(JIMICHI_SUITE);|jimichi-config/suite' ;;
  *"get pod client-"*"-o go-template"*) printf '1|client|-suite;$(JIMICHI_SUITE);|jimichi-config/suite' ;;
  *"logs pod/relay-"*) echo "2026/11/27 12:00:00 relay listening on 0.0.0.0:9000 suite=c25519, roster 5" ;;
  *"get deployment client-"*)
    [ -e "$STAND/$which.deployed" ] || exit 1
    printf 'app=client,client=%s,' "$which" ;;
  *" get rs "*) printf '1 hash%s\n' "$which" ;;
  *" get pods -l app=client,client="*) echo "client-$which-$(st $which.gen 0)" ;;
  *"get pod client-"*"startedAt"*) printf '2026-11-27T12:%02d:%02dZ' "$(st $which.gen 0)" "$(st $which.restarts 0)" ;;
  *"get pod client-"*"restartCount"*) st $which.restarts 0 ;;
  *"get pod client-"*"nodeName"*) printf jimichi-worker ;;
  *"get pvc "*"-o name"*) [ -e "$STAND/pvc-$which" ] && echo "persistentvolumeclaim/vault-client-$which"; true ;;
  *"get pvc "*"volumeName"*) st "pvc-$which" ;;
  *"delete pvc "*)
    if [ -e "$STAND/pvc-$which" ]; then
      echo "delete pvc vault-client-$which" >>"$STAND/order"
      rm -f "$STAND/pv.$(st pvc-$which)" "$STAND/pvc-$which" "$STAND/$which.dir" "$STAND/$which.file"
    fi ;;
  *"get pv "*"-o name"*) [ -e "$STAND/pv.${args#get pv }" ] || [ -e "$STAND/pv.$(printf '%s' "${args#get pv }" | cut -d' ' -f1)" ] && echo pv; true ;;
  *"get pv "*"go-template"*) printf 'hostPath /var/local-path-provisioner/%s_jimichi_vault-client-%s' "$(st pvc-$which)" "$which" ;;
  *" logs pod/client-"*"--previous"*) cat "$STAND/$which.$(st $which.gen 0).$(( $(st $which.restarts 0) - 1 )).log" ;;
  *" logs pod/client-"*) cat "$(logfile "$which")" ;;
  *" logs deployment/client-"*) tail -n 30 "$(logfile "$which")" ;;
  *" delete pod client-"*)
    echo "delete pod client-$which" >>"$STAND/order"
    start "$which" ;;
  *" port-forward "*)
    echo "port-forward client-$which" >>"$STAND/order"
    port=$(printf '%s\n' "$args" | sed -n 's/.* \([0-9]*\):9201$/\1/p')
    echo "Forwarding from 127.0.0.1:$port -> 9201"
    trap 'exit 0' TERM
    while :; do sleep 0.1; done ;;
  *) echo "kubectl $args" >>"$STAND/unexpected"; exit 1 ;;
esac
`

// the admin ports behind the forwards, 19501 for client-a and 19502 for
// client-b. Every body is kept in $STAND/body.<n>, listed in $STAND/bodies.
// NOT_STARTED makes that many unlocks with the real password answer not
// started and restart the container; CARD_DIFFERS gives another card after an
// unlock with the real password; IDENTITY_LINE, RELAY_LINE and EXTRA_WRITTEN
// add a line to the log of a later run
const vaultCurl = `PATH="$STUB_PATH"
url="${!#}"
method=GET
w=""
data=""
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method="$2"; shift ;;
    -w) w="$2"; shift ;;
    --data-binary) data=yes; shift ;;
  esac
  shift
done
port=${url#http://127.0.0.1:}
port=${port%%/*}
path=/${url#http://127.0.0.1:*/}
which=a
[ "$port" = 19502 ] && which=b
body=""
if [ -n "$data" ]; then
  body=$(cat; printf x)
  body=${body%x}
  n=$(( $(cat "$STAND/count" 2>/dev/null || echo 0) + 1 ))
  echo "$n" >"$STAND/count"
  printf '%s' "$body" >"$STAND/body.$n"
  echo "$n $method $path $which" >>"$STAND/bodies"
fi
echo "curl $method $path client-$which" >>"$STAND/order"
st() { cat "$STAND/$1" 2>/dev/null || printf '%s' "${2:-}"; }
logfile() { printf '%s/%s.%s.%s.log' "$STAND" "$which" "$(st "$which.gen" 0)" "$(st "$which.restarts" 0)"; }
line() { printf '2026/11/27 12:00:01 %s\n' "$1" >>"$(logfile)"; }
vol=$(st "$which.vol")
code=204
text=""
reply() { code="$1"; text="$2"; }
opened() {
  echo "$1" >"$STAND/$which.vol"
  line "vault opened"
  line "circuit of 3 hops among 5 listed nodes to the mailbox, request period 200ms"
}
case "$method $path" in
  "GET /card")
    if [ -z "$vol" ]; then reply 503 "locked: no volume is open"$'\n'
    elif [ -n "${CARD_DIFFERS:-}" ] && [ "$vol" = real ] && [ "$(st a.gen)" = 2 ]; then reply 200 "c25519:card-other"$'\n'
    else reply 200 "c25519:card-$which-$vol"$'\n'
    fi ;;
  "GET /status")
    if [ -z "$vol" ]; then reply 503 "locked: no volume is open"$'\n'
    else
      state=unpaired trips=0 silent=""
      if [ -e "$STAND/$which.paired" ]; then state=established silent=',"silent_for":1'; fi
      [ "$vol" = real ] && [ -e "$STAND/$which.paired" ] && trips=1
      if [ "$vol" = cover ]; then state=handshaking silent=',"silent_for":200'; fi
      reply 200 "{\"state\":\"$state\",\"container\":\"$(st $which.container draft)\",\"requests\":10,\"bad\":0,\"bad_replies\":0,\"handshakes\":1,\"refused_handshakes\":0,\"replayed_handshakes\":0,\"round_trips\":$trips$silent}"$'\n'
    fi ;;
  "PUT /vault/init")
    if [ -n "$vol" ]; then reply 409 "a volume is open already"$'\n'
    elif [ -e "$STAND/$which.file" ]; then reply 409 "the container exists: PUT /vault/unlock opens it"$'\n'
    else
      mapfile -t lines <<<"$body"
      if [ "$which" = a ]; then
        printf '%s' "${lines[0]}" >"$STAND/a.pw.real"
        printf '%s' "${lines[2]}" >"$STAND/a.pw.cover"
        opened real
      else
        opened b
      fi
      echo draft >"$STAND/$which.container"
    fi ;;
  "PUT /contact")
    if [ -z "$vol" ]; then reply 503 "locked: no volume is open"$'\n'
    else
      if [ "$(st $which.container)" = draft ]; then
        touch "$STAND/$which.file"
        echo written >"$STAND/$which.container"
        line "vault written"
      fi
      touch "$STAND/$which.paired"
      line "contact pinned"
    fi ;;
  "PUT /vault/unlock")
    pw="${body%$'\n'}"
    if [ -n "$vol" ]; then reply 409 "a volume is open already"$'\n'
    elif [ ! -e "$STAND/$which.file" ]; then reply 409 "no container yet: PUT /vault/init creates one"$'\n'
    elif [ "$pw" = "$(st a.pw.real)" ] && [ "$(st notstarted 0)" -lt "${NOT_STARTED:-0}" ]; then
      echo $(( $(st notstarted 0) + 1 )) >"$STAND/notstarted"
      line "refusing to build the circuit: no entry answered"
      echo $(( $(st a.restarts 0) + 1 )) >"$STAND/a.restarts"
      line "admin listening on 127.0.0.1:9201"
      line "vault locked"
      reply 503 "vault: not started: circuit, the container is on disk"$'\n'
    elif [ "$pw" = "$(st a.pw.real)" ]; then
      opened real
      echo written >"$STAND/a.container"
      touch "$STAND/a.paired"
      if [ -n "${IDENTITY_LINE:-}" ]; then line "contact pinned card_hash=00ff role=initiator"; else line "contact pinned"; fi
      [ -z "${RELAY_LINE:-}" ] || line "circuit rebuilt through the same entry"
    elif [ "$pw" = "$(st a.pw.cover)" ]; then
      opened cover
      echo written >"$STAND/a.container"
      line "contact pinned"
      [ -z "${EXTRA_WRITTEN:-}" ] || line "vault written"
    else
      line "vault: no volume opens with this password"
      reply 403 "vault: no volume opens with this password"$'\n'
    fi ;;
  *) echo "curl $method $path" >>"$STAND/unexpected"; exit 22 ;;
esac
printf '%s' "$text"
if [ -n "$w" ]; then
  w=${w//'%{http_code}'/$code}
  w=${w//'%{time_total}'/0.250000}
  printf "$w"
fi
`

// the nodes: a directory per claim, the file once PUT /contact wrote it.
// EXTRA_NAME leaves a second name next to it, NLINK gives it more links and
// SHA_CHANGE another digest once the cover volume is open
const vaultDocker = `PATH="$STUB_PATH"
[ "$1" = exec ] || exit 1
target="${!#}"
which=a
case "$target" in *vault-client-b*) which=b ;; esac
case "$3" in
  ls)
    [ -e "$STAND/$which.dir" ] || exit 2
    if [ -e "$STAND/$which.file" ]; then
      echo peer.vault
      [ -z "${EXTRA_NAME:-}" ] || echo peer.vault.tmp
    fi ;;
  stat)
    if [ "$5" = '%a|%u|%g' ]; then echo '777|0|0'; else echo "regular file|600|65532|65532|${NLINK:-1}|8224|100$([ "$which" = a ] && echo 1 || echo 2)"; fi ;;
  sha256sum)
    content="file-$which"
    if [ -n "${SHA_CHANGE:-}" ] && [ "$which" = a ] && [ "$(cat "$STAND/a.vol" 2>/dev/null)" = cover ]; then content=changed; fi
    printf '%s  %s\n' "$(printf '%s' "$content" | sha256sum | cut -c1-64)" "$target" ;;
  test)
    echo "docker test ! -e $target" >>"$STAND/order"
    [ ! -e "$STAND/$which.dir" ] ;;
  *) echo "docker $*" >>"$STAND/unexpected"; exit 1 ;;
esac
`

const vaultJimichi = `PATH="$STUB_PATH"
case "$1" in
  keygen-card) echo "c25519:cover-card" ;;
  card-hash) printf '%s' "$2" | sha256sum | cut -c1-64 ;;
  *) exit 2 ;;
esac
`

// the introduction of the base clients ends in a round trip in the log of
// client-a
const vaultIntroduce = `PATH="$STUB_PATH"
echo "introduce JIMICHI=$JIMICHI RESTART=$RESTART" >>"$STAND/order"
printf '2026/11/27 12:00:02 e2e round trip in 1ms\n' >>"$STAND/a.$(cat "$STAND/a.gen").$(cat "$STAND/a.restarts").log"
`

type vaultRun struct {
	status         int
	stdout, stderr string
	stand          string
	calls          string
	jimichi        string
	dirs           []string
}

// the path of a program as the bash of the test sees it
func posixPath(t *testing.T, shell, program string) string {
	t.Helper()
	out, err := exec.Command(shell, "-c", `command -v "$1"`, "bash", program).Output()
	if err != nil {
		t.Skipf("no %s for the shims: %v", program, err)
	}
	return strings.TrimSpace(string(out))
}

func posix(t *testing.T, shell, path string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return path
	}
	out, err := exec.Command(shell, "-c", `cygpath -u "$1"`, "bash", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// runs vault.sh against the stand-ins with only the shims in PATH; the
// testbed starts with the base clients
func vaultDemo(t *testing.T, args []string, env ...string) vaultRun {
	t.Helper()
	shell := bash(t)
	interpreter := posixPath(t, shell, "bash")
	realPath, err := exec.Command(shell, "-c", `printf '%s' "$PATH"`).Output()
	if err != nil {
		t.Fatal(err)
	}
	bin, stand, tmp, home, work := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!"+interpreter+"\n"+recordCall+text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range vaultTools {
		write(tool, "exec '"+posixPath(t, shell, tool)+"' \"$@\"\n")
	}
	for name, text := range map[string]string{
		"kubectl": vaultKubectl, "curl": vaultCurl, "docker": vaultDocker, "jimichi": vaultJimichi, "introduce-stub": vaultIntroduce,
	} {
		write(name, text)
	}
	for _, c := range []string{"a", "b"} {
		for _, f := range []string{c + ".deployed", c + ".gen", c + ".restarts", c + ".1.0.log"} {
			if err := os.WriteFile(filepath.Join(stand, f), []byte(map[string]string{c + ".gen": "1\n", c + ".restarts": "0\n"}[f]), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	initial := map[string]string{"mode": "base\n"}
	if slices.Contains(env, "EARLIER=yes") {
		for _, c := range []string{"a", "b"} {
			initial["pvc-"+c] = "pv-" + c + "-0\n"
			initial["pv.pv-"+c+"-0"], initial[c+".dir"], initial[c+".file"] = "", "", ""
		}
	}
	for name, text := range initial {
		if err := os.WriteFile(filepath.Join(stand, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	calls := filepath.Join(stand, "calls")
	jimichi := posix(t, shell, filepath.Join(bin, "jimichi"))
	cmd := exec.Command(shell, append(args, script(t, "vault.sh"))...)
	cmd.Dir = work
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SHELLOPTS", "BASHOPTS", "BASH_ENV", "ENV", "CDPATH",
			"KUBECONFIG", "JIMICHI", "JIMICHI_CONTEXT", "JIMICHI_HEALTHY_NODES", "SUITE", "CLUSTER", "NAMESPACE", "INTRODUCE":
			continue
		}
		if strings.HasPrefix(strings.ToUpper(name), "VAULT_") {
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env,
		"PATH="+bin,
		"STUB_PATH="+string(realPath),
		"HOME="+filepath.ToSlash(home),
		"TMPDIR="+filepath.ToSlash(tmp),
		"STAND="+filepath.ToSlash(stand),
		"VAULT_CALLS="+filepath.ToSlash(calls),
		"JIMICHI="+jimichi,
		"INTRODUCE="+posix(t, shell, filepath.Join(bin, "introduce-stub")),
		"VAULT_PAUSE=0",
	)
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile(calls)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if unexpected, err := os.ReadFile(filepath.Join(stand, "unexpected")); err == nil {
		t.Errorf("calls the stand-ins do not know:\n%s", unexpected)
	}
	if strings.Contains(stderr.String(), "command not found") {
		t.Errorf("vault.sh ran a program outside the shims:\n%s", stderr.String())
	}
	return vaultRun{cmd.ProcessState.ExitCode(), stdout.String(), stderr.String(), stand, string(recorded), jimichi, []string{tmp, home, work}}
}

func (r vaultRun) file(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.stand, name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(raw)
}

// the bodies vault.sh sent, in order, of the given request
func (r vaultRun) bodies(t *testing.T, method, path, client string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(r.file(t, "bodies"), "\n") {
		f := strings.Fields(line)
		if len(f) == 4 && f[1] == method && f[2] == path && f[3] == client {
			out = append(out, r.file(t, "body."+f[0]))
		}
	}
	return out
}

// the four passwords as the init and the unlock bodies carry them
func (r vaultRun) passwords(t *testing.T) []string {
	t.Helper()
	initA, initB := r.bodies(t, "PUT", "/vault/init", "a"), r.bodies(t, "PUT", "/vault/init", "b")
	unlocks := r.bodies(t, "PUT", "/vault/unlock", "a")
	if len(initA) != 1 || len(initB) != 1 || len(unlocks) == 0 {
		t.Fatalf("init bodies %q %q, unlock bodies %q", initA, initB, unlocks)
	}
	a := strings.Split(initA[0], "\n")
	if len(a) != 5 {
		t.Fatalf("init of client-a %q, want two blocks", initA[0])
	}
	return []string{a[0], a[2], strings.TrimSuffix(initB[0], "\n\n"), strings.TrimSuffix(unlocks[0], "\n")}
}

// the steps that change the testbed, in the order they happened
func (r vaultRun) order(t *testing.T) []string {
	t.Helper()
	return strings.Split(strings.TrimSpace(r.file(t, "order")), "\n")
}

// whether want appears in got in this order, other entries between them
func inOrder(got, want []string) bool {
	i := 0
	for _, g := range got {
		if i < len(want) && g == want[i] {
			i++
		}
	}
	return i == len(want)
}

var base64Password = regexp.MustCompile(`^[A-Za-z0-9+/]{32}$`)

func TestVaultDemoRunsTheSteps(t *testing.T) {
	skipShort(t)
	t.Parallel()
	r := vaultDemo(t, nil)
	if r.status != 0 {
		t.Fatalf("status %d, want 0:\n%s\n%s", r.status, r.stdout, r.stderr)
	}
	order := r.order(t)
	if !inOrder(order, []string{
		"delete deployment client-a", "delete deployment client-b", "apply vault",
		"curl PUT /vault/init client-a", "curl PUT /vault/init client-b",
		"curl PUT /contact client-a", "curl PUT /contact client-b",
		"delete pod client-a", "delete pod client-a",
		"delete deployment client-a", "delete deployment client-b", "delete pvc vault-client-a", "delete pvc vault-client-b",
		"apply base", "introduce JIMICHI=" + r.jimichi + " RESTART=no",
		"docker test ! -e /var/local-path-provisioner/pv-a-1_jimichi_vault-client-a",
		"docker test ! -e /var/local-path-provisioner/pv-b-2_jimichi_vault-client-b",
	}) {
		t.Errorf("steps out of order:\n%s", strings.Join(order, "\n"))
	}
	if strings.Count(r.file(t, "order"), "delete pvc ") != 2 || strings.Count(r.file(t, "order"), "apply vault") != 1 {
		t.Errorf("want the claims deleted once, at the end, and the overlay applied once:\n%s", strings.Join(order, "\n"))
	}
	pw := r.passwords(t)
	seen := map[string]bool{}
	for _, p := range pw {
		if !base64Password.MatchString(p) || seen[p] {
			t.Fatalf("passwords %q, want four different ones of 32 base64 characters", pw)
		}
		seen[p] = true
	}
	if got, want := r.bodies(t, "PUT", "/vault/init", "a")[0], pw[0]+"\n\n"+pw[1]+"\nc25519:cover-card\n"; got != want {
		t.Errorf("init of client-a %q, want %q", got, want)
	}
	if got, want := r.bodies(t, "PUT", "/vault/init", "b")[0], pw[2]+"\n\n"; got != want {
		t.Errorf("init of client-b %q, want %q", got, want)
	}
	unlocks := r.bodies(t, "PUT", "/vault/unlock", "a")
	if want := []string{pw[3] + "\n", pw[0] + "\n", pw[3] + "\n", pw[1] + "\n"}; strings.Join(unlocks, "|") != strings.Join(want, "|") {
		t.Errorf("unlocks of client-a %q, want the wrong, the real, the wrong and the cover password", unlocks)
	}
	puts := 0
	for _, step := range order {
		if strings.HasPrefix(step, "curl PUT ") && strings.HasSuffix(step, " client-b") {
			puts++
		}
	}
	if puts != 2 {
		t.Errorf("%d PUT requests to client-b, want its init and its contact alone", puts)
	}
	for _, want := range []string{"time to running: init client-a", "time to running: unlock real", "time to running: unlock cover",
		"stretch at the 500m limit: 0.250000 s (403, run 5)", "stretch at the 500m limit: 0.250000 s (403, run 6)",
		"kinds of line, run 5: admin circuit locked novolume opened pinned; run 6: admin circuit locked novolume opened pinned"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
		}
	}
	if !strings.HasPrefix(r.stdout, "vault-demo: bounds: open 300s, round trip 300s, silence 180s, pod 180s, pause 0s; suite c25519\n") {
		t.Errorf("the first line does not give the bounds:\n%s", r.stdout)
	}
}

func TestVaultDemoKeepsPasswordsOffArgumentsAndDisk(t *testing.T) {
	skipShort(t)
	t.Parallel()
	r := vaultDemo(t, nil)
	if r.status != 0 {
		t.Fatalf("status %d, want 0:\n%s", r.status, r.stderr)
	}
	pw := r.passwords(t)
	if !strings.Contains(r.calls, "=== kubectl ") || !strings.Contains(r.calls, "=== head -c 24 /dev/urandom") ||
		!strings.Contains(r.calls, "declare -x STAND=") {
		t.Fatal("the calls were not recorded with their environment")
	}
	for i, p := range pw {
		if strings.Contains(r.calls, p) {
			t.Errorf("password %d is in the argv or the environment of a call", i+1)
		}
		if strings.Contains(r.stdout, p) || strings.Contains(r.stderr, p) {
			t.Errorf("password %d is in the output", i+1)
		}
	}
	for _, dir := range r.dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, p := range pw {
				if bytes.Contains(raw, []byte(p)) {
					t.Errorf("password %d is in %s", i+1, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestVaultDemoCleansAnEarlierRun(t *testing.T) {
	skipShort(t)
	t.Parallel()
	r := vaultDemo(t, nil, "EARLIER=yes")
	if r.status != 0 {
		t.Fatalf("status %d, want 0:\n%s", r.status, r.stderr)
	}
	if !inOrder(r.order(t), []string{"delete pvc vault-client-a", "delete pvc vault-client-b", "apply vault", "curl PUT /vault/init client-a"}) {
		t.Errorf("the claims of the earlier run were not removed before the overlay:\n%s", r.file(t, "order"))
	}
	if !strings.Contains(r.calls, "=== kubectl --context kind-jimichi wait --for=delete pv/pv-a-0 ") {
		t.Error("no wait for the volume of the earlier run")
	}
}

func TestVaultDemoRestoresBaseAfterAFailure(t *testing.T) {
	skipShort(t)
	t.Parallel()
	r := vaultDemo(t, nil, "CARD_DIFFERS=yes")
	if r.status != 1 || !strings.Contains(r.stderr, "vault-demo: step 5: client-a: the real password opened another identity") {
		t.Fatalf("status %d, want 1 and step 5:\n%s", r.status, r.stderr)
	}
	order := r.order(t)
	if !inOrder(order, []string{"delete pod client-a", "delete pvc vault-client-a", "delete pvc vault-client-b", "apply base"}) ||
		!strings.HasPrefix(order[len(order)-1], "docker test ! -e") || !strings.Contains(r.file(t, "order"), "introduce JIMICHI=") {
		t.Errorf("deploy/base not restored after the failure:\n%s", strings.Join(order, "\n"))
	}
}

func TestVaultDemoTouchesNothingOutsideItsContext(t *testing.T) {
	skipShort(t)
	t.Parallel()
	r := vaultDemo(t, nil, "CONTEXT=kind-other")
	if r.status != 2 {
		t.Fatalf("status %d, want 2:\n%s", r.status, r.stderr)
	}
	for _, word := range []string{" apply ", " delete ", " port-forward ", "=== curl"} {
		if strings.Contains(r.calls, word) {
			t.Errorf("a call with %q outside the context kind-jimichi", word)
		}
	}
	if got := r.file(t, "order"); got != "" {
		t.Errorf("the testbed changed:\n%s", got)
	}
}

func TestVaultDemoRetriesOnceAfterNotStarted(t *testing.T) {
	skipShort(t)
	t.Parallel()
	r := vaultDemo(t, nil, "NOT_STARTED=1")
	if r.status != 0 {
		t.Fatalf("one not started: status %d, want 0:\n%s", r.status, r.stderr)
	}
	pw := r.passwords(t)
	if n := strings.Count(strings.Join(r.bodies(t, "PUT", "/vault/unlock", "a"), "|"), pw[0]+"\n"); n != 2 {
		t.Errorf("the real password went %d times, want twice", n)
	}
	r = vaultDemo(t, nil, "NOT_STARTED=2")
	if r.status != 1 || !strings.Contains(r.stderr, "step 5: client-a: PUT /vault/unlock answered 503: vault: not started: circuit, the container is on disk") {
		t.Fatalf("two not started: status %d, want 1:\n%s", r.status, r.stderr)
	}
}

func TestVaultDemoRefusesTracing(t *testing.T) {
	skipShort(t)
	t.Parallel()
	for _, c := range []struct {
		name string
		args []string
		env  []string
	}{
		{"bash -x", []string{"-x"}, nil},
		{"SHELLOPTS=xtrace", nil, []string{"SHELLOPTS=xtrace"}},
		{"SHELLOPTS=allexport", nil, []string{"SHELLOPTS=allexport"}},
	} {
		r := vaultDemo(t, c.args, c.env...)
		if r.status != 2 || !strings.Contains(r.stderr, "vault.sh refuses to run with xtrace or allexport") {
			t.Errorf("%s: status %d, want 2:\n%s", c.name, r.status, r.stderr)
		}
		if strings.Contains(r.calls, "=== head ") || strings.Contains(r.calls, "=== curl") {
			t.Errorf("%s: passwords drawn or a request sent", c.name)
		}
	}
}

func TestVaultDemoFailsOnAnIdentityInTheLog(t *testing.T) {
	skipShort(t)
	t.Parallel()
	r := vaultDemo(t, nil, "IDENTITY_LINE=yes")
	if r.status != 1 || !strings.Contains(r.stderr, "vault-demo: step 7: a line outside the kinds of a client with -vault: 2026/11/27 12:00:01 contact pinned card_hash=00ff role=initiator") {
		t.Fatalf("status %d, want 1 and step 7:\n%s", r.status, r.stderr)
	}
}

func TestVaultDemoComparesTheRuns(t *testing.T) {
	skipShort(t)
	t.Parallel()
	r := vaultDemo(t, nil, "EXTRA_WRITTEN=yes")
	if r.status != 1 || !strings.Contains(r.stderr, "vault-demo: step 7: run 6 wrote the file") {
		t.Errorf("a vault written in run 6: status %d, want 1 and step 7:\n%s", r.status, r.stderr)
	}
	r = vaultDemo(t, nil, "RELAY_LINE=yes")
	if r.status != 0 || !strings.Contains(r.stdout, "a line from the chain, outside the comparison: 2026/11/27 12:00:01 circuit rebuilt through the same entry") {
		t.Errorf("a rebuild in run 5 alone: status %d, want 0 and the line printed:\n%s\n%s", r.status, r.stdout, r.stderr)
	}
}

func TestVaultDemoChecksTheFile(t *testing.T) {
	skipShort(t)
	t.Parallel()
	for _, c := range []struct {
		env, step string
	}{
		{"SHA_CHANGE=yes", "vault-demo: step 7: client-a: the file changed"},
		{"EXTRA_NAME=yes", "vault-demo: step 4: client-a: /var/local-path-provisioner/pv-a-1_jimichi_vault-client-a holds peer.vault peer.vault.tmp"},
		{"NLINK=2", "vault-demo: step 4: client-a: the file is regular file|600|65532|65532|2|8224|1001"},
	} {
		r := vaultDemo(t, nil, c.env)
		if r.status != 1 || !strings.Contains(r.stderr, c.step) {
			t.Errorf("%s: status %d, want 1 and %q:\n%s", c.env, r.status, c.step, r.stderr)
		}
	}
}

// the passwords leave the shell only through printf into curl: the static
// half of the guarantee the runs above check
func TestVaultScriptExpandsPasswordsOnlyIntoCurl(t *testing.T) {
	raw, err := os.ReadFile(script(t, "vault.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, word := range []string{"<<", "set -x", "-o xtrace", "set -a", "-o allexport", "declare -x", "local -x", "export pw_", "export -n"} {
		if strings.Contains(text, word) {
			t.Errorf("vault.sh holds %q", word)
		}
	}
	var code []string
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			code = append(code, line)
		}
	}
	if len(code) < 3 || !strings.HasPrefix(code[0], `case $- in *x*|*a*) `) || !strings.HasSuffix(code[0], "exit 2 ;; esac") ||
		code[1] != "set -euo pipefail" || code[2] != "set +o xtrace +o allexport" {
		t.Errorf("vault.sh does not begin with the refusal of xtrace and allexport: %q", code[:min(3, len(code))])
	}
	var (
		drawn    = regexp.MustCompile(`^(pw_real|pw_cover|pw_b|pw_wrong)=\$\(head -c 24 /dev/urandom \| base64\)$`)
		piped    = regexp.MustCompile(`^\s*(?:[a-z-]+\) )?out=\$\(printf '[^']*'(?: "\$(?:pw_real|pw_cover|pw_b|pw_wrong|card_cover)")+ \| curl [^|$]*(?:"\$[A-Z_]+"[^|$]*)*--data-binary @- "\$url"\) \|\|$`)
		unset    = regexp.MustCompile(`^\s*unset pw_real pw_cover pw_b pw_wrong$`)
		mentions = regexp.MustCompile(`pw_[a-z]+`)
	)
	drawnNames := map[string]bool{}
	for _, line := range code {
		if !mentions.MatchString(line) {
			continue
		}
		switch {
		case drawn.MatchString(line):
			drawnNames[drawn.FindStringSubmatch(line)[1]] = true
		case piped.MatchString(line):
			if _, after, _ := strings.Cut(line, "| curl "); mentions.MatchString(after) {
				t.Errorf("a password reaches curl other than on its standard input: %s", line)
			}
		case unset.MatchString(line):
		default:
			t.Errorf("a password outside printf into curl: %s", line)
		}
	}
	if len(drawnNames) != 4 {
		t.Errorf("passwords drawn %v, want pw_real, pw_cover, pw_b and pw_wrong", drawnNames)
	}
}
