#!/usr/bin/env bash
# the clients of deploy/vault on the testbed of a developer, never in CI: a
# clean start, an init of two volumes at client-a and of one at client-b, the
# introduction, a restart with the real password that keeps the identity and
# the conversation, a restart with the password of the cover volume that opens
# another identity, the file the same byte for byte, a log that names no
# identity, then deploy/base again. Exit 0 success, 1 a check failed, 2 a
# precondition failed and the testbed is untouched, 3 deploy/base not restored
case $- in *x*|*a*) echo "vault.sh refuses to run with xtrace or allexport: the passwords would leak" >&2; exit 2 ;; esac
set -euo pipefail
set +o xtrace +o allexport

. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/checks.sh"
. "$(dirname "$0")/deploy.sh"

# client-a takes the local port base + 1, client-b base + 2
VAULT_PORT_BASE="${VAULT_PORT_BASE:-19500}"
VAULT_PAUSE="${VAULT_PAUSE:-2}"
# an init or an unlock answers after the first chain, about 200 s at worst
VAULT_OPEN_WAIT="${VAULT_OPEN_WAIT:-300}"
VAULT_TRIP_WAIT="${VAULT_TRIP_WAIT:-300}"
VAULT_SILENT_WAIT="${VAULT_SILENT_WAIT:-180}"
VAULT_POD_WAIT="${VAULT_POD_WAIT:-180}"
INTRODUCE="${INTRODUCE:-$(dirname "$0")/introduce.sh}"
ADMIN_PORT=9201
ADMIN_WAIT=10
WRONG_WAIT=120
SILENT_AFTER=120
FILE_STATE='^regular file\|600\|65532\|65532\|1\|8224\|[0-9]+$'
OVERLAY=deploy/vault/client.yaml
BASE=deploy/base/client.yaml
CLIENTS=(client-a client-b)
NOTICE="stand left without base clients: run make redeploy, then kubectl -n jimichi delete pvc vault-client-a vault-client-b"

# the kinds of line a client with -vault prints; relay kinds come from the
# chain, not the volume, and previous kinds only from a container that ended
# with not started
KINDS=(admin locked novolume opened circuit pinned written refusing noconv notpinned closed rebuilt rebuildfail redraw)
declare -A KIND_RE=(
  [admin]='^admin listening on 127\.0\.0\.1:9201$'
  [locked]='^vault locked$'
  [novolume]='^vault: no volume opens with this password$'
  [opened]='^vault opened$'
  [circuit]='^circuit of [0-9]+ hops among [0-9]+ listed nodes to the mailbox, request period [0-9][0-9a-zµ.]*$'
  [pinned]='^contact pinned$'
  [written]='^vault written$'
  [refusing]='^refusing to build the circuit: .+$'
  [noconv]='^the conversation did not start$'
  [notpinned]='^vault: not pinned: (memory|closed|io)$'
  [closed]='^circuit closed(: .+)?$'
  [rebuilt]='^circuit rebuilt through the same entry$'
  [rebuildfail]='^circuit rebuild failed: .+$'
  [redraw]='^the chain could not be dialled again, new middle hops drawn, redraw [0-9]+ of [0-9]+$'
)
declare -A KIND_CLASS=([refusing]=previous [noconv]=previous [notpinned]=previous
  [closed]=relay [rebuilt]=relay [rebuildfail]=relay [redraw]=relay)

declare -A port=([client-a]=$((VAULT_PORT_BASE + 1)) [client-b]=$((VAULT_PORT_BASE + 2)))
declare -A pod=() since=() restarts=() fwd=() node=() dir=() volume=() kind=() snap=() sum=()
caps_text=()
caps_run=()
caps_prev=()
forwards=()
step=0
restore=""
code=""
reply=""
took=""

say() { echo "vault-demo: $*"; }

fail() {
  echo "vault-demo: step $step: $*" >&2
  exit 1
}

preflight() {
  local tool
  for tool in kubectl curl docker base64 sha256sum; do
    command -v "$tool" >/dev/null || { echo "vault.sh needs $tool" >&2; return 1; }
  done
  if [ -z "${JIMICHI:-}" ]; then
    command -v go >/dev/null || { echo "vault.sh needs go or JIMICHI" >&2; return 1; }
  fi
  deployment_context || return 1
  assert_suite_pods relay 5 || return 1
  assert_suite_anchor || return 1
  jimichi="${JIMICHI:-}"
  if [ -z "$jimichi" ]; then
    mkdir -p bin || return 1
    jimichi="bin/jimichi$(go env GOEXE)"
    go build -o "$jimichi" ./cmd/jimichi || return 1
  fi
  card_cover=$("$jimichi" keygen-card -suite "$SUITE" -mailbox "$(relay_addr relay-5)") || return 1
  [[ "$card_cover" = "$SUITE:"* ]] || { echo "the card of keygen-card does not identify suite=$SUITE" >&2; return 1; }
}

trim() {
  while [[ "$reply" = *$'\n' ]]; do reply="${reply%$'\n'}"; done
}

# the output of curl -w with the code (and the time) on its last line
answer() {
  local last="${1##*$'\n'}"
  reply="${1%$'\n'*}"
  [ "$reply" != "$1" ] || reply=""
  trim
  code="${last%% *}"
  took="${last#* }"
}

admin() {
  local client="$1" method="$2" path="$3" out
  out=$(curl -sS --max-time "$ADMIN_WAIT" -w '\n%{http_code}' -X "$method" "http://127.0.0.1:${port[$client]}$path") ||
    fail "$client: $method $path did not get an answer"
  answer "$out"
}

put_contact() {
  local client="$1" card="$2" out
  out=$(printf '%s' "$card" | curl -sS --max-time "$ADMIN_WAIT" -w '\n%{http_code}' -X PUT --data-binary @- "http://127.0.0.1:${port[$client]}/contact") ||
    fail "$client: PUT /contact did not get an answer"
  answer "$out"
}

init() {
  local client="$1" out url="http://127.0.0.1:${port[$1]}/vault/init"
  case "$client" in
    client-a) out=$(printf '%s\n\n%s\n%s\n' "$pw_real" "$pw_cover" "$card_cover" | curl -sS --max-time "$VAULT_OPEN_WAIT" -w '\n%{http_code} %{time_total}' -X PUT --data-binary @- "$url") ||
      fail "$client: PUT /vault/init did not get an answer" ;;
    client-b) out=$(printf '%s\n\n' "$pw_b" | curl -sS --max-time "$VAULT_OPEN_WAIT" -w '\n%{http_code} %{time_total}' -X PUT --data-binary @- "$url") ||
      fail "$client: PUT /vault/init did not get an answer" ;;
  esac
  answer "$out"
}

# the password goes by its name, never as a value
unlock() {
  local client="$1" which="$2" out url="http://127.0.0.1:${port[$1]}/vault/unlock"
  case "$which" in
    real) out=$(printf '%s\n' "$pw_real" | curl -sS --max-time "$VAULT_OPEN_WAIT" -w '\n%{http_code} %{time_total}' -X PUT --data-binary @- "$url") ||
      fail "$client: PUT /vault/unlock did not get an answer" ;;
    cover) out=$(printf '%s\n' "$pw_cover" | curl -sS --max-time "$VAULT_OPEN_WAIT" -w '\n%{http_code} %{time_total}' -X PUT --data-binary @- "$url") ||
      fail "$client: PUT /vault/unlock did not get an answer" ;;
    wrong) out=$(printf '%s\n' "$pw_wrong" | curl -sS --max-time "$WRONG_WAIT" -w '\n%{http_code} %{time_total}' -X PUT --data-binary @- "$url") ||
      fail "$client: PUT /vault/unlock did not get an answer" ;;
  esac
  answer "$out"
}

# one value of the one line of GET /status
field() {
  printf '%s\n' "$1" | sed -n "s/.*[{,]\"$2\":\(\"[^\"]*\"\|[0-9][0-9]*\).*/\1/p" | tr -d '"'
}

logs_of() {
  kubectl -n "$NAMESPACE" logs "pod/${pod[$1]}" -c client "${@:2}" | tr -d '\r'
}

forward() {
  local client="$1" log="$tmp/$1.log"
  kubectl_exec -n "$NAMESPACE" port-forward --address 127.0.0.1 "pod/${pod[$client]}" "${port[$client]}:$ADMIN_PORT" >"$log" 2>&1 &
  fwd[$client]=$!
  forwards+=("$!")
  wait_forward "$!" "$log" "${port[$client]}" || fail "$client: the port-forward to ${pod[$client]} did not come up"
}

unforward() {
  local pid="${fwd[$1]:-}"
  [ -n "$pid" ] || return 0
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  fwd[$1]=""
}

# the current container logged a locked start and opened nothing
locked_start() {
  local client="$1" log deadline=$((SECONDS + VAULT_POD_WAIT))
  while :; do
    log=$(logs_of "$client" 2>/dev/null || true)
    if printf '%s\n' "$log" | grep -q ' admin listening on ' && printf '%s\n' "$log" | grep -q ' vault locked$'; then
      if printf '%s\n' "$log" | grep -q ' vault opened$'; then
        fail "$client: ${pod[$client]} opened a volume before any init or unlock"
      fi
      return 0
    fi
    [ "$SECONDS" -lt "$deadline" ] || fail "$client: ${pod[$client]} did not start locked within ${VAULT_POD_WAIT}s"
    sleep "$VAULT_PAUSE"
  done
}

still_locked() {
  admin "$1" GET /card
  [ "$code" = 503 ] && [ "$reply" = "locked: no volume is open" ] ||
    fail "$1: GET /card answered $code $reply while locked, want 503 locked: no volume is open"
  admin "$1" GET /status
  [ "$code" = 503 ] || fail "$1: GET /status answered $code while locked, want 503"
}

await_locked() {
  local client="$1"
  pod[$client]=$(current_pod "$client") || fail "$client: no running pod"
  since[$client]=$(started_at "${pod[$client]}")
  restarts[$client]=$(restarts_of "${pod[$client]}")
  locked_start "$client"
  forward "$client"
  still_locked "$client"
}

capture() {
  local client="$1" run="$2" text
  text=$(logs_of "$client" "${@:3}") || fail "$client: no log of ${pod[$client]} to capture"
  caps_text+=("$text")
  caps_run+=("$run")
  caps_prev+=("${3:+previous}")
}

# a 503 not started ends the process, and the kubelet starts the container
# again in the same pod
restarted() {
  local client="$1" run="$2" now deadline=$((SECONDS + VAULT_POD_WAIT))
  while :; do
    now=$(restarts_of "${pod[$client]}")
    if [ -n "$now" ] && [ "$now" -gt "${restarts[$client]}" ]; then break; fi
    [ "$SECONDS" -lt "$deadline" ] || fail "$client: ${pod[$client]} did not restart after not started"
    sleep "$VAULT_PAUSE"
  done
  unforward "$client"
  capture "$client" "$run" --previous
  since[$client]=$(started_at "${pod[$client]}")
  restarts[$client]="$now"
  locked_start "$client"
  forward "$client"
}

# an init or an unlock that must end in 204; one not started is repeated once
open_volume() {
  local client="$1" how="$2" which="$3" run="$4" retried="" disk
  while :; do
    if [ "$how" = init ]; then init "$client"; else unlock "$client" "$which"; fi
    [ "$code" != 204 ] || return 0
    disk=""
    if [ "$code" = 503 ] && [[ "$reply" =~ ^vault:\ not\ started:\ (circuit|conversation|pin),\ (.+)$ ]]; then
      disk="${BASH_REMATCH[2]}"
    fi
    if [ -z "$retried" ] && { { [ "$how" = init ] && [ "$disk" = "no container" ]; } ||
      { [ "$how" = unlock ] && [ "$disk" = "the container is on disk" ]; }; }; then
      say "step $step: $client answered $code $reply, once more after its restart"
      retried=yes
      restarted "$client" "$run"
      continue
    fi
    fail "$client: PUT /vault/$how answered $code: $reply"
  done
}

stretch() {
  unlock client-a wrong
  [ "$code" = 403 ] && [ "$reply" = "vault: no volume opens with this password" ] ||
    fail "client-a: a wrong password answered $code $reply, want 403"
  say "stretch at the 500m limit: $took s (403, run $1)"
}

file_state() {
  local client="$1" out
  out=$(docker exec "${node[$client]}" ls -A "${dir[$client]}" | tr -d '\r') || fail "$client: no directory ${dir[$client]} on ${node[$client]}"
  [ "$out" = peer.vault ] || fail "$client: ${dir[$client]} holds $(printf '%s' "$out" | tr '\n' ' '), want peer.vault alone"
  out=$(docker exec "${node[$client]}" stat -c '%F|%a|%u|%g|%h|%s|%i' "${dir[$client]}/peer.vault" | tr -d '\r') ||
    fail "$client: no stat of the file"
  [[ "$out" =~ $FILE_STATE ]] || fail "$client: the file is $out, want a regular file, 600, 65532:65532, one link, 8224 bytes"
  file_now="$out"
  out=$(docker exec "${node[$client]}" sha256sum "${dir[$client]}/peer.vault" | tr -d '\r') || fail "$client: no sha256 of the file"
  sum_now="${out%% *}"
}

same_file() {
  file_state "$1"
  [ "$file_now" = "${snap[$1]}" ] && [ "$sum_now" = "${sum[$1]}" ] ||
    fail "$1: the file changed: $file_now $sum_now, after the introduction ${snap[$1]} ${sum[$1]}"
}

delete_pod() {
  local client="$1"
  kubectl -n "$NAMESPACE" delete pod "${pod[$client]}" --wait=true --timeout="${VAULT_POD_WAIT}s" >/dev/null ||
    fail "$client: ${pod[$client]} was not deleted"
  unforward "$client"
  await_locked "$client"
  same_file "$client"
}

await_trip() {
  local client="$1" from="$2" trips
  while :; do
    admin "$client" GET /status
    [ "$code" = 200 ] || fail "$client: GET /status answered $code: $reply"
    trips=$(field "$reply" round_trips)
    if [ -n "$trips" ] && [ "$trips" -gt 0 ]; then
      say "$client: a round trip $((SECONDS - from)) s after the 204"
      return 0
    fi
    [ $((SECONDS - from)) -lt "$VAULT_TRIP_WAIT" ] || fail "$client: no round trip within ${VAULT_TRIP_WAIT}s of the 204"
    sleep "$VAULT_PAUSE"
  done
}

# the kind of one line of a log, or nothing
kind_of() {
  local line="$1" rest k
  [[ "$line" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}\ (.*)$ ]] || return 0
  rest="${BASH_REMATCH[1]}"
  for k in "${KINDS[@]}"; do
    if [[ "$rest" =~ ${KIND_RE[$k]} ]]; then
      printf '%s\n' "$k"
      return 0
    fi
  done
}

check_capture() {
  local text="$1" prev="$2" line k card
  for card in "${identities[@]}"; do
    [[ "$text" != *"$card"* ]] || fail "a log names an identity: $card"
  done
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    k=$(kind_of "$line")
    [ -n "$k" ] || fail "a line outside the kinds of a client with -vault: $line"
    if [ "${KIND_CLASS[$k]:-}" = previous ] && [ "$prev" != previous ]; then
      fail "a line of a container that did not start, in a running one: $line"
    fi
    if [ "${KIND_CLASS[$k]:-}" = relay ]; then
      say "a line from the chain, outside the comparison: $line"
    fi
  done < <(printf '%s\n' "$text")
}

# every capture of a run, oldest first
run_text() {
  local i out=""
  for i in "${!caps_run[@]}"; do
    [ "${caps_run[$i]}" != "$1" ] || out+="${caps_text[$i]}"$'\n'
  done
  printf '%s' "$out"
}

kinds() {
  local line k
  local -A seen=()
  while IFS= read -r line; do
    k=$(kind_of "$line")
    [ -n "$k" ] && [ -z "${KIND_CLASS[$k]:-}" ] || continue
    seen[$k]=yes
  done < <(printf '%s\n' "$1")
  printf '%s\n' "${!seen[@]}" | sort | tr '\n' ' ' | sed 's/ $//'
}

# one vault written and a contact pinned after it
written_once() {
  local text="$1" written pinned
  written=$(printf '%s\n' "$text" | grep -n ' vault written$' | cut -d: -f1 | tr '\n' ' ')
  pinned=$(printf '%s\n' "$text" | grep -n ' contact pinned$' | head -n 1 | cut -d: -f1)
  [ "$(printf '%s' "$written" | wc -w)" -eq 1 ] && [ -n "$pinned" ] && [ "${written% }" -lt "$pinned" ]
}

claims_gone() {
  local client claim
  for client in "${CLIENTS[@]}"; do
    claim="vault-$client"
    [ -z "$(kubectl -n "$NAMESPACE" get pvc "$claim" --ignore-not-found -o name)" ] || { echo "$claim remains" >&2; return 1; }
    if [ -n "${volume[$client]:-}" ]; then
      [ -z "$(kubectl get pv "${volume[$client]}" --ignore-not-found -o name)" ] || { echo "pv/${volume[$client]} remains" >&2; return 1; }
    fi
    if [ -n "${dir[$client]:-}" ]; then
      docker exec "${node[$client]}" test ! -e "${dir[$client]}" || { echo "${dir[$client]} remains on ${node[$client]}" >&2; return 1; }
    fi
  done
}

stop_clients() {
  local inventory
  inventory=$(workload_inventory) || return 1
  check_inventory "$inventory" || return 1
  delete_captured_deployments "$inventory" client || return 1
  wait_old_pods "$inventory" client || return 1
}

drop_claims() {
  local client claim pv
  for client in "${CLIENTS[@]}"; do
    claim="vault-$client"
    pv=$(kubectl -n "$NAMESPACE" get pvc "$claim" --ignore-not-found -o jsonpath='{.spec.volumeName}') || return 1
    kubectl -n "$NAMESPACE" delete pvc "$claim" --ignore-not-found --wait=true --timeout="${VAULT_POD_WAIT}s" >/dev/null || return 1
    if [ -n "$pv" ]; then
      kubectl wait --for=delete "pv/$pv" --timeout="${VAULT_POD_WAIT}s" >/dev/null || return 1
    fi
  done
}

base_round_trip() {
  for _ in $(seq 1 40); do
    if logged_since_start client-a "e2e round trip in "; then return 0; fi
    sleep 3
  done
  echo "no round trip between the base clients" >&2
  return 1
}

restore_base() {
  local client
  unset pw_real pw_cover pw_b pw_wrong
  stop_forwards
  stop_clients || return 1
  drop_claims || return 1
  kubectl apply -f "$BASE" >/dev/null || return 1
  for client in "${CLIENTS[@]}"; do
    kubectl -n "$NAMESPACE" rollout status "deployment/$client" --timeout="${VAULT_POD_WAIT}s" >/dev/null || return 1
  done
  assert_suite_pods client 2 || return 1
  JIMICHI="$jimichi" RESTART=no bash "$INTRODUCE" || return 1
  base_round_trip || return 1
  claims_gone || return 1
}

tails() {
  local client f
  for client in "${CLIENTS[@]}"; do
    echo "--- $client" >&2
    kubectl -n "$NAMESPACE" logs "deployment/$client" -c client --tail=30 >&2 || true
  done
  for f in "$tmp"/*.log; do
    if [ -e "$f" ]; then
      echo "--- $(basename "$f" .log) port-forward" >&2
      cat "$f" >&2
    fi
  done
}

on_exit() {
  local status=$?
  trap - EXIT
  trap 'echo "$NOTICE" >&2; exit 3' INT TERM
  if [ "$status" -ne 0 ]; then tails; fi
  stop_forwards
  if [ -z "$restore" ]; then
    say "step 9: back to deploy/base"
    if restore_base; then restore=done; else restore=failed; fi
  fi
  rm -rf "$tmp"
  if [ "$restore" != done ]; then
    echo "$NOTICE" >&2
    exit 3
  fi
  [ "$status" -eq 0 ] || exit 1
  say "deploy/base restored, $SECONDS s in all"
}

say "bounds: open ${VAULT_OPEN_WAIT}s, round trip ${VAULT_TRIP_WAIT}s, silence ${VAULT_SILENT_WAIT}s, pod ${VAULT_POD_WAIT}s, pause ${VAULT_PAUSE}s; suite $SUITE"
preflight || exit 2
tmp=$(mktemp -d) || exit 2
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

step=1
say "step 1: a clean start of deploy/vault"
stop_clients || fail "the clients were not stopped"
drop_claims || fail "the claims of an earlier run were not removed"
kubectl apply -f "$OVERLAY" >/dev/null || fail "$OVERLAY was not applied"
for client in "${CLIENTS[@]}"; do
  kubectl -n "$NAMESPACE" rollout status "deployment/$client" --timeout="${VAULT_POD_WAIT}s" >/dev/null ||
    fail "$client did not roll out"
done
assert_suite_pods client 2 || fail "the clients of $OVERLAY do not run the suite of the testbed"
for client in "${CLIENTS[@]}"; do
  await_locked "$client"
  node[$client]=$(kubectl -n "$NAMESPACE" get pod "${pod[$client]}" -o jsonpath='{.spec.nodeName}')
  volume[$client]=$(kubectl -n "$NAMESPACE" get pvc "vault-$client" -o jsonpath='{.spec.volumeName}')
  [ -n "${node[$client]}" ] && [ -n "${volume[$client]}" ] || fail "$client: no node or no volume"
  out=$(kubectl get pv "${volume[$client]}" -o go-template='{{with .spec.hostPath}}hostPath {{.path}}{{end}}{{with .spec.local}}local {{.path}}{{end}}')
  kind[$client]="${out%% *}"
  dir[$client]="${out#* }"
  [ -n "${kind[$client]}" ] && [ "${dir[$client]}" != "$out" ] || fail "$client: pv/${volume[$client]} has no hostPath and no local path"
  out=$(docker exec "${node[$client]}" ls -A "${dir[$client]}" | tr -d '\r') || fail "$client: no directory ${dir[$client]} on ${node[$client]}"
  [ -z "$out" ] || fail "$client: ${dir[$client]} already holds $out"
  say "$client: ${pod[$client]} locked, pv/${volume[$client]} ${kind[$client]} ${dir[$client]} on ${node[$client]}, empty"
done

step=2
say "step 2: four passwords of 24 random bytes, in variables of this shell only"
pw_real=$(head -c 24 /dev/urandom | base64)
pw_cover=$(head -c 24 /dev/urandom | base64)
pw_b=$(head -c 24 /dev/urandom | base64)
pw_wrong=$(head -c 24 /dev/urandom | base64)

step=3
say "step 3: init, two volumes at client-a, one at client-b"
for client in "${CLIENTS[@]}"; do
  open_volume "$client" init "" init
  say "time to running: init $client $took s"
done

step=4
say "step 4: the introduction"
admin client-a GET /card
[ "$code" = 200 ] || fail "client-a: GET /card answered $code"
card_a="$reply"
admin client-b GET /card
[ "$code" = 200 ] || fail "client-b: GET /card answered $code"
card_b="$reply"
for card in "$card_a" "$card_b"; do
  [[ "$card" = "$SUITE:"* ]] || fail "a card does not identify suite=$SUITE"
done
[ "$card_a" != "$card_b" ] && [ "$card_a" != "$card_cover" ] && [ "$card_b" != "$card_cover" ] ||
  fail "the cards of client-a, client-b and the cover are not three"
put_contact client-a "$card_b"
[ "$code" = 204 ] || fail "client-a: PUT /contact answered $code: $reply"
put_contact client-b "$card_a"
[ "$code" = 204 ] || fail "client-b: PUT /contact answered $code: $reply"
t0=$SECONDS
for client in "${CLIENTS[@]}"; do
  admin "$client" GET /status
  [ "$code" = 200 ] || fail "$client: GET /status answered $code: $reply"
  [ "$(field "$reply" container)" = written ] && [ "$(field "$reply" state)" != unpaired ] ||
    fail "$client: status $reply, want the container written and a pinned contact"
  for _ in $(seq 1 "$ADMIN_WAIT"); do
    if written_once "$(logs_of "$client")"; then break; fi
    sleep 1
  done
  written_once "$(logs_of "$client")" || fail "$client: want one vault written line before contact pinned"
  file_state "$client"
  snap[$client]="$file_now"
  sum[$client]="$sum_now"
  say "$client: ${pod[$client]}: ${snap[$client]%|*} inode ${snap[$client]##*|} sha256 ${sum[$client]}"
  [ "$(current_pod "$client")" = "${pod[$client]}" ] && [ "$(started_at "${pod[$client]}")" = "${since[$client]}" ] &&
    [ "$(restarts_of "${pod[$client]}")" = "${restarts[$client]}" ] || fail "$client restarted between init and PUT /contact"
done
await_trip client-a "$t0"
admin client-b GET /status
state=$(field "$reply" state)
[ "$code" = 200 ] && { [ "$state" = established ] || [ "$state" = confirmed ]; } && [ "$(field "$reply" container)" = written ] ||
  fail "client-b: status $code $reply, want a session and the container written"
capture client-a init

step=5
say "step 5: client-a again, with the real password"
pod_b="${pod[client-b]}"
since_b="${since[client-b]}"
restarts_b="${restarts[client-b]}"
delete_pod client-a
stretch 5
open_volume client-a unlock real 5
t0=$SECONDS
say "time to running: unlock real $took s"
admin client-a GET /card
[ "$code" = 200 ] && [ "$reply" = "$card_a" ] || fail "client-a: the real password opened another identity"
await_trip client-a "$t0"
admin client-b GET /status
[ "$code" = 200 ] || fail "client-b: GET /status answered $code: $reply"
[ "$(current_pod client-b)" = "$pod_b" ] && [ "$(started_at "$pod_b")" = "$since_b" ] && [ "$(restarts_of "$pod_b")" = "$restarts_b" ] ||
  fail "client-b restarted"
if logged_since_start client-b "contact card changed, refusing"; then fail "client-b refused a card"; fi
capture client-a 5

step=6
say "step 6: client-a again, with the password of the cover volume"
delete_pod client-a
stretch 6
open_volume client-a unlock cover 6
t1=$SECONDS
say "time to running: unlock cover $took s"
admin client-a GET /card
[ "$code" = 200 ] || fail "client-a: GET /card answered $code"
card_a_cover="$reply"
[ "$card_a_cover" != "$card_a" ] && [ "$card_a_cover" != "$card_b" ] && [ "$card_a_cover" != "$card_cover" ] ||
  fail "client-a: the cover volume opened a known identity"
admin client-b GET /status
[ "$code" = 200 ] || fail "client-b: GET /status answered $code: $reply"
before_b="$(field "$reply" handshakes) $(field "$reply" refused_handshakes) $(field "$reply" bad)"
while :; do
  admin client-a GET /status
  [ "$code" = 200 ] || fail "client-a: GET /status answered $code: $reply"
  silent=$(field "$reply" silent_for)
  if [ -n "$silent" ] && [ "$silent" -gt "$SILENT_AFTER" ]; then break; fi
  [ $((SECONDS - t1)) -lt "$VAULT_SILENT_WAIT" ] || fail "client-a: silent_for ${silent:-none} ${VAULT_SILENT_WAIT}s after the 204, want more than $SILENT_AFTER"
  sleep "$VAULT_PAUSE"
done
[ "$(field "$reply" round_trips)" = 0 ] || fail "client-a: the cover volume made a round trip"
say "client-a: the cover volume silent for $silent s, no round trip"
admin client-b GET /status
[ "$code" = 200 ] || fail "client-b: GET /status answered $code: $reply"
after_b="$(field "$reply" handshakes) $(field "$reply" refused_handshakes) $(field "$reply" bad)"
[ "$after_b" = "$before_b" ] || fail "client-b: handshakes, refused_handshakes and bad went from $before_b to $after_b"
capture client-a 6
capture client-b b

step=7
say "step 7: the logs and the files"
identities=()
for card in "$card_a" "$card_b" "$card_cover" "$card_a_cover"; do
  identities+=("$card" "$("$jimichi" card-hash "$card")")
done
for i in "${!caps_text[@]}"; do
  check_capture "${caps_text[$i]}" "${caps_prev[$i]}"
done
for run in init b; do
  written_once "$(run_text "$run")" || fail "run $run: want one vault written line before contact pinned"
done
for run in 5 6; do
  if run_text "$run" | grep -q ' vault written$'; then fail "run $run wrote the file"; fi
done
kinds_5=$(kinds "$(run_text 5)")
kinds_6=$(kinds "$(run_text 6)")
say "kinds of line, run 5: $kinds_5; run 6: $kinds_6"
[ "$kinds_5" = "$kinds_6" ] || fail "the kinds of line differ between the real and the cover volume"
for client in "${CLIENTS[@]}"; do
  same_file "$client"
  out=$(docker exec "${node[$client]}" stat -c '%a|%u|%g' "${dir[$client]}" | tr -d '\r') || fail "$client: no stat of ${dir[$client]}"
  say "$client: pv ${kind[$client]}, directory mode|uid|gid $out, file ${file_now%|*} unchanged, sha256 $sum_now"
done

step=8
say "step 8: every restart without an unlock stayed locked (steps 5 and 6)"

step=9
say "step 9: back to deploy/base"
if restore_base; then restore=done; else restore=failed; fi
