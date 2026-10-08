#!/usr/bin/env bash
# deploy the testbed into the current cluster and pass only if client-a and
# client-b, introduced to each other, hold a conversation through the mailbox
# of relay-5 with a put in nearly every request, the mailbox is never an entry,
# a client holding a foreign anchor refuses to build a chain, each client
# asked one relay alone for descriptors, a client that pinned its contact
# refuses another card and stays stopped until it is introduced again, and no
# other pod reaches a cell port
set -euo pipefail

. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/checks.sh"

SUITE="${SUITE:-c25519}"
CLUSTER="${CLUSTER:-jimichi}"
REQUIRE_ISOLATION="${REQUIRE_ISOLATION:-${CI:-false}}"
PROBE_IMAGE="busybox:1.37.0"
# the linux/amd64 manifest, not the multi-platform index: kind load cannot import
# an index whose other platforms were never pulled
PROBE_DIGEST="sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4"

kubectl apply -f deploy/base/relay.yaml -f deploy/base/network.yaml
relay_list=$(relays)
relay_count=$(printf '%s\n' "$relay_list" | awk 'END { print NR }')
for relay in $relay_list; do
  kubectl -n "$NAMESPACE" rollout status "deployment/$relay" --timeout=180s
done
# a client left from an earlier run would ask a relay while the counts below
# are taken, so it goes now and comes back once they are; every client pod
# counted below then started after the relays it reaches and the anchor that
# certifies them. Deleting both also removes a client-a whose selector
# predates client-b, which an apply could not change
kubectl -n "$NAMESPACE" delete deployment client-a client-b --ignore-not-found --wait=true >/dev/null
kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found --wait=true >/dev/null
for _ in $(seq 1 60); do
  [ -z "$(kubectl -n "$NAMESPACE" get pods -l app=client -o name 2>/dev/null)" ] && break
  sleep 2
done
if ! bash scripts/enroll.sh; then
  echo "enrollment failed" >&2
  kubectl -n "$NAMESPACE" get pods -o wide >&2 || true
  kubectl -n "$NAMESPACE" logs -l app=relay --prefix --tail=20 >&2 || true
  exit 1
fi

# the conversation of client-a since the start of its container: a round trip
# through the mailbox within two minutes
await_round_trip() {
  for _ in $(seq 1 40); do
    if logged_since_start client-a "e2e round trip in "; then
      kubectl -n "$NAMESPACE" logs deployment/client-a --tail=3
      return 0
    fi
    sleep 3
  done
  echo "no round trip between the clients" >&2
  kubectl -n "$NAMESPACE" get pods -o wide >&2 || true
  for client in client-a client-b; do
    kubectl -n "$NAMESPACE" logs "deployment/$client" --tail=30 >&2 || true
  done
  return 1
}

# a relay fetches the descriptor of each roster peer once and again from half
# of its life until the peer serves a later one, long after a fresh
# enrollment. Two passes in a row that show every relay with all its
# peers and the same counts of descriptor requests mean those fetches are over:
# a single pass could be read while the last relay is still asking. From here
# the requests a relay answers for its own descriptor stay as they are unless a
# client asks it
all_peers=""
for relay in $relay_list; do all_peers="$all_peers $((relay_count - 1))"; done
all_peers="${all_peers# }"
settled=""
asked=""
for _ in $(seq 1 30); do
  stats=$(bash scripts/stats.sh 2>/dev/null || true)
  seen=""
  if [ "$(column "$stats" peers || true)" = "$all_peers" ]; then
    seen=$(column "$stats" descriptor_requests || true)
  fi
  if [ -n "$seen" ] && [ "$seen" = "$asked" ]; then
    settled=yes
    break
  fi
  asked="$seen"
  sleep 2
done
if [ -z "$settled" ]; then
  echo "the relays did not settle with the descriptors of their $((relay_count - 1)) roster peers" >&2
  bash scripts/stats.sh >&2 || true
  kubectl -n "$NAMESPACE" logs -l app=relay --prefix --tail=20 >&2 || true
  exit 1
fi
stats_0="$stats"
mirror_0=$(column "$stats" mirror_requests)

jimichi="bin/jimichi$(go env GOEXE)"
kubectl apply -f deploy/base/client.yaml
for client in client-a client-b; do
  kubectl -n "$NAMESPACE" rollout status "deployment/$client" --timeout=180s
done
if ! JIMICHI="$jimichi" RESTART=no bash scripts/introduce.sh; then
  echo "the clients were not introduced" >&2
  for client in client-a client-b; do
    kubectl -n "$NAMESPACE" logs "deployment/$client" --tail=30 >&2 || true
  done
  exit 1
fi
await_round_trip || exit 1
for relay in $relay_list; do
  pod=$(current_pod "$relay") && kubectl -n "$NAMESPACE" logs "pod/$pod" --tail=1 || true
done

stats=$(stats_pass) || { echo "no counters from the relays after the round trip" >&2; exit 1; }
mirror_1=$(column "$stats" mirror_requests)
starts_1=$(client_starts)
# a rebuild goes through the same entry, so it asks no other relay
entries=$(entries_of "client-a and client-b" "$mirror_0" "$mirror_1" "$starts_1")
check_mailboxes "$stats" || exit 1
check_mailbox_not_entry "$stats_0" "$stats" || exit 1
echo "mailbox: $MAILBOX_RELAY keeps the queues, the clients asked $entries for the descriptors"
put_share || exit 1

# the same relays, verified against the anchor of a CA that certified none of them
foreign=$("bin/jimichi$(go env GOEXE)" keygen-ca -suite "$SUITE")
nodes=""
for relay in $relay_list; do nodes="$nodes,$(relay_addr "$relay")"; done
nodes="${nodes#,}"
# the pod runs under the same restrictions as client-a, so its refusal is the
# one a real client gives; the overrides replace the whole container
overrides=$(cat <<JSON
{
  "apiVersion": "v1",
  "spec": {
    "securityContext": {"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [{
      "name": "badca",
      "image": "jimichi/client:dev",
      "imagePullPolicy": "IfNotPresent",
      "args": ["-nodes", "$nodes", "-suite", "$SUITE", "-ca", "$foreign", "-count", "1"],
      "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}}
    }]
  }
}
JSON
)
kubectl -n "$NAMESPACE" run badca --image=jimichi/client:dev --restart=Never --overrides="$overrides" >/dev/null
if ! kubectl -n "$NAMESPACE" wait pod/badca --for=jsonpath='{.status.phase}'=Failed --timeout=120s >/dev/null; then
  echo "a client with a foreign anchor did not fail" >&2
  kubectl -n "$NAMESPACE" logs pod/badca >&2 || true
  kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found >/dev/null
  exit 1
fi
refusal=$(kubectl -n "$NAMESPACE" logs pod/badca | grep "refusing to build the circuit" | grep "certificate from an unknown CA" || true)
if [ -z "$refusal" ]; then
  echo "a client with a foreign anchor failed without refusing the chain for its unknown CA" >&2
  kubectl -n "$NAMESPACE" logs pod/badca >&2 || true
  kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found >/dev/null
  exit 1
fi
kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found >/dev/null
echo "foreign anchor: $refusal"

# the refused client ran once and asked one relay as well, and no relay
# answered a request for its own descriptor since the counts taken before the
# clients: a client asks no node for a descriptor of that node alone
stats=$(stats_pass) || { echo "no counters from the relays after the clients" >&2; exit 1; }
mirror_2=$(column "$stats" mirror_requests)
starts_2=$(client_starts)
entry_refused=$(entries_of "the refused client, with the clients restarting $((starts_2 - starts_1)) time(s)," "$mirror_1" "$mirror_2" "$((1 + starts_2 - starts_1))")
asked_after=$(column "$stats" descriptor_requests)
if [ "$asked_after" != "$asked" ]; then
  echo "a relay answered a request for its own descriptor after the relays had settled: a client asked a node other than through the descriptors of its entry" >&2
  echo "descriptor requests per relay before the clients: $asked" >&2
  echo "descriptor requests per relay after the clients:  $asked_after" >&2
  printf '%s\n' "$stats" >&2
  exit 1
fi
echo "entry only: the clients asked $entries for the descriptors, the refused client $entry_refused, and no relay was asked for its own descriptor"

# only a new introduction, which restarts both clients, brings the
# conversation back after the refusal
trap stop_forwards EXIT
refuse_other_cards || exit 1
JIMICHI="$jimichi" bash scripts/introduce.sh || exit 1
await_round_trip || exit 1

# a hardened pod that is neither a client nor a relay must not reach any cell
# port; reaching every info port shows that a refusal comes from the policy and
# not from a probe that cannot reach the relays at all
isolation() {
  local script="" code="" relay host
  # pulled by digest on the host and loaded like the testbed images, so the
  # nodes need no registry access and run exactly this image
  docker image inspect "busybox@$PROBE_DIGEST" >/dev/null 2>&1 || docker pull -q "busybox@$PROBE_DIGEST" >/dev/null
  docker tag "busybox@$PROBE_DIGEST" "$PROBE_IMAGE"
  kind load docker-image "$PROBE_IMAGE" --name "$CLUSTER" >/dev/null
  for relay in $relay_list; do
    host="$relay.$NAMESPACE.svc.cluster.local"
    script="$script nc -z -w 3 $host 9100 || exit 2;"
    script="$script if nc -z -w 3 $host 9000; then exit 1; fi;"
  done
  kubectl -n "$NAMESPACE" delete pod isolation-probe --ignore-not-found --wait=true >/dev/null
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: isolation-probe
  namespace: $NAMESPACE
  labels: {app: probe}
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: probe
      image: $PROBE_IMAGE
      imagePullPolicy: Never
      command: ["sh", "-c", "$script"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        requests: {cpu: 10m, memory: 8Mi}
        limits: {cpu: 100m, memory: 32Mi}
EOF
  for _ in $(seq 1 60); do
    code=$(kubectl -n "$NAMESPACE" get pod isolation-probe \
      -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)
    [ -n "$code" ] && break
    sleep 2
  done
  kubectl -n "$NAMESPACE" delete pod isolation-probe --ignore-not-found --wait=false >/dev/null
  case "$code" in
    0) echo "isolation: the cell ports of $relay_count relays closed to other pods, info ports open"; return 0 ;;
    1) echo "isolation: NOT ENFORCED, a pod that is neither a client nor a relay reached a cell port; the network plugin of this cluster ignores the policy (kindnet needs nftables queue support in the kernel, which WSL2 lacks)" >&2 ;;
    2) echo "isolation: the probe reached no info port, so it proves nothing" >&2 ;;
    *) echo "isolation: the probe did not finish" >&2 ;;
  esac
  # CI runs on a kernel that enforces the policy, so there a failed probe fails
  # the run; a development host may lack the support and only gets the warning
  [ "$REQUIRE_ISOLATION" = "true" ] && return 1
  echo "isolation: not required here (REQUIRE_ISOLATION=$REQUIRE_ISOLATION), continuing" >&2
  return 0
}

isolation
