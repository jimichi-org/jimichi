#!/usr/bin/env bash
# introduce client-a and client-b: each pins the contact card of the other. A
# card reaches the operator only through a port-forward to the loopback admin
# port of its client, and it is taken only if it hashes to the card_hash line
# that client printed in the log of its running container. A restart of
# either client is a new identity, so with RESTART=yes (the default) both are
# restarted first; any failure starts over with a restart, three times at most
set -euo pipefail

. "$(dirname "$0")/lib.sh"

RESTART="${RESTART:-yes}"
# client-a takes the local port base + 1, client-b base + 2
INTRODUCE_PORT_BASE="${INTRODUCE_PORT_BASE:-19400}"
# seconds between two looks at a log or a port
INTRODUCE_PAUSE="${INTRODUCE_PAUSE:-1}"
ADMIN_PORT=9201
CLIENTS=(client-a client-b)

jimichi="${JIMICHI:-}"
if [ -z "$jimichi" ]; then
  mkdir -p bin
  jimichi="bin/jimichi$(go env GOEXE)"
  go build -o "$jimichi" ./cmd/jimichi
fi

logs=$(mktemp -d)
forwards=()
stop_forwards() {
  for pid in "${forwards[@]}"; do kill "$pid" 2>/dev/null || true; done
  forwards=()
}
cleanup() {
  local status=$?
  stop_forwards
  if [ "$status" -ne 0 ]; then
    for f in "$logs"/*.log; do
      [ -e "$f" ] && { echo "--- $(basename "$f" .log) port-forward" >&2; cat "$f" >&2; }
    done
  fi
  rm -rf "$logs"
}
trap cleanup EXIT

# the client prints its card_hash once, before any request, as a line of its
# own; anything but one such line means the wrong container or a log that is
# not there yet
card_hash_of() {
  local pod="$1" found count=0
  for _ in $(seq 1 10); do
    found=$(kubectl -n "$NAMESPACE" logs "pod/$pod" -c client 2>/dev/null |
      sed -n 's/^[0-9/]* [0-9:]* card_hash=\([0-9a-f]\{64\}\)$/\1/p')
    count=$(printf '%s\n' "$found" | awk 'NF { n++ } END { print n + 0 }')
    if [ "$count" -eq 1 ]; then
      printf '%s\n' "$found"
      return 0
    fi
    sleep "$INTRODUCE_PAUSE"
  done
  echo "pod/$pod: $count card_hash lines in the log of its current container, want exactly one" >&2
  return 1
}

# the client opens its admin port once its first circuit stands and says so;
# a forward to a port nobody listens on yet could end on the first request
admin_up() {
  local pod="$1"
  for _ in $(seq 1 90); do
    if kubectl -n "$NAMESPACE" logs "pod/$pod" -c client 2>/dev/null | grep -q " admin listening on "; then
      return 0
    fi
    sleep "$INTRODUCE_PAUSE"
  done
  echo "pod/$pod did not open its admin port" >&2
  return 1
}

# the line a client prints once it has pinned the card that hashes to $2
pinned() {
  local pod="$1" hash="$2"
  for _ in $(seq 1 10); do
    if kubectl -n "$NAMESPACE" logs "pod/$pod" -c client 2>/dev/null | grep -q " contact pinned card_hash=$hash "; then
      return 0
    fi
    sleep "$INTRODUCE_PAUSE"
  done
  echo "pod/$pod did not log that it pinned card_hash=$hash" >&2
  return 1
}

# PUT /contact through the forward; the card goes on standard input, not on a
# command line
put_card() {
  printf '%s' "$2" | curl -sS -w '\n%{http_code}' -X PUT --data-binary @- "http://127.0.0.1:$1/contact" | tail -n 1
}

attempt() {
  local restart="$1" i pod log port card got code
  local pods=() since=() hashes=() ports=() cards=()
  if [ "$restart" = yes ]; then
    kubectl -n "$NAMESPACE" rollout restart deployment/client-a deployment/client-b >/dev/null || return 1
    for i in 0 1; do
      kubectl -n "$NAMESPACE" rollout status "deployment/${CLIENTS[$i]}" --timeout=180s >/dev/null || return 1
    done
  fi
  for i in 0 1; do
    pod=$(current_pod "${CLIENTS[$i]}") || return 1
    kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=120s >/dev/null || return 1
    pods[i]="$pod"
    since[i]=$(started_at "$pod") || return 1
    hashes[i]=$(card_hash_of "$pod") || return 1
    admin_up "$pod" || return 1
    port=$((INTRODUCE_PORT_BASE + i + 1))
    ports[i]="$port"
    log="$logs/${CLIENTS[$i]}.log"
    # the admin port listens on loopback inside the pod, so only a
    # port-forward through the kube API reaches it
    kubectl -n "$NAMESPACE" port-forward --address 127.0.0.1 "pod/$pod" "$port:$ADMIN_PORT" >"$log" 2>&1 &
    forwards+=("$!")
    wait_forward "$!" "$log" "$port" || return 1
  done
  for i in 0 1; do
    card=""
    for _ in $(seq 1 10); do
      card=$(curl -fsS "http://127.0.0.1:${ports[$i]}/card" 2>/dev/null) && break
      card=""
      sleep "$INTRODUCE_PAUSE"
    done
    if [ -z "$card" ]; then
      echo "${CLIENTS[$i]}: no card from its admin port" >&2
      return 1
    fi
    got=$("$jimichi" card-hash "$card") || return 1
    if [ "$got" != "${hashes[$i]}" ]; then
      echo "${CLIENTS[$i]}: the card on its admin port hashes to $got, its log says ${hashes[$i]}" >&2
      return 1
    fi
    cards[i]="$card"
  done
  for i in 0 1; do
    code=$(put_card "${ports[$i]}" "${cards[$((1 - i))]}") || return 1
    if [ "$code" != 204 ]; then
      echo "${CLIENTS[$i]}: PUT /contact answered $code, want 204" >&2
      return 1
    fi
  done
  for i in 0 1; do
    pinned "${pods[$i]}" "${hashes[$((1 - i))]}" || return 1
  done
  # a container that restarted between reading its card and the PUT is a new
  # identity that pinned nothing
  for i in 0 1; do
    if [ "$(current_pod "${CLIENTS[$i]}")" != "${pods[$i]}" ] || [ "$(started_at "${pods[$i]}")" != "${since[$i]}" ]; then
      echo "${CLIENTS[$i]} restarted during the introduction" >&2
      return 1
    fi
  done
  echo "introduced client-a=${hashes[0]} client-b=${hashes[1]}"
}

restart="$RESTART"
for n in 1 2 3; do
  if attempt "$restart"; then
    exit 0
  fi
  stop_forwards
  echo "introduction attempt $n failed" >&2
  restart=yes
done
echo "client-a and client-b were not introduced in 3 attempts" >&2
exit 1
