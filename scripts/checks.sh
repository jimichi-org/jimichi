# sourced by e2e.sh after lib.sh: the checks of a deployed testbed. Each one
# fails with a line on standard error and a nonzero status, so the scripts
# tests run it against stand-ins; relay_list holds the relays in the order of
# scripts/stats.sh
# the relay whose mailbox the clients use, as deploy/base/client.yaml says
MAILBOX_RELAY="${MAILBOX_RELAY:-relay-5}"
# the forwards of the refusal check: client-a takes the base + 1, client-b + 2
CHECK_PORT_BASE="${CHECK_PORT_BASE:-19410}"
# seconds between two looks at a log
CHECK_PAUSE="${CHECK_PAUSE:-1}"

# one counter of one relay out of the lines scripts/stats.sh prints
counter() {
  printf '%s\n' "$1" | sed -n "s/^$2 .*\"$3\":\([0-9][0-9]*\).*/\1/p"
}

# one counter of every relay as one line, in the order of the list; fails when
# the pass lacks a relay
column() {
  local relay value out=""
  for relay in $relay_list; do
    value=$(counter "$1" "$relay" "$2")
    [ -n "$value" ] || return 1
    out="$out $value"
  done
  printf '%s\n' "${out# }"
}

# the relays whose counter is higher in the second column than in the first
grown() {
  local before after relay place=0 out=""
  read -r -a before <<<"$1"
  read -r -a after <<<"$2"
  for relay in $relay_list; do
    if [ "${after[$place]}" -gt "${before[$place]}" ]; then out="$out $relay"; fi
    place=$((place + 1))
  done
  printf '%s\n' "${out# }"
}

# one pass of scripts/stats.sh that shows every relay, or nothing
stats_pass() {
  local out
  for _ in $(seq 1 10); do
    out=$(bash scripts/stats.sh 2>/dev/null || true)
    if column "$out" mirror_requests >/dev/null; then
      printf '%s\n' "$out"
      return 0
    fi
    sleep 2
  done
  return 1
}

# how many times the containers of both clients have started
client_starts() {
  local client pod restarts total=0
  for client in client-a client-b; do
    pod=$(current_pod "$client") || return 1
    restarts=$(restarts_of "$pod")
    total=$((total + restarts + 1))
  done
  echo "$total"
}

# whether the running container of a client logged a line that matches, from
# its own start on
logged_since_start() {
  local client="$1" pattern="$2" pod since
  pod=$(current_pod "$client") || return 1
  since=$(started_at "$pod")
  [ -n "$since" ] && kubectl -n "$NAMESPACE" logs "pod/$pod" -c client --since-time="$since" 2>/dev/null | grep -Eq "$pattern"
}

# every start of a client draws one entry and asks that relay alone for the
# descriptors of all listed nodes, so between two passes the requests for the
# mirror grow at one relay per client start and at no other. The starts are
# read after the counters: a restart in between only widens the bound
entries_of() {
  local what="$1" before="$2" after="$3" starts="$4" entries count
  entries=$(grown "$before" "$after")
  count=$(printf '%s\n' "$entries" | awk '{ print NF }')
  if [ "$count" -lt 1 ] || [ "$count" -gt "$starts" ]; then
    echo "$what started $starts time(s) and $count relays answered a request for the descriptors, want one per start: ${entries:-none}" >&2
    echo "requests for the descriptors per relay before: $before" >&2
    echo "requests for the descriptors per relay after:  $after" >&2
    return 1
  fi
  printf '%s\n' "$entries"
}

# the conversation keeps its queues on the mailbox relay alone: every relay
# runs -exit mailbox and shows the counters, the mailbox relay took puts and
# answered fetches with a record, and no other relay saw a mailbox request
check_mailboxes() {
  local stats="$1" relay requests puts hits
  for relay in $relay_list; do
    requests=$(counter "$stats" "$relay" mailbox_requests)
    puts=$(counter "$stats" "$relay" mailbox_puts)
    hits=$(counter "$stats" "$relay" mailbox_hits)
    if [ -z "$requests" ] || [ -z "$puts" ] || [ -z "$hits" ]; then
      echo "$relay shows no mailbox counters: every relay runs -exit mailbox" >&2
      return 1
    fi
    if [ "$relay" = "$MAILBOX_RELAY" ]; then
      if [ "$puts" -eq 0 ] || [ "$hits" -eq 0 ]; then
        echo "the mailbox of $relay took $puts puts and answered $hits fetches with a record after a round trip" >&2
        return 1
      fi
    elif [ "$requests" -ne 0 ]; then
      echo "$relay answered $requests mailbox requests, only $MAILBOX_RELAY ends the chains of the clients" >&2
      return 1
    fi
  done
}

# the mailbox relay is never an entry: a -peer client draws its entry among
# the other relays, so between two passes the mailbox relay answered no
# request for the descriptors
check_mailbox_not_entry() {
  local asked_0 asked_1
  asked_0=$(counter "$1" "$MAILBOX_RELAY" mirror_requests)
  asked_1=$(counter "$2" "$MAILBOX_RELAY" mirror_requests)
  if [ -z "$asked_0" ] || [ -z "$asked_1" ]; then
    echo "$MAILBOX_RELAY shows no count of requests for the descriptors" >&2
    return 1
  fi
  if [ "$asked_1" != "$asked_0" ]; then
    echo "$MAILBOX_RELAY answered $((asked_1 - asked_0)) requests for the descriptors: the mailbox was an entry" >&2
    return 1
  fi
}

# with cover puts every request after the session carries a put unless the
# window of puts in flight is full, and 16 puts at 200 ms cover any round trip
# of the stand: between two passes $3 seconds apart the mailbox relay took a
# put, stored, full or refused, in at least 0.9 of its requests
put_share_between() {
  local first="$1" second="$2" seconds="$3" requests puts key
  requests=$(($(counter "$second" "$MAILBOX_RELAY" mailbox_requests) - $(counter "$first" "$MAILBOX_RELAY" mailbox_requests)))
  puts=0
  for key in mailbox_puts mailbox_put_full mailbox_put_refused; do
    puts=$((puts + $(counter "$second" "$MAILBOX_RELAY" "$key") - $(counter "$first" "$MAILBOX_RELAY" "$key")))
  done
  if [ "$requests" -le 0 ] || [ $((10 * puts)) -lt $((9 * requests)) ]; then
    echo "the mailbox took $puts puts in $requests requests over ${seconds}s, want at least 0.9 of them" >&2
    return 1
  fi
  echo "puts: $puts in $requests requests at the mailbox over ${seconds}s"
}

put_share() {
  local first second
  first=$(stats_pass) || return 1
  sleep 30
  second=$(stats_pass) || return 1
  put_share_between "$first" "$second" 30
}

forwards=()
stop_forwards() {
  for pid in "${forwards[@]}"; do kill "$pid" 2>/dev/null || true; done
  forwards=()
}

# the card goes to curl on standard input, not on its command line
put_card() {
  printf '%s' "$2" | curl -sS -w '\n%{http_code}' -X PUT --data-binary @- "http://127.0.0.1:$1/contact" | tail -n 1
}

# a client that pinned its contact takes no other card: a card of a key nobody
# holds and then the real card of client-a are both refused with 409, and
# client-b logs the refusal and stays stopped without a restart; $jimichi is
# the binary that makes the card
refuse_other_cards() {
  local foreign pod_a pod_b restarts_b log port_a port_b card_a code refused=""
  foreign=$("$jimichi" keygen-card -suite "$SUITE" -mailbox "$(relay_addr "$MAILBOX_RELAY")") || return 1
  pod_a=$(current_pod client-a) || return 1
  pod_b=$(current_pod client-b) || return 1
  restarts_b=$(restarts_of "$pod_b")
  port_a=$((CHECK_PORT_BASE + 1))
  port_b=$((CHECK_PORT_BASE + 2))
  log=$(mktemp)
  kubectl -n "$NAMESPACE" port-forward --address 127.0.0.1 "pod/$pod_a" "$port_a:9201" >"$log" 2>&1 &
  forwards+=("$!")
  wait_forward "$!" "$log" "$port_a" || return 1
  kubectl -n "$NAMESPACE" port-forward --address 127.0.0.1 "pod/$pod_b" "$port_b:9201" >"$log.b" 2>&1 &
  forwards+=("$!")
  wait_forward "$!" "$log.b" "$port_b" || return 1
  rm -f "$log" "$log.b"
  card_a=$(curl -fsS "http://127.0.0.1:$port_a/card") || return 1

  code=$(put_card "$port_b" "$foreign")
  if [ "$code" != 409 ]; then
    echo "client-b answered $code to the card of a key nobody holds, want 409" >&2
    return 1
  fi
  for _ in $(seq 1 10); do
    if logged_since_start client-b "contact card changed, refusing: pinned card_hash="; then
      refused=yes
      break
    fi
    sleep "$CHECK_PAUSE"
  done
  [ -n "$refused" ] || { echo "client-b did not log the refusal" >&2; return 1; }
  code=$(put_card "$port_b" "$card_a")
  if [ "$code" != 409 ]; then
    echo "the stopped client-b answered $code to the card it had pinned, want 409" >&2
    return 1
  fi
  if [ "$(current_pod client-b)" != "$pod_b" ] || [ "$(restarts_of "$pod_b")" != "$restarts_b" ]; then
    echo "client-b restarted after the refusal; it must stay stopped until the operator restarts it" >&2
    return 1
  fi
  stop_forwards
  echo "refusal: client-b answered 409 to another card and to the card it had pinned, and stays stopped"
}
