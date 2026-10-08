# sourced by the other scripts
NAMESPACE="${NAMESPACE:-jimichi}"
# Git Bash rewrites arguments that look like paths, and a base64 anchor can
export MSYS_NO_PATHCONV=1

# the relay deployments, found by label and printed in the order of their
# names: the scripts take the relays from here, however many the testbed runs
relays() {
  local names
  names=$(kubectl -n "$NAMESPACE" get deployment -l app=relay \
    -o go-template='{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}' | sort -V)
  [ -n "$names" ] || { echo "no relay deployment in namespace $NAMESPACE" >&2; return 1; }
  printf '%s\n' "$names"
}

# a script forwards a relay to the local port base + its place in the list,
# and the bases are 100 apart (19100 for the counters, 19200 and 19300 for
# enrollment), so the ranges of up to 99 relays do not meet
ports_fit() {
  if [ "$(printf '%s\n' "$1" | wc -l)" -gt 99 ]; then
    echo "more than 99 relays: their local ports would run into the next port base" >&2
    return 1
  fi
}

# the address a relay advertises and its certificate carries; a relay is named
# after its deployment and its service
relay_addr() {
  printf '%s.%s.svc.cluster.local:9000\n' "$1" "$NAMESPACE"
}

# prints the one running pod of the newest rollout of a deployment; right after a
# restart the old pods still exist, and kubectl would happily read their logs
current_pod() {
  local deploy="$1" selector hash pods
  selector=$(kubectl -n "$NAMESPACE" get deployment "$deploy" \
    -o go-template='{{range $k, $v := .spec.selector.matchLabels}}{{$k}}={{$v}},{{end}}')
  selector="${selector%,}"
  [ -n "$selector" ] || { echo "no deployment/$deploy" >&2; return 1; }
  for _ in $(seq 1 60); do
    hash=$(kubectl -n "$NAMESPACE" get rs -l "$selector" \
      -o go-template='{{range .items}}{{$rs := .}}{{range .metadata.ownerReferences}}{{if eq .name "'"$deploy"'"}}{{index $rs.metadata.annotations "deployment.kubernetes.io/revision"}} {{index $rs.metadata.labels "pod-template-hash"}}{{"\n"}}{{end}}{{end}}{{end}}' \
      | sort -n | tail -1 | cut -d' ' -f2)
    pods=$(kubectl -n "$NAMESPACE" get pods -l "$selector,pod-template-hash=$hash" \
      -o go-template='{{range .items}}{{if and (eq .status.phase "Running") (not .metadata.deletionTimestamp)}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}')
    if [ -n "$hash" ] && [ -n "$pods" ] && [ "$(printf '%s\n' "$pods" | wc -l)" -eq 1 ]; then
      printf '%s\n' "$pods"
      return 0
    fi
    sleep 1
  done
  echo "no single running pod for deployment/$deploy" >&2
  return 1
}

# when the running container of a pod started, on the cluster clock
started_at() {
  kubectl -n "$NAMESPACE" get pod "$1" -o jsonpath='{.status.containerStatuses[0].state.running.startedAt}'
}

# kubectl prints one line per local port once it listens; waiting for them
# keeps the caller from racing the forward
wait_forward() {
  local pid="$1" log="$2"
  shift 2
  for _ in $(seq 1 150); do
    kill -0 "$pid" 2>/dev/null || { echo "port-forward $(basename "$log" .log) exited" >&2; return 1; }
    local ready=yes
    for port in "$@"; do
      grep -q "Forwarding from 127.0.0.1:$port " "$log" || ready=""
    done
    [ -n "$ready" ] && return 0
    sleep 0.1
  done
  echo "port-forward $(basename "$log" .log) did not come up" >&2
  return 1
}

# how many times the running container of a pod has been restarted
restarts_of() {
  kubectl -n "$NAMESPACE" get pod "$1" -o jsonpath='{.status.containerStatuses[0].restartCount}'
}

# the selector of a deployment cannot change, and client-a once selected only
# app=client; such a deployment goes before the manifest of the two clients
drop_old_client() {
  kubectl -n "$NAMESPACE" get deployment client-a >/dev/null 2>&1 || return 0
  if [ -z "$(kubectl -n "$NAMESPACE" get deployment client-a -o jsonpath='{.spec.selector.matchLabels.client}')" ]; then
    kubectl -n "$NAMESPACE" delete deployment client-a --wait=true >/dev/null
  fi
}

# both clients of the conversation run: client-b exists only with the manifest
# that selects each client by its own label
peers_deployed() {
  kubectl -n "$NAMESPACE" get deployment client-b >/dev/null 2>&1 &&
    [ -n "$(kubectl -n "$NAMESPACE" get deployment client-a -o jsonpath='{.spec.selector.matchLabels.client}' 2>/dev/null)" ]
}
