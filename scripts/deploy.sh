# sourced by deployment entry points after lib.sh
CLUSTER="${CLUSTER:-jimichi}"
SUITE="${SUITE:-c25519}"
export CLUSTER NAMESPACE SUITE

require_suite() {
  case "$SUITE" in
    c25519|gost) ;;
    *) echo "unsupported SUITE=$SUITE; choose c25519 or gost" >&2; return 1 ;;
  esac
}

healthy_nodes() {
  local nodes names
  nodes=$(kubectl get nodes -o go-template='{{range .items}}{{.metadata.name}}{{"|"}}{{if .spec.unschedulable}}unschedulable{{end}}{{"|"}}{{range .status.conditions}}{{if eq .type "Ready"}}{{.status}}{{end}}{{end}}{{"\n"}}{{end}}') || return 1
  if ! printf '%s\n' "$nodes" | awk -F '|' -v cluster="$CLUSTER" '
    NF != 3 || $1 !~ "^" cluster "-(control-plane|worker[0-9]*)$" || $2 != "" || $3 != "True" { bad=1 }
    END { exit bad || NR == 0 }
  '; then
    echo "deployment requires healthy, schedulable nodes of kind-$CLUSTER: $nodes" >&2
    return 1
  fi
  names=$(printf '%s\n' "$nodes" | cut -d'|' -f1 | sort)
  if [ -n "${JIMICHI_HEALTHY_NODES:-}" ] && [ "$names" != "$JIMICHI_HEALTHY_NODES" ]; then
    echo "cluster node membership changed during deployment" >&2
    return 1
  fi
  export JIMICHI_HEALTHY_NODES="$names"
}

deployment_context() {
  local context server processes
  require_suite || return 1
  [ "$NAMESPACE" = jimichi ] || { echo "deployment requires NAMESPACE=jimichi" >&2; return 1; }
  [[ "$CLUSTER" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "invalid local kind cluster name: $CLUSTER" >&2; return 1; }
  context=$(kubectl config current-context) || return 1
  [ "$context" = "kind-$CLUSTER" ] || { echo "current context $context, want kind-$CLUSTER" >&2; return 1; }
  export JIMICHI_CONTEXT="$context"
  server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}') || return 1
  [[ "$server" =~ ^https://(127\.0\.0\.1|localhost|\[::1\]):[0-9]+$ ]] || {
    echo "kind API server must use loopback: $server" >&2; return 1;
  }
  unset JIMICHI_HEALTHY_NODES
  healthy_nodes || return 1
  case "$(uname -s)" in
    MINGW*|MSYS*) processes=$(ps -W | awk 'NR > 1 { print $NF }') || return 1 ;;
    *) processes=$(ps -eo comm=) || return 1 ;;
  esac
  if printf '%s\n' "$processes" | grep -E '(^|[/\\])(lab|observer)(\.exe)?$' >&2; then
    echo "stop host-side lab/observer processes before deployment; the coordinator must exclusively control the stand" >&2
    return 1
  fi
}

workload_inventory() {
  kubectl -n "$NAMESPACE" get deployments,replicasets,statefulsets,daemonsets,jobs,cronjobs,replicationcontrollers,horizontalpodautoscalers,pods --show-managed-fields=true \
    -o go-template='{{define "labels"}}{{with .}}{{with index . "app"}}{{.}}{{end}},{{with index . "client"}}{{.}}{{end}},{{with index . "hop"}}{{.}}{{end}}{{end}}{{end}}{{range .items}}{{.kind}}{{"|"}}{{.metadata.name}}{{"|"}}{{.metadata.uid}}{{"|"}}{{with .metadata.labels}}{{with index . "app"}}{{.}}{{end}}{{end}}{{"|"}}{{with .metadata.labels}}{{with index . "client"}}{{.}}{{end}}{{end}}{{"|"}}{{with .metadata.labels}}{{with index . "hop"}}{{.}}{{end}}{{end}}{{"|"}}{{range .metadata.ownerReferences}}{{.kind}},{{.name}},{{.uid}},{{.controller}};{{end}}{{"|"}}{{range .metadata.managedFields}}{{.manager}};{{end}}{{"|"}}{{with .metadata.labels}}{{with index . "app.kubernetes.io/managed-by"}}{{.}}{{end}}{{end}}{{"|"}}{{if .spec.template}}{{template "labels" .spec.selector.matchLabels}}{{"|"}}{{template "labels" .spec.template.metadata.labels}}{{"|"}}{{len .spec.template.spec.containers}}{{range .spec.template.spec.containers}},{{.name}},{{.image}}{{end}}{{"|"}}{{if .spec.template.spec.initContainers}}{{len .spec.template.spec.initContainers}}{{else}}0{{end}}{{else if eq .kind "Pod"}}-|-{{"|"}}{{len .spec.containers}}{{range .spec.containers}},{{.name}},{{.image}}{{end}}{{"|"}}{{if .spec.initContainers}}{{len .spec.initContainers}}{{else}}0{{end}}{{else}}-|-|-|-{{end}}{{"|"}}{{if .metadata.deletionTimestamp}}deleting{{end}}{{"|"}}{{.metadata.resourceVersion}}{{"\n"}}{{end}}'
}

check_inventory() {
  local inventory="$1" phase="${2:-before}" kind resource line name uid app client hop owners managers managed selector template containers init deleting version
  local owner_kind owner_name owner_uid controller extra manager expected selector_expected
  local -A deployments=() replicasets=() classes=() labels=() seen=()
  local lines=() manager_list=()
  mapfile -t lines <<<"$inventory"
  for kind in Deployment ReplicaSet Pod; do
    for line in "${lines[@]}"; do
      [ -n "$line" ] || continue
      IFS='|' read -r resource name uid app client hop owners managers managed selector template containers init deleting version <<<"$line"
      [ "$resource" = "$kind" ] || continue
      [ -n "$uid" ] && [ -z "${seen[$uid]:-}" ] || { echo "invalid or duplicate workload UID: $line" >&2; return 1; }
      seen[$uid]=yes
      [ -z "$deleting" ] || { echo "workload already deleting: $kind/$name" >&2; return 1; }
      [ -z "$managed" ] || { echo "external manager $managed on $kind/$name" >&2; return 1; }
      IFS=';' read -r -a manager_list <<<"$managers"
      for manager in "${manager_list[@]}"; do
        case "$manager" in
          ''|kubectl|kubectl-client-side-apply|kubectl-rollout|kubectl-set|kube-controller-manager|kubelet) ;;
          *) echo "external reconciliation manager $manager on $kind/$name" >&2; return 1 ;;
        esac
      done
      case "$kind" in
        Deployment)
          case "$name" in
            client-a) expected=client; selector_expected=client,a, ;;
            client-b) expected=client; selector_expected=client,b, ;;
            relay-[1-5]) expected=relay; selector_expected="relay,,${name#relay-}" ;;
            *) echo "unexpected Deployment/$name owner=$owners" >&2; return 1 ;;
          esac
          [ -z "$owners" ] && [ "$app,$client,$hop" = "$selector_expected" ] &&
            [ "$selector" = "$selector_expected" ] && [ "$template" = "$selector_expected" ] || {
              echo "conflicting labels, template or owner on Deployment/$name: $line" >&2; return 1;
            }
          [[ "$uid" =~ ^[a-zA-Z0-9-]+$ ]] && [[ "$version" =~ ^[a-zA-Z0-9_.-]+$ ]] || {
            echo "invalid Deployment/$name UID or resourceVersion" >&2; return 1;
          }
          deployments[$uid]="$name"
          classes[$uid]="$expected"
          labels[$uid]="$selector_expected"
          ;;
        ReplicaSet|Pod)
          IFS=',' read -r owner_kind owner_name owner_uid controller extra <<<"${owners%;}"
          [ "$controller" = true ] && [ -z "$extra" ] && [[ "$owners" != *';'*';'* ]] || {
            echo "unmanaged $kind/$name owner=$owners" >&2; return 1;
          }
          if [ "$kind" = ReplicaSet ]; then
            [ "$owner_kind" = Deployment ] && [ "${deployments[$owner_uid]:-}" = "$owner_name" ] || {
              echo "orphaned ReplicaSet/$name owner=$owners" >&2; return 1;
            }
            expected="${classes[$owner_uid]}"
            selector_expected="${labels[$owner_uid]}"
            [ "$selector" = "$selector_expected" ] && [ "$template" = "$selector_expected" ] || {
              echo "conflicting template on ReplicaSet/$name: $line" >&2; return 1;
            }
            replicasets[$uid]="$name"
            classes[$uid]="$expected"
            labels[$uid]="$selector_expected"
          else
            [ "$owner_kind" = ReplicaSet ] && [ "${replicasets[$owner_uid]:-}" = "$owner_name" ] || {
              echo "unmanaged Pod/$name owner=$owners" >&2; return 1;
            }
            expected="${classes[$owner_uid]}"
            selector_expected="${labels[$owner_uid]}"
          fi
          [ "$app,$client,$hop" = "$selector_expected" ] || { echo "conflicting labels on $kind/$name: $line" >&2; return 1; }
          ;;
      esac
      [ "$containers" = "1,$expected,jimichi/$expected:dev" ] && [ "$init" = 0 ] || {
        echo "unexpected containers on $kind/$name: $containers init=$init" >&2; return 1;
      }
      if [ "$phase" = clients-stopped ] && [ "$expected" = client ]; then
        echo "client workload remains after deletion: $kind/$name uid=$uid" >&2; return 1
      fi
    done
  done
  for line in "${lines[@]}"; do
    [ -n "$line" ] || continue
    case "$line" in
      Deployment'|'*|ReplicaSet'|'*|Pod'|'*) ;;
      *) echo "unexpected workload/controller: $line" >&2; return 1 ;;
    esac
  done
}

wait_old_pods() {
  local inventory="$1" class="$2" kind name uid app rest
  local pods=()
  while IFS='|' read -r kind name uid app rest; do
    if [ "$kind" = Pod ] && [ "$app" = "$class" ]; then pods+=("pod/$name"); fi
  done <<<"$inventory"
  if [ "${#pods[@]}" -ne 0 ]; then
    kubectl -n "$NAMESPACE" wait --for=delete "${pods[@]}" --timeout=180s || return 1
  fi
}

unchanged_workload_uids() {
  local before="$1" after="$2" kind name uid rest
  local -A old=()
  while IFS='|' read -r kind name uid rest; do
    [ -n "$kind" ] || continue
    old[$kind/$name]="$uid"
  done <<<"$before"
  while IFS='|' read -r kind name uid rest; do
    [ -n "$kind" ] || continue
    [ "${old[$kind/$name]:-}" = "$uid" ] || {
      echo "workload appeared during deployment barrier: $kind/$name uid=$uid" >&2; return 1;
    }
  done <<<"$after"
}

delete_captured_deployments() {
  local inventory="$1" class="$2" kind name uid app client hop owners managers managed selector template containers init deleting version
  while IFS='|' read -r kind name uid app client hop owners managers managed selector template containers init deleting version; do
    [ "$kind" = Deployment ] && [ "$app" = "$class" ] || continue
    # raw deletion carries UID/version preconditions; ordinary delete does not
    printf '{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"%s","resourceVersion":"%s"},"propagationPolicy":"Foreground"}\n' "$uid" "$version" |
      kubectl -n "$NAMESPACE" delete --raw "/apis/apps/v1/namespaces/$NAMESPACE/deployments/$name" \
        -f - --request-timeout=180s >/dev/null || return 1
    kubectl -n "$NAMESPACE" wait --for=delete "deployment/$name" --timeout=180s || return 1
  done <<<"$inventory"
}

deployment_barrier() {
  local namespace inventory remaining line
  deployment_context || return 1
  namespace=$(kubectl get namespace "$NAMESPACE" --ignore-not-found -o name) || return 1
  if [ -z "$namespace" ]; then
    echo "deployment barrier complete: namespace $NAMESPACE absent"
    return 0
  fi
  inventory=$(workload_inventory) || return 1
  check_inventory "$inventory" || return 1
  while IFS= read -r line; do
    case "$line" in Pod'|'*) printf 'barrier old %s\n' "$line" ;; esac
  done <<<"$inventory"
  delete_captured_deployments "$inventory" client || return 1
  wait_old_pods "$inventory" client || return 1
  healthy_nodes || return 1
  remaining=$(workload_inventory) || return 1
  check_inventory "$remaining" clients-stopped || return 1
  unchanged_workload_uids "$inventory" "$remaining" || return 1
  delete_captured_deployments "$inventory" relay || return 1
  wait_old_pods "$inventory" relay || return 1
  healthy_nodes || return 1
  remaining=$(workload_inventory) || return 1
  if [ -n "$remaining" ]; then
    echo "workload appeared or remained during deployment barrier: $remaining" >&2
    return 1
  fi
  echo "deployment barrier complete: old Pod UIDs and all workload controllers gone"
}

assert_suite_pods() {
  local class="$1" count="$2" config pods pod row logs state name args source extra i flags
  local arguments=()
  config=$(kubectl -n "$NAMESPACE" get configmap jimichi-config -o jsonpath='{.data.suite}') || return 1
  [ "$config" = "$SUITE" ] || { echo "suite ConfigMap=$config, want $SUITE" >&2; return 1; }
  pods=$(kubectl -n "$NAMESPACE" get pods -l "app=$class" -o go-template='{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}') || return 1
  [ "$(printf '%s\n' "$pods" | awk 'NF { n++ } END { print n+0 }')" -eq "$count" ] || {
    echo "want exactly $count current $class Pods: $pods" >&2; return 1;
  }
  for pod in $pods; do
    row=$(kubectl -n "$NAMESPACE" get pod "$pod" -o go-template='{{if .metadata.deletionTimestamp}}deleting{{end}}{{len .spec.containers}}{{range .spec.containers}}{{"|"}}{{.name}}{{"|"}}{{range .args}}{{.}}{{";"}}{{end}}{{"|"}}{{range .env}}{{if eq .name "JIMICHI_SUITE"}}{{.valueFrom.configMapKeyRef.name}}{{"/"}}{{.valueFrom.configMapKeyRef.key}}{{end}}{{end}}{{end}}') || return 1
    IFS='|' read -r state name args source extra <<<"$row"
    IFS=';' read -r -a arguments <<<"$args"
    flags=0
    for ((i=0; i<${#arguments[@]}; i++)); do
      if [ "${arguments[$i]}" = -suite ]; then
        [ "${arguments[$((i+1))]:-}" = '$(JIMICHI_SUITE)' ] || { echo "Pod/$pod has a conflicting suite flag" >&2; return 1; }
        flags=$((flags + 1))
      fi
      [[ "${arguments[$i]}" != -suite=* ]] || { echo "Pod/$pod has a conflicting suite flag" >&2; return 1; }
    done
    [ "$state" = 1 ] && [ "$name" = "$class" ] && [ "$flags" -eq 1 ] &&
      [ "$source" = jimichi-config/suite ] && [ -z "$extra" ] || {
        echo "Pod/$pod lacks the explicit ConfigMap suite argument: $row" >&2; return 1;
      }
    if [ "$class" = relay ]; then
      logs=$(kubectl -n "$NAMESPACE" logs "pod/$pod" -c relay) || return 1
      printf '%s\n' "$logs" | grep -E "relay listening on .* suite=$SUITE," >/dev/null || {
        echo "Pod/$pod startup log does not identify suite=$SUITE" >&2; return 1;
      }
    fi
  done
  echo "suite $SUITE: $count $class Pods use explicit ConfigMap arguments"
}

assert_suite_anchor() {
  local anchor
  anchor=$(kubectl -n "$NAMESPACE" get configmap jimichi-ca -o jsonpath='{.data.anchor}') || return 1
  [[ "$anchor" = "$SUITE:"* ]] || { echo "CA anchor does not identify suite=$SUITE" >&2; return 1; }
  echo "suite $SUITE: fresh CA and every enrollment-verified descriptor agree"
}
