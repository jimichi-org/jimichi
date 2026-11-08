package scripts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
)

func TestWorkloadInventoryTemplateHandlesOptionalFields(t *testing.T) {
	raw, err := os.ReadFile(script(t, "deploy.sh"))
	if err != nil {
		t.Fatal(err)
	}
	const marker = "-o go-template='{{define"
	start := strings.Index(string(raw), marker)
	if start < 0 {
		t.Fatal("no inventory template")
	}
	text := string(raw)[start+len("-o go-template='"):]
	text = text[:strings.IndexByte(text, '\'')]
	parsed, err := template.New("inventory").Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	var values any
	if err := json.Unmarshal([]byte(`{"items":[
{"kind":"Pod","metadata":{"name":"unmanaged","uid":"u","resourceVersion":"1"},"spec":{"containers":[{"name":"probe","image":"busybox"}]}},
{"kind":"Deployment","metadata":{"name":"relay-1","uid":"d","resourceVersion":"2","labels":{"app":"relay","hop":"1"}},"spec":{"selector":{"matchLabels":{"app":"relay","hop":"1"}},"template":{"metadata":{"labels":{"app":"relay","hop":"1"}},"spec":{"containers":[{"name":"relay","image":"jimichi/relay:dev"}]}}}},
{"kind":"CronJob","metadata":{"name":"other","uid":"c","resourceVersion":"3"},"spec":{}}
]}`), &values); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := parsed.Execute(&out, values); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<no value>") || !strings.Contains(out.String(), "relay,,1|relay,,1|1,relay,jimichi/relay:dev|0|") || strings.Count(out.String(), "\n") != 3 {
		t.Fatalf("unexpected inventory serialization: %s", out.String())
	}
}

const barrierKubectl = `#!/usr/bin/env bash
echo "$*" >>"$KUBECTL_CALLS"
case "$*" in
  *"config current-context"*) echo "${CONTEXT:-kind-jimichi}" ;;
  *"config view --minify"*) echo "${SERVER:-https://127.0.0.1:16443}" ;;
  *"get nodes"*)
    if [ "${NODE_CHANGED:-}" = yes ] && [ "$(cat "$STAND/stage")" != before ]; then exit 0; fi
    echo "jimichi-control-plane||${NODE_STATUS:-True}" ;;
  *"get namespace"*)
    [ "${NAMESPACE_ERROR:-}" != yes ] || exit 1
    [ "${NAMESPACE_ABSENT:-}" = yes ] || echo namespace/jimichi ;;
  *"get deployments,replicasets,"*) cat "$STAND/$(cat "$STAND/stage")" ;;
  *"delete --raw "*)
    args="$*"; path="${args#*delete --raw }"; path="${path%% *}"; name="${path##*/}"
    body=$(cat)
    echo "delete-options $name $body" >>"$KUBECTL_CALLS"
    case "$body" in *'"uid":"d-'"$name"'","resourceVersion":"100"'*'"propagationPolicy":"Foreground"'*) ;; *) exit 2 ;; esac
    if [ "${REPLACE_ON_DELETE:-}" = "$name" ]; then
      echo "retained replacement $name" >>"$KUBECTL_CALLS"
      echo 'Error from server (Conflict): precondition failed' >&2
      exit 1
    fi
    if [ "${VERSION_ON_DELETE:-}" = "$name" ]; then
      echo "retained changed-version $name" >>"$KUBECTL_CALLS"
      echo 'Error from server (Conflict): resourceVersion precondition failed' >&2
      exit 1
    fi
    [ "${DELETE_ERROR:-}" != yes ] || exit 1
    if [ -n "${APPEAR_ON_DELETE:-}" ] && [ "$name" = client-a ]; then
      printf '%s\n' "$APPEAR_ON_DELETE" >>"$STAND/clients"
      echo 'retained appeared client-b' >>"$KUBECTL_CALLS"
    fi
    echo "deleted captured d-$name" >>"$KUBECTL_CALLS"
    case "$name" in client-*) echo clients >"$STAND/stage" ;; relay-*) echo empty >"$STAND/stage" ;; esac ;;
  *"wait --for=delete"*) [ "${WAIT_ERROR:-}" != yes ] ;;
  *) echo "unexpected kubectl: $*" >&2; exit 2 ;;
esac
`

const suiteKubectl = `#!/usr/bin/env bash
case "$*" in
  *"get configmap jimichi-config"*) echo "${CONFIG_SUITE:-$SUITE}" ;;
  *"get configmap jimichi-ca"*) echo "${ANCHOR_SUITE:-$SUITE}:public-anchor" ;;
  *"get pods -l app="*)
    class=relay; count=5
    case "$*" in *app=client*) class=client; count=2 ;; esac
    for i in $(seq 1 "${POD_COUNT:-$count}"); do echo "$class-$i"; done ;;
  *"get pod "*)
    class=relay
    case "$*" in *"get pod client-"*) class=client ;; esac
    printf '%s|%s|-suite;%s;%s|%s\n' "${CONTAINERS:-1}" "$class" '$(JIMICHI_SUITE)' "${EXTRA_ARGS:-}" "${ENV_SOURCE:-jimichi-config/suite}" ;;
  *"logs pod/relay-"*) echo "2026/11/08 12:00:00 relay listening on :9000, info on :9100, suite=${LOG_SUITE:-$SUITE}, keymem=offheap" ;;
  *) echo "unexpected kubectl: $*" >&2; exit 2 ;;
esac
`

func TestSuiteEvidenceChecksEveryPodAndFreshAnchor(t *testing.T) {
	for _, c := range []struct {
		name, why string
		env       []string
	}{
		{"c25519", "", nil},
		{"gost", "", []string{"SUITE=gost"}},
		{"wrong config", "suite ConfigMap", []string{"CONFIG_SUITE=gost"}},
		{"wrong anchor", "CA anchor", []string{"ANCHOR_SUITE=gost"}},
		{"wrong startup suite", "startup log", []string{"LOG_SUITE=gost"}},
		{"missing pod", "exactly 5", []string{"POD_COUNT=4"}},
		{"extra container", "explicit ConfigMap suite", []string{"CONTAINERS=2"}},
		{"wrong source", "explicit ConfigMap suite", []string{"ENV_SOURCE=other/suite"}},
		{"duplicate suite", "conflicting suite flag", []string{"EXTRA_ARGS=-suite;gost;"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(suiteKubectl), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bash(t), "-c", `. "$1"; . "$2"; assert_suite_pods relay 5 && assert_suite_pods client 2 && assert_suite_anchor`, "bash", script(t, "lib.sh"), script(t, "deploy.sh"))
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "SUITE=c25519", "JIMICHI_CONTEXT=")
			cmd.Env = append(cmd.Env, c.env...)
			output, err := cmd.CombinedOutput()
			if c.why == "" {
				if err != nil || !strings.Contains(string(output), "enrollment-verified descriptor") {
					t.Fatalf("%v: %s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), c.why) {
				t.Fatalf("%v, want %s: %s", err, c.why, output)
			}
		})
	}
}

func baseInventory() (all, relays string) {
	for _, name := range []string{"client-a", "client-b", "relay-1", "relay-2", "relay-3", "relay-4", "relay-5"} {
		app, client, hop := "relay", "", strings.TrimPrefix(name, "relay-")
		if strings.HasPrefix(name, "client-") {
			app, client, hop = "client", strings.TrimPrefix(name, "client-"), ""
		}
		labels := strings.Join([]string{app, client, hop}, ",")
		fields := strings.Join([]string{app, client, hop}, "|")
		containers := "1," + app + ",jimichi/" + app + ":dev"
		rows := fmt.Sprintf("Deployment|%s|d-%s|%s||kubectl-client-side-apply;||%s|%s|%s|0||100\n", name, name, fields, labels, labels, containers)
		rows += fmt.Sprintf("ReplicaSet|%s-rs|r-%s|%s|Deployment,%s,d-%s,true;|kube-controller-manager;||%s|%s|%s|0||100\n", name, name, fields, name, name, labels, labels, containers)
		rows += fmt.Sprintf("Pod|%s-pod|p-%s|%s|ReplicaSet,%s-rs,r-%s,true;|kubelet;||-|-|%s|0||100\n", name, name, fields, name, name, containers)
		all += rows
		if app == "relay" {
			relays += rows
		}
	}
	return all, relays
}

func runBarrier(t *testing.T, before, clients, empty string, env ...string) (int, string, string) {
	t.Helper()
	shell := bash(t)
	bin, stand := t.TempDir(), t.TempDir()
	for name, value := range map[string]string{"kubectl": barrierKubectl, "ps": "#!/usr/bin/env bash\necho COMMAND\necho \"${HOST_PROCESS:-bash}\"\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(value), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range map[string]string{"before": before, "clients": clients, "empty": empty, "stage": "before"} {
		if err := os.WriteFile(filepath.Join(stand, name), []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(stand, "calls")
	cmd := exec.Command(shell, "-c", `. "$1"; . "$2"; deployment_barrier`, "bash", script(t, "lib.sh"), script(t, "deploy.sh"))
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "STAND="+filepath.ToSlash(stand), "KUBECTL_CALLS="+filepath.ToSlash(log), "SUITE=c25519", "NAMESPACE=jimichi", "CLUSTER=jimichi", "JIMICHI_CONTEXT=")
	cmd.Env = append(cmd.Env, env...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(log)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), output.String(), string(calls)
}

func TestDeploymentBarrierStopsOwnedClientsBeforeRelays(t *testing.T) {
	before, relays := baseInventory()
	status, out, calls := runBarrier(t, before, relays, "")
	if status != 0 || !strings.Contains(out, "deployment barrier complete: old Pod UIDs") {
		t.Fatalf("status %d, output %s", status, out)
	}
	client := strings.Index(calls, "delete --raw /apis/apps/v1/namespaces/jimichi/deployments/client-a -f - --request-timeout=180s")
	clientWait := strings.Index(calls, "wait --for=delete pod/client-a-pod pod/client-b-pod --timeout=180s")
	relay := strings.Index(calls, "delete --raw /apis/apps/v1/namespaces/jimichi/deployments/relay-1 -f - --request-timeout=180s")
	if client < 0 || clientWait < client || relay < clientWait {
		t.Fatalf("wrong stop order or deletion scope:\n%s", calls)
	}
	for _, unsafe := range []string{"--all", "--force", "--grace-period=0", "delete namespace", "-n jimichi delete pod"} {
		if strings.Contains(calls, unsafe) {
			t.Errorf("unsafe %q in calls:\n%s", unsafe, calls)
		}
	}
	if !strings.Contains(calls, "--context kind-jimichi -n jimichi delete") {
		t.Fatal("mutations did not pin the validated context")
	}
	if strings.Count(calls, "delete-options ") != 7 || strings.Count(calls, `"resourceVersion":"100"`) != 7 || strings.Count(calls, `"propagationPolicy":"Foreground"`) != 7 {
		t.Fatalf("missing atomic UID/version/foreground DeleteOptions: %s", calls)
	}
}

func TestDeploymentBarrierPreflightRefusesWithoutMutation(t *testing.T) {
	before, relays := baseInventory()
	for _, c := range []struct {
		name, inventory, why string
		env                  []string
	}{
		{"unknown suite", before, "unsupported SUITE", []string{"SUITE=rsa"}},
		{"wrong namespace", before, "requires NAMESPACE=jimichi", []string{"NAMESPACE=other"}},
		{"wrong context", before, "want kind-jimichi", []string{"CONTEXT=production"}},
		{"remote API", before, "must use loopback", []string{"SERVER=https://example.com:443"}},
		{"unhealthy node", before, "healthy, schedulable nodes", []string{"NODE_STATUS=False"}},
		{"host lab", before, "stop host-side lab/observer", []string{"HOST_PROCESS=/stand/lab.exe"}},
		{"namespace read failure", before, "", []string{"NAMESPACE_ERROR=yes"}},
		{"unexpected deployment", strings.ReplaceAll(before, "relay-5", "other-5"), "unexpected Deployment/other-5", nil},
		{"wrong deployment label", strings.Replace(before, "client|a|", "client|wrong|", 1), "conflicting labels", nil},
		{"wrong pod label", strings.Replace(before, "p-client-a|client|a|", "p-client-a|client|b|", 1), "conflicting labels on Pod", nil},
		{"wrong image", strings.Replace(before, "jimichi/client:dev", "foreign/client:dev", 1), "unexpected containers", nil},
		{"orphan ReplicaSet", strings.Replace(before, "Deployment,client-a,d-client-a,true;", "Deployment,client-a,foreign,true;", 1), "orphaned ReplicaSet", nil},
		{"unmanaged pod", before + "Pod|probe|probe|probe||||||-|-|1,probe,busybox|0|\n", "unmanaged Pod/probe", nil},
		{"job", before + "Job|lab|job|||||||||-|-|\n", "unexpected workload/controller", nil},
		{"HPA", before + "HorizontalPodAutoscaler|scale|hpa|||||||||-|-|\n", "unexpected workload/controller", nil},
		{"external manager", strings.Replace(before, "kubectl-client-side-apply;", "argocd-controller;", 1), "external reconciliation manager", nil},
		{"external owner", strings.Replace(before, "client|a|||", "client|a||Operator,stand,operator,true;|", 1), "conflicting labels", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			status, out, calls := runBarrier(t, c.inventory, relays, "", c.env...)
			if status == 0 || !strings.Contains(out, c.why) || strings.Contains(calls, " delete ") {
				t.Fatalf("status %d, want refusal %q; output %s; calls:\n%s", status, c.why, out, calls)
			}
		})
	}
}

func TestDeploymentBarrierHandlesAbsentNamespaceAndDeletionFailures(t *testing.T) {
	before, relays := baseInventory()
	status, out, calls := runBarrier(t, "", "", "", "NAMESPACE_ABSENT=yes")
	if status != 0 || !strings.Contains(out, "namespace jimichi absent") || strings.Contains(calls, " delete ") {
		t.Fatalf("absent namespace: status %d, output %s; calls %s", status, out, calls)
	}
	for _, env := range []string{"DELETE_ERROR=yes", "WAIT_ERROR=yes", "NODE_CHANGED=yes"} {
		status, out, calls := runBarrier(t, before, relays, "", env)
		if status == 0 || strings.Contains(calls, "/deployments/relay-") || strings.Contains(out, "barrier complete") {
			t.Fatalf("%s: status %d, output %s; calls %s", env, status, out, calls)
		}
	}
	for _, c := range []struct{ clients, empty string }{{before, ""}, {strings.Replace(relays, "p-relay-1|", "new-relay-1|", 1), ""}, {relays, "Pod|new|new\n"}} {
		status, out, _ := runBarrier(t, before, c.clients, c.empty)
		if status == 0 || strings.Contains(out, "barrier complete") {
			t.Fatalf("recreated workload: status %d, output %s", status, out)
		}
	}
}

func TestDeploymentBarrierAllowsMissingDeploymentsAndOldReplicaSets(t *testing.T) {
	before, relays := baseInventory()
	old := "ReplicaSet|relay-1-old|old-relay-1|relay||1|Deployment,relay-1,d-relay-1,true;|kube-controller-manager;||relay,,1|relay,,1|1,relay,jimichi/relay:dev|0|\n"
	for _, c := range []struct{ before, clients string }{{"", ""}, {relays, relays}, {before + old, relays + old}} {
		status, out, _ := runBarrier(t, c.before, c.clients, "")
		if status != 0 || !strings.Contains(out, "barrier complete") {
			t.Fatalf("status %d: %s", status, out)
		}
	}
}

func TestDeploymentBarrierKeepsImmediateReplacementAndNewDeployment(t *testing.T) {
	before, relays := baseInventory()
	for _, name := range []string{"client-a", "relay-1"} {
		status, out, calls := runBarrier(t, before, relays, "", "REPLACE_ON_DELETE="+name)
		if status == 0 || !strings.Contains(out, "precondition failed") || !strings.Contains(calls, "retained replacement "+name) || strings.Contains(calls, "deleted captured d-"+name) {
			t.Fatalf("%s replaced immediately before DELETE: status %d, output %s; calls %s", name, status, out, calls)
		}
	}
	status, out, calls := runBarrier(t, before, relays, "", "VERSION_ON_DELETE=client-a")
	if status == 0 || !strings.Contains(out, "resourceVersion precondition failed") || !strings.Contains(calls, "retained changed-version client-a") || strings.Contains(calls, "deleted captured d-client-a") {
		t.Fatalf("same UID modified immediately before DELETE: status %d, output %s; calls %s", status, out, calls)
	}
	missing, appeared := "", ""
	for _, line := range strings.Split(before, "\n") {
		if strings.Contains(line, "client-b") {
			if strings.HasPrefix(line, "Deployment|") {
				appeared = strings.Replace(line, "d-client-b|", "new-client-b|", 1)
			}
			continue
		}
		missing += line + "\n"
	}
	status, out, calls = runBarrier(t, missing, relays, "", "APPEAR_ON_DELETE="+appeared)
	if status == 0 || !strings.Contains(out, "client workload remains") || !strings.Contains(calls, "retained appeared client-b") || strings.Contains(calls, "/deployments/client-b") || strings.Contains(calls, "/deployments/relay-") {
		t.Fatalf("originally missing Deployment appeared immediately before DELETE: status %d, output %s; calls %s", status, out, calls)
	}
}

func TestKubectlRawDeleteCarriesAtomicPreconditions(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("no kubectl for the isolated HTTP transport test")
	}
	const uri = "/apis/apps/v1/namespaces/jimichi/deployments/client-a"
	const options = `{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"captured-uid","resourceVersion":"100"},"propagationPolicy":"Foreground"}`
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.Method != http.MethodDelete || r.URL.Path != uri {
			t.Errorf("unexpected request method/path/body read: %s %s %v", r.Method, r.URL.Path, err)
		}
		requests <- string(body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"kind":"Status","apiVersion":"v1","status":"Success","code":200}`)
	}))
	defer server.Close()
	config := filepath.Join(t.TempDir(), "config")
	text := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: isolated\n  cluster:\n    server: %s\ncontexts:\n- name: isolated\n  context:\n    cluster: isolated\n    user: isolated\ncurrent-context: isolated\nusers:\n- name: isolated\n  user: {}\n", server.URL)
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(kubectl, "--kubeconfig", config, "--context", "isolated", "delete", "--raw", uri, "-f", "-", "--request-timeout=5s")
	cmd.Stdin = strings.NewReader(options)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated raw DELETE: %v: %s", err, output)
	}
	if got := <-requests; got != options {
		t.Fatalf("kubectl altered DeleteOptions: %s", got)
	}
}
