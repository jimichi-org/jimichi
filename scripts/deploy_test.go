package scripts

import (
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// one document of a manifest file
type manifest struct {
	kind, name, text string
}

var (
	docSplit    = regexp.MustCompile(`(?m)^---\s*$`)
	kindLine    = regexp.MustCompile(`(?m)^kind:\s*(\S+)\s*$`)
	nameLine    = regexp.MustCompile(`(?m)^  name:\s*(\S+)\s*$`)
	argsLine    = regexp.MustCompile(`(?m)^\s+args:[ \t]*`)
	argItem     = regexp.MustCompile(`^\s+- (.*)$`)
	recreate    = regexp.MustCompile(`strategy:\s*(\{\s*type:\s*Recreate\s*\}|\n\s+type:\s*Recreate\b)`)
	ipcLock     = regexp.MustCompile(`add:\s*\[\s*"?IPC_LOCK"?\s*\]`)
	dropAll     = regexp.MustCompile(`drop:\s*\[\s*"?ALL"?\s*\]`)
	mailboxFlag = regexp.MustCompile(`(?m)^MAILBOX_RELAY="\$\{MAILBOX_RELAY:-(\S+)\}"$`)
)

func manifests(t *testing.T, name string) map[string]manifest {
	t.Helper()
	return manifestsIn(t, "base", name)
}

func manifestsIn(t *testing.T, dir, name string) map[string]manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "deploy", dir, name))
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]manifest)
	for _, doc := range docSplit.Split(string(raw), -1) {
		kind, named := kindLine.FindStringSubmatch(doc), nameLine.FindStringSubmatch(doc)
		if kind == nil || named == nil {
			continue
		}
		out[kind[1]+"/"+named[1]] = manifest{kind: kind[1], name: named[1], text: doc}
	}
	return out
}

// the arguments of the one container, in the flow form ["-a", "b"] or as a
// block list of quoted items
func argsOf(t *testing.T, m manifest) []string {
	t.Helper()
	loc := argsLine.FindStringIndex(m.text)
	if loc == nil {
		t.Fatalf("%s: no args", m.name)
	}
	rest := m.text[loc[1]:]
	var args []string
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		for _, item := range strings.Split(rest[1:end], ",") {
			args = append(args, strings.Trim(strings.TrimSpace(item), `"`))
		}
		return args
	}
	for _, line := range strings.Split(rest, "\n")[1:] {
		item := argItem.FindStringSubmatch(line)
		if item == nil {
			break
		}
		args = append(args, strings.Trim(item[1], `"`))
	}
	return args
}

// the value after a flag, or "" when the flag is absent
func flagValue(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

// what every pod of the testbed keeps: a new pod for every rollout, key pages
// it can lock and nothing else of the capabilities, a read-only root and no
// volume to write a key to
func hardened(t *testing.T, m manifest) {
	t.Helper()
	confined(t, m, append(confinement(m), want{"no volume", !strings.Contains(m.text, "volumes:") && !strings.Contains(m.text, "volumeMounts:")}))
}

type want struct {
	what string
	ok   bool
}

// what hardened asks of a pod besides having no volume
func confinement(m manifest) []want {
	return []want{
		{"strategy Recreate", recreate.MatchString(m.text)},
		{"IPC_LOCK added", ipcLock.MatchString(m.text)},
		{"every other capability dropped", dropAll.MatchString(m.text)},
		{"a read-only root", strings.Contains(m.text, "readOnlyRootFilesystem: true")},
		{"no privilege escalation", strings.Contains(m.text, "allowPrivilegeEscalation: false")},
		{"a user other than root", strings.Contains(m.text, "runAsNonRoot: true")},
	}
}

func confined(t *testing.T, m manifest, wants []want) {
	t.Helper()
	for _, c := range wants {
		if !c.ok {
			t.Errorf("%s: want %s", m.name, c.what)
		}
	}
}

func explicitSuite(t *testing.T, m manifest) {
	t.Helper()
	if got := flagValue(argsOf(t, m), "-suite"); got != "$(JIMICHI_SUITE)" {
		t.Errorf("%s: -suite %q, want ConfigMap environment reference", m.name, got)
	}
	if !regexp.MustCompile(`name: JIMICHI_SUITE\s+valueFrom:\s+configMapKeyRef: \{name: jimichi-config, key: suite\}`).MatchString(m.text) {
		t.Errorf("%s: no jimichi-config/suite environment source", m.name)
	}
}

// the two clients of the conversation: each its own deployment, selected by
// its own label besides app=client, which the network policy admits to the
// cell ports, with no port of its own and the arguments of -peer through the
// mailbox the e2e checks read
func TestClientManifestsKeepTheConversation(t *testing.T) {
	all := manifests(t, "client.yaml")
	checks, err := os.ReadFile(script(t, "checks.sh"))
	if err != nil {
		t.Fatal(err)
	}
	relay := mailboxFlag.FindSubmatch(checks)
	if relay == nil {
		t.Fatal("checks.sh names no default MAILBOX_RELAY")
	}
	mailbox := string(relay[1]) + ".jimichi.svc.cluster.local:9000"
	for _, c := range []struct {
		name  string
		label string
		args  map[string]string
		flags []string
	}{
		{"client-a", "a", map[string]string{"-count": "0", "-interval": "2s"}, nil},
		{"client-b", "b", map[string]string{"-interval": "0"}, []string{"-respond"}},
	} {
		m, ok := all["Deployment/"+c.name]
		if !ok {
			t.Fatalf("no deployment %s", c.name)
		}
		hardened(t, m)
		explicitSuite(t, m)
		labels := "{app: client, client: " + c.label + "}"
		if strings.Count(m.text, labels) != 3 || !strings.Contains(m.text, "matchLabels: "+labels) {
			t.Errorf("%s: want the labels and the selector %s", c.name, labels)
		}
		if strings.Contains(m.text, "ports:") {
			t.Errorf("%s: the admin port is reached only through a port-forward, want no ports", c.name)
		}
		args := argsOf(t, m)
		for flag, want := range map[string]string{
			"-ca": "$(JIMICHI_CA)", "-hops": "3", "-mode": "fixed", "-rate": "200ms", "-mailbox": mailbox,
		} {
			if got := flagValue(args, flag); got != want {
				t.Errorf("%s: %s %q, want %q", c.name, flag, got, want)
			}
		}
		for flag, want := range c.args {
			if got := flagValue(args, flag); got != want {
				t.Errorf("%s: %s %q, want %q", c.name, flag, got, want)
			}
		}
		for _, flag := range append([]string{"-peer"}, c.flags...) {
			if !slices.Contains(args, flag) {
				t.Errorf("%s: no %s in %q", c.name, flag, args)
			}
		}
		if nodes := strings.Split(flagValue(args, "-nodes"), ","); len(nodes) != 5 || nodes[4] != mailbox {
			t.Errorf("%s: -nodes %q, want five relays ending on the mailbox", c.name, nodes)
		}
	}
}

// every relay keeps a mailbox at the exit, so a client could end its chain on
// any of them; the e2e checks read the mailbox counters of each
func TestRelayManifestsRunTheMailbox(t *testing.T) {
	relays := 0
	for _, m := range manifests(t, "relay.yaml") {
		if m.kind != "Deployment" {
			continue
		}
		relays++
		hardened(t, m)
		explicitSuite(t, m)
		if got := flagValue(argsOf(t, m), "-exit"); got != "mailbox" {
			t.Errorf("%s: -exit %q, want mailbox", m.name, got)
		}
	}
	if relays != 5 {
		t.Fatalf("%d relay deployments, want five", relays)
	}
}

var (
	apiAddress = regexp.MustCompile(`(?m)^  apiServerAddress:\s*(\S+)\s*$`)
	apiPort    = regexp.MustCompile(`(?m)^  apiServerPort:\s*(\d+)\s*$`)
)

// certificate issuance trusts the path through the kube API, so the testbed
// keeps it on loopback, and on a port below the dynamic range 49152-65535,
// whose blocks Windows reserves after a restart
func TestKindClusterKeepsTheAPIServerOnLoopback(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "kind", "cluster.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	addr, port := apiAddress.FindSubmatch(raw), apiPort.FindSubmatch(raw)
	if addr == nil || port == nil {
		t.Fatal("cluster.yaml does not set networking.apiServerAddress and apiServerPort")
	}
	if ip, err := netip.ParseAddr(string(addr[1])); err != nil || !ip.IsLoopback() {
		t.Errorf("apiServerAddress %s, want a loopback address", addr[1])
	}
	if p, err := strconv.Atoi(string(port[1])); err != nil || p < 1024 || p >= 49152 {
		t.Errorf("apiServerPort %s, want 1024 to 49151", port[1])
	}
}

func TestUpOrdersBuildBeforeCommonDeploymentWithoutPreload(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join("..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	up := regexp.MustCompile(`(?m)^up:\n((?:\t[^\n]*\n)+)`).FindStringSubmatch(strings.ReplaceAll(string(makefile), "\r\n", "\n"))
	if up == nil {
		t.Fatal("up has no explicitly sequenced recipe")
	}
	if got := strings.TrimSpace(up[1]); got != "$(MAKE) kind-up\n\t$(MAKE) images\n\t$(MAKE) deploy" {
		t.Fatalf("up must sequence kind-up, image build and shared deployment: %s", got)
	}
	e2e, err := os.ReadFile(script(t, "e2e.sh"))
	if err != nil {
		t.Fatal(err)
	}
	e2eText := strings.ReplaceAll(string(e2e), "\r\n", "\n")
	load := "kind load docker-image jimichi/relay:dev jimichi/client:dev"
	barrier := strings.Index(e2eText, "\ndeployment_barrier\n")
	if barrier < 0 || strings.Count(e2eText, load) != 1 || strings.Index(e2eText, load) < barrier {
		t.Fatal("common deployment must load selected images once after its barrier")
	}
	makeCommand, err := exec.LookPath("make")
	if err != nil {
		t.Log("make unavailable; recipe ordering and common load count checked directly")
		return
	}
	cmd := exec.Command(makeCommand, "--no-print-directory", "-n", "-j", "up")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make dry run: %v: %s", err, output)
	}
	text := string(output)
	cluster, build, deploy := strings.Index(text, "kind create cluster"), strings.Index(text, "docker build"), strings.Index(text, "bash scripts/e2e.sh")
	if cluster < 0 || build <= cluster || deploy <= build || strings.Count(text, "docker build") != 2 || strings.Count(text, "bash scripts/e2e.sh") != 1 || strings.Contains(text, "kind load") {
		t.Fatalf("unexpected up dry run ordering or count: %s", text)
	}
}

// a document without the comment lines that open it, with LF line ends
func body(text string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for len(lines) > 0 && (strings.TrimSpace(lines[0]) == "" || strings.HasPrefix(lines[0], "#")) {
		lines = lines[1:]
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// the client of deploy/base as deploy/vault must hold it: these lines and only
// these differ, each at its place
func withVault(t *testing.T, base, claim string) string {
	t.Helper()
	var out []string
	inserted := map[string]int{}
	lines := strings.Split(base, "\n")
	for i, line := range lines {
		if line == "            limits: {cpu: 500m, memory: 128Mi}" {
			out = append(out, "            limits: {cpu: 500m, memory: 256Mi}",
				"      volumes:", "        - name: vault", "          persistentVolumeClaim: {claimName: "+claim+"}")
			inserted["volumes"]++
			continue
		}
		out = append(out, line)
		switch {
		case line == "        runAsGroup: 65532":
			out = append(out, "        fsGroup: 65532")
			inserted["fsGroup"]++
		case i+1 < len(lines) && strings.HasPrefix(line, "            - ") && lines[i+1] == "          securityContext:":
			out = append(out, `            - "-vault"`, `            - "/vault/peer.vault"`,
				"          volumeMounts:", "            - {name: vault, mountPath: /vault}")
			inserted["args"]++
		}
	}
	for _, what := range []string{"fsGroup", "args", "volumes"} {
		if inserted[what] != 1 {
			t.Fatalf("%s: the place of %s found %d times in deploy/base, want once", claim, what, inserted[what])
		}
	}
	return strings.Join(out, "\n")
}

// deploy/vault is deploy/base byte for byte except for the volume, its mount,
// -vault, fsGroup and the memory the stretch of a password takes
func TestVaultOverlayIsBasePlusTheVault(t *testing.T) {
	base, overlay := manifests(t, "client.yaml"), manifestsIn(t, "vault", "client.yaml")
	for _, c := range []string{"a", "b"} {
		name, claim := "Deployment/client-"+c, "vault-client-"+c
		b, okB := base[name]
		m, okM := overlay[name]
		if !okB || !okM {
			t.Fatalf("%s: in deploy/base %v, in deploy/vault %v", name, okB, okM)
		}
		if got, want := argsOf(t, m), append(argsOf(t, b), "-vault", "/vault/peer.vault"); !slices.Equal(got, want) {
			t.Errorf("%s: args %q, want those of deploy/base and -vault /vault/peer.vault", name, got)
		}
		if got, want := body(m.text), withVault(t, body(b.text), claim); got != want {
			t.Errorf("%s: the overlay differs from deploy/base beyond the vault:\n%s\nwant:\n%s", name, got, want)
		}
		confined(t, m, confinement(m))
		explicitSuite(t, m)
		labels := "{app: client, client: " + c + "}"
		if strings.Count(m.text, labels) != 3 || !strings.Contains(m.text, "matchLabels: "+labels) {
			t.Errorf("%s: want the labels and the selector %s", name, labels)
		}
		if strings.Contains(m.text, "ports:") {
			t.Errorf("%s: want no ports", name)
		}
		if strings.Count(m.text, "volumes:") != 1 || strings.Count(m.text, "- name: vault") != 1 ||
			strings.Count(m.text, "persistentVolumeClaim: {claimName: "+claim+"}") != 1 || strings.Count(m.text, "claimName:") != 1 {
			t.Errorf("%s: want one volume, the claim %s", name, claim)
		}
		if strings.Count(m.text, "volumeMounts:") != 1 || strings.Count(m.text, "mountPath:") != 1 ||
			strings.Count(m.text, "- {name: vault, mountPath: /vault}") != 1 {
			t.Errorf("%s: want one mount, the vault at /vault", name)
		}
	}
}

func TestVaultClaimsAreSmallAndDefault(t *testing.T) {
	overlay := manifestsIn(t, "vault", "client.yaml")
	claims := 0
	for _, m := range overlay {
		if m.kind != "PersistentVolumeClaim" {
			continue
		}
		claims++
		want := "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: " + m.name +
			"\n  namespace: jimichi\nspec:\n  accessModes: [ReadWriteOnce]\n  resources: {requests: {storage: 1Mi}}"
		if got := body(m.text); got != want {
			t.Errorf("%s:\n%s\nwant:\n%s", m.name, got, want)
		}
	}
	if claims != 2 {
		t.Errorf("%d claims in deploy/vault, want two", claims)
	}
	for _, c := range []string{"a", "b"} {
		m := overlay["Deployment/client-"+c]
		claim := regexp.MustCompile(`claimName: (\S+)\}`).FindStringSubmatch(m.text)
		if claim == nil || claim[1] != "vault-client-"+c {
			t.Errorf("client-%s: claim %q, want vault-client-%s", c, claim, c)
			continue
		}
		if _, ok := overlay["PersistentVolumeClaim/"+claim[1]]; !ok {
			t.Errorf("client-%s: the claim %s is not in deploy/vault", c, claim[1])
		}
	}
}

// a relay keeps nothing on a disk in any manifest, and no manifest mounts a
// directory of the node or a scratch volume
func TestNoRelayHasAVolume(t *testing.T) {
	root := filepath.Join("..", "deploy")
	var files []string
	err := filepath.WalkDir(root, func(file string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() && rel == "kind" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(rel, ".yaml") {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	if want := []string{"base/client.yaml", "base/network.yaml", "base/relay.yaml", "vault/client.yaml"}; !slices.Equal(files, want) {
		t.Fatalf("manifests %q, want %q: a new one is checked here first", files, want)
	}
	relayLabel := regexp.MustCompile(`\bapp: relay\b`)
	relays := 0
	for _, file := range files {
		dir, name := path.Split(file)
		for _, m := range manifestsIn(t, strings.TrimSuffix(dir, "/"), name) {
			if strings.Contains(m.text, "hostPath:") || strings.Contains(m.text, "emptyDir:") {
				t.Errorf("%s %s: want no hostPath and no emptyDir", file, m.name)
			}
			if !relayLabel.MatchString(m.text) || m.kind == "NetworkPolicy" {
				continue
			}
			if dir == "vault/" {
				t.Errorf("%s: a relay %s in deploy/vault", file, m.name)
			}
			if m.kind == "Deployment" {
				relays++
			}
			if strings.Contains(m.text, "volumes:") || strings.Contains(m.text, "volumeMounts:") {
				t.Errorf("%s %s: a relay has a volume", file, m.name)
			}
		}
	}
	if relays != 5 {
		t.Errorf("%d relay deployments under deploy/, want five", relays)
	}
}
