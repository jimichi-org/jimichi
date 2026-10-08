package scripts

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "base", name))
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
	for _, c := range []struct {
		what string
		ok   bool
	}{
		{"strategy Recreate", recreate.MatchString(m.text)},
		{"IPC_LOCK added", ipcLock.MatchString(m.text)},
		{"every other capability dropped", dropAll.MatchString(m.text)},
		{"a read-only root", strings.Contains(m.text, "readOnlyRootFilesystem: true")},
		{"no privilege escalation", strings.Contains(m.text, "allowPrivilegeEscalation: false")},
		{"a user other than root", strings.Contains(m.text, "runAsNonRoot: true")},
		{"no volume", !strings.Contains(m.text, "volumes:") && !strings.Contains(m.text, "volumeMounts:")},
	} {
		if !c.ok {
			t.Errorf("%s: want %s", m.name, c.what)
		}
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
		if got := flagValue(argsOf(t, m), "-exit"); got != "mailbox" {
			t.Errorf("%s: -exit %q, want mailbox", m.name, got)
		}
	}
	if relays != 5 {
		t.Fatalf("%d relay deployments, want five", relays)
	}
}
