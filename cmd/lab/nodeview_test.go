package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab/nodeview"
)

func TestNodeviewCLIRejectsUnregisteredFlags(t *testing.T) {
	for _, set := range []string{"compromise", "collude", "mailbox"} {
		for _, arg := range []string{"-flows=6", "-hops=3", "-duration=20s", "-send=200ms", "-bins=100ms", "-repeats=1", "-mark-replay=", "-nodes=5", "-rogue=2", "-samples=100000", "-missing=1", "-leftout=0", "-withhold=0", "-train=5", "-corridor=0.2", "-claims=1", "-base=0.001", "positional"} {
			t.Run(set+"/"+arg, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "not-created")
				var out, errOut bytes.Buffer
				args := []string{"-set", set, "-rev", strings.Repeat("a", 40), "-out", root, arg}
				if code := command(args, &out, &errOut); code != 2 {
					t.Fatalf("exit %d, want 2", code)
				}
				if out.Len() != 0 || errOut.String() != "nodeview: invalid_config\n" {
					t.Fatalf("unexpected diagnostics: stdout %q, stderr %q", out.String(), errOut.String())
				}
				if _, err := os.Stat(root); !os.IsNotExist(err) {
					t.Fatal("invalid command touched output directory")
				}
			})
		}
	}
}

func TestNodeviewCLIInvalidConfig(t *testing.T) {
	for _, extra := range [][]string{
		{"-rev=unknown"}, {"-rev=" + strings.Repeat("A", 40)}, {"-suite=other"},
		{"-out="}, {"-node-phase="}, {"-node-phase=other"},
		{"-node-phase=pilot"}, {"-node-phase=primary"}, {"-node-phase=train"},
		{"-set=collude", "-peer"}, {"-set=mailbox", "-peer=false"},
		{"-node-phase=primary", "-node-plan=plan.json", "-peer=false"},
	} {
		var out, errOut bytes.Buffer
		args := append([]string{"-set=compromise", "-rev=" + strings.Repeat("a", 40)}, extra...)
		if code := command(args, &out, &errOut); code != 2 || out.Len() != 0 {
			t.Fatalf("args %v: exit %d, stdout %q", extra, code, out.String())
		}
		if errOut.String() != "nodeview: invalid_config\n" {
			t.Fatalf("unexpected diagnostic %q", errOut.String())
		}
	}
}

func TestNodeviewFlagsRequireNodeSet(t *testing.T) {
	for _, set := range []string{"main", "rates", "paced", "paths", "deny", "cover", "mark", "keymem"} {
		for _, arg := range []string{"-node-phase=structural", "-node-plan=", "-peer=false"} {
			var out, errOut bytes.Buffer
			if code := command([]string{"-set", set, arg}, &out, &errOut); code != 2 || out.Len() != 0 || errOut.String() != "nodeview: invalid_set\n" {
				t.Fatalf("%s %s: exit %d, stdout %q, stderr %q", set, arg, code, out.String(), errOut.String())
			}
		}
	}
}

func TestNodeviewCLIParserDoesNotDiscloseValues(t *testing.T) {
	const secret = "private-sentinel-value"
	for _, args := range [][]string{
		{"-set=compromise", "-seed=" + secret},
		{"-set=collude", "-duration=" + secret},
		{"--set=mailbox", "-peer=" + secret},
		{"-" + secret, "-set", "compromise"},
		{"--" + secret, "--set", "mailbox"},
	} {
		var out, errOut bytes.Buffer
		if code := command(args, &out, &errOut); code != 2 || out.Len() != 0 || errOut.String() != "nodeview: invalid_flag\n" {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
		}
	}
}

func TestNodeviewConfigPreservesRegisteredSelection(t *testing.T) {
	for _, set := range []string{"compromise", "collude", "mailbox"} {
		for _, phase := range []string{"structural", "train", "pilot", "primary"} {
			if phase == "train" && set != "mailbox" {
				continue
			}
			f := nodeviewFlags{set: set, phase: phase, plan: "plan.json", suite: "gost", revision: strings.Repeat("a", 40), out: "artifacts", seed: 11703}
			c, err := nodeviewConfig(f)
			if err != nil || string(c.Set) != set || string(c.Phase) != phase || c.Suite.String() != "gost" || c.PlanPath != "plan.json" || c.Revision != f.revision || c.Seed != 11703 || c.Peer {
				t.Fatalf("%s/%s: config %#v, err %v", set, phase, c, err)
			}
		}
	}
	f := nodeviewFlags{set: "compromise", phase: "structural", peer: true, suite: "c25519", revision: strings.Repeat("b", 40), out: "artifacts", explicit: map[string]bool{"peer": true}}
	if c, err := nodeviewConfig(f); err != nil || !c.Peer || c.PlanPath != "" {
		t.Fatalf("peer structural: config %#v, err %v", c, err)
	}
}

func TestNodeviewExitCodes(t *testing.T) {
	for _, tc := range []struct {
		status nodeview.Reason
		err    error
		want   int
	}{
		{nodeview.ReasonNone, nil, 0},
		{nodeview.ReasonNone, nodeview.ErrInvalid, 2},
		{nodeview.ReasonNone, nodeview.ErrUnsupported, 3},
		{nodeview.ReasonUnsupported, errors.New("opaque"), 3},
		{nodeview.ReasonCancelled, errors.New("opaque"), 130},
		{nodeview.ReasonIPC, errors.New("opaque"), 1},
		{nodeview.ReasonContract, nil, 1},
		{nodeview.ReasonNone, errors.New("opaque"), 1},
	} {
		if got := nodeviewExit(nodeview.Report{Status: tc.status}, tc.err); got != tc.want {
			t.Fatalf("status %q: exit %d, want %d", tc.status, got, tc.want)
		}
	}
}

func TestNodeviewPrivateChildRequiresPipes(t *testing.T) {
	for _, args := range [][]string{{"--nodeview-child-v1=relay"}, {"--nodeview-child-v1=scorer", "-help"}, {"--nodeview-child-v1=unknown"}} {
		var out, errOut bytes.Buffer
		if code := command(args, &out, &errOut); code != 2 || out.Len() != 0 || errOut.Len() != 0 {
			t.Fatalf("private child: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
		}
	}
}

func TestNodeviewHelpStatesRegisteredMatrix(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := command([]string{"-set=compromise", "-help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, term := range []string{"compromise", "collude", "mailbox", "-node-phase", "-node-plan", "-peer", "coordinates come from the registered matrix"} {
		if !strings.Contains(errOut.String(), term) {
			t.Fatalf("help missing %q", term)
		}
	}
}

func TestNodeviewPlanningEstimatePrecedesPairedPlanning(t *testing.T) {
	for _, phase := range []nodeview.Phase{nodeview.Pilot, nodeview.Primary} {
		var out bytes.Buffer
		c := nodeview.Config{Set: nodeview.Collude, Phase: phase, Suite: jcrypto.SuiteC25519, PlanPath: "private-path-sentinel", Seed: 11703}
		if err := nodeviewPlanningEstimate(&out, c); err != nil {
			t.Fatal(err)
		}
		var record struct {
			Schema   string                 `json:"schema"`
			Set      nodeview.Set           `json:"set"`
			Phase    nodeview.Phase         `json:"phase"`
			Estimate nodeview.PowerEstimate `json:"maximum_paired_planning"`
		}
		if err := json.Unmarshal(out.Bytes(), &record); err != nil || record.Schema != "jimichi-nodeview-planning-estimate-v1" || record.Set != nodeview.Collude || record.Phase != phase || record.Estimate != nodeview.PairedPowerEstimate() {
			t.Fatalf("invalid public planning estimate: %v", err)
		}
		if strings.Contains(out.String(), c.PlanPath) || strings.Contains(out.String(), "11703") {
			t.Fatal("estimate disclosed non-estimate inputs")
		}
		if err := nodeviewPlanningEstimate(failedNodeviewEstimateWriter{}, c); err == nil {
			t.Fatal("failed estimate write silently allowed planning")
		}
	}
	for _, c := range []nodeview.Config{{Phase: nodeview.Structural, Suite: jcrypto.SuiteC25519}, {Phase: nodeview.Train, Suite: jcrypto.SuiteC25519}, {Phase: nodeview.Pilot, Suite: jcrypto.SuiteGOST}} {
		var out bytes.Buffer
		if err := nodeviewPlanningEstimate(&out, c); err != nil || out.Len() != 0 {
			t.Fatal("unrequested inferential planning estimate emitted")
		}
	}
}

type failedNodeviewEstimateWriter struct{}

func (failedNodeviewEstimateWriter) Write([]byte) (int, error) {
	return 0, errors.New("estimate write failed")
}
