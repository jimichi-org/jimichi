package nodeview

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func testNodeviewPlan(set Set) Plan {
	c := Config{Set: set, Phase: Structural, Suite: jcrypto.SuiteC25519, Revision: strings.Repeat("a", 40)}
	return defaultPlan(c, strings.Repeat("b", 40), strings.Repeat("c", 64))
}

func TestDefaultPlansKeepCompleteRegistration(t *testing.T) {
	for _, set := range []Set{Compromise, Collude, Mailbox} {
		p := testNodeviewPlan(set)
		if err := ValidatePlan(p); err != nil {
			t.Fatalf("%s: %v", set, err)
		}
		if len(p.ModelFamily.IDs) != 13 || p.ModelFamily.M != 13 || len(p.DifferenceFamily.IDs) != 13 || p.DifferenceFamily.M != 13 || p.ModelFamily.Delta != .05 || p.DifferenceFamily.Power != .8 {
			t.Fatal("registered families changed")
		}
		ids := map[string]bool{}
		for _, c := range p.Configurations {
			if ids[c.ID] || c.N != 5 || c.H != 3 {
				t.Fatal("duplicate coordinate or changed network")
			}
			ids[c.ID] = true
		}
		switch set {
		case Compromise:
			for _, id := range []string{"E1", "E2", "H1", "H2", "M1", "M2"} {
				if !ids[id] {
					t.Fatalf("missing model %s", id)
				}
			}
		case Collude:
			for _, id := range []string{"node-F5-L0", "node-F5-L1", "node-F5-L2", "node-F10-L0", "node-F10-L1", "node-F10-L2", "node-F20-L0", "node-F20-L1", "node-F20-L2"} {
				if !ids[id] {
					t.Fatalf("missing linking point %s", id)
				}
			}
			if len(ids) != 27 {
				t.Fatal("missing serial, adjacent or incomplete controls")
			}
		case Mailbox:
			for _, id := range []string{"mail-P0-C0", "mail-P0-C1", "mail-P33250000-C0", "mail-P33250000-C1", "mail-P0-defaults", "mail-P33250000-defaults"} {
				if !ids[id] {
					t.Fatalf("missing mailbox point %s", id)
				}
			}
		}
	}
}

func TestPlanRejectsChangedRegistration(t *testing.T) {
	for name, mutate := range map[string]func(*Plan){
		"schema":            func(p *Plan) { p.Schema = "other" },
		"revision":          func(p *Plan) { p.Revision = strings.Repeat("A", 40) },
		"binary":            func(p *Plan) { p.BinarySHA256 = "unknown" },
		"family":            func(p *Plan) { p.DifferenceFamily.M = 12 },
		"margin":            func(p *Plan) { p.ModelFamily.Delta = .1 },
		"nan":               func(p *Plan) { p.ModelFamily.Power = math.NaN() },
		"missing":           func(p *Plan) { p.Configurations = p.Configurations[1:] },
		"duplicate":         func(p *Plan) { p.Configurations[1] = p.Configurations[0] },
		"fewer":             func(p *Plan) { p.Configurations[0].Slots = 2016 },
		"unrounded":         func(p *Plan) { p.Configurations[0].Slots = 2049 },
		"repeats":           func(p *Plan) { p.Configurations[0].Main = 29 },
		"ceiling":           func(p *Plan) { p.Limits.Lifecycles++ },
		"feature":           func(p *Plan) { p.FeatureVersion = "raw" },
		"transform":         func(p *Plan) { p.TransformDigest = strings.Repeat("d", 64) },
		"primary":           func(p *Plan) { p.Phase = Primary },
		"unknown-pilot-set": func(p *Plan) { p.Phase = Pilot; p.Set = "unknown"; p.Configurations = nil },
		"unreleased-reference": func(p *Plan) {
			p.FrozenModels = []ModelReference{{Configuration: "private-sentinel", Population: "request", Digest: strings.Repeat("d", 64)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := testNodeviewPlan(Compromise)
			mutate(&p)
			if err := ValidatePlan(p); err == nil {
				t.Fatal("changed or incomplete registration accepted")
			}
		})
	}
}

func TestStrictJSONRejectsAmbiguityAndUnknownFields(t *testing.T) {
	type nested struct {
		Value int `json:"value"`
	}
	type document struct {
		Value int    `json:"value"`
		Child nested `json:"child"`
	}
	var good document
	if err := strictJSON(strings.NewReader(`{"value":1,"child":{"value":2}}`), &good); err != nil || good.Value != 1 || good.Child.Value != 2 {
		t.Fatalf("valid JSON rejected: %v", err)
	}
	for _, raw := range []string{
		`{"value":1,"value":2}`, `{"child":{"value":1,"value":2}}`,
		`{"unknown":1}`, `{"child":{"unknown":1}}`, `{}` + `{}`,
		`{"value":1`, `{"value":1} trailing`, `{"value":1.5}`, `{"value":1e999}`,
	} {
		var out document
		if err := strictJSON(strings.NewReader(raw), &out); err == nil {
			t.Fatalf("invalid JSON accepted: %s", raw)
		}
	}
}

func TestPlanLoadChecksSourceBinding(t *testing.T) {
	p := planningTestSeal(t, testNodeviewPlan(Collude))
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{Set: p.Set, Phase: Structural, Suite: jcrypto.SuiteC25519, Revision: p.Revision}
	if _, err := loadPlan(path, c, p.Tree, p.BinarySHA256); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	for _, change := range []string{"revision", "tree", "binary", "set", "suite"} {
		c2, tree, binary := c, p.Tree, p.BinarySHA256
		switch change {
		case "revision":
			c2.Revision = strings.Repeat("d", 40)
		case "tree":
			tree = strings.Repeat("d", 40)
		case "binary":
			binary = strings.Repeat("d", 64)
		case "set":
			c2.Set = Compromise
		case "suite":
			c2.Suite = jcrypto.SuiteGOST
		}
		if _, err := loadPlan(path, c2, tree, binary); err == nil {
			t.Fatalf("mismatched %s accepted", change)
		}
	}
}

func TestAdjacentArtifactsStayInsidePlanDirectory(t *testing.T) {
	root := t.TempDir()
	plan := filepath.Join(root, "plan.json")
	if got, err := adjacentFile(plan, "frozen-models.json"); err != nil || got != filepath.Join(root, "frozen-models.json") {
		t.Fatalf("valid adjacent path %q, %v", got, err)
	}
	for _, name := range []string{"..", "../outside", filepath.Join(t.TempDir(), "model.json")} {
		if _, err := adjacentFile(plan, name); err == nil {
			t.Fatal("nonadjacent artifact accepted")
		}
	}
}
