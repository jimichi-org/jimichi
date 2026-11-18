package nodeview

import (
	"strings"
	"testing"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func TestDelayedContactOrphanIsExactRegisteredException(t *testing.T) {
	allowed := map[[3]string]bool{
		{"compromise", "structural", "c25519"}: true,
		{"compromise", "structural", "gost"}:   true,
		{"compromise", "primary", "gost"}:      true,
	}
	for _, suite := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, set := range []Set{Compromise, Collude, Mailbox} {
			for _, phase := range []Phase{Structural, Train, Pilot, Primary} {
				c := Config{Set: set, Phase: phase, Suite: suite, Revision: strings.Repeat("a", 40)}
				for _, row := range foreignTrustCoordinates() {
					want := allowed[[3]string{string(set), string(phase), suite.String()}] && (row.ID == "trust-peer-honest-k1-m1" || row.ID == "trust-peer-honest-k1-m2")
					if registeredOrphan(c, row) != want {
						t.Fatalf("orphan applicability changed for %s/%s/%s/%s", set, phase, suite.String(), row.ID)
					}
				}
			}
		}
	}
	for _, row := range foreignTrustCoordinates() {
		if row.ID != "trust-peer-honest-k1-m1" && row.ID != "trust-peer-honest-k1-m2" {
			continue
		}
		for _, c := range []Config{
			{Set: Compromise, Phase: Structural, Suite: jcrypto.SuiteC25519},
			{Set: Compromise, Phase: Structural, Suite: jcrypto.SuiteGOST},
			{Set: Compromise, Phase: Primary, Suite: jcrypto.SuiteGOST},
		} {
			for _, mutation := range []struct {
				name string
				edit func(*Coordinate)
			}{
				{"id", func(r *Coordinate) { r.ID = "unknown" }},
				{"id-missing-pair", func(r *Coordinate) {
					if r.Missing == 1 {
						r.ID = "trust-peer-honest-k1-m2"
					} else {
						r.ID = "trust-peer-honest-k1-m1"
					}
				}},
				{"missing", func(r *Coordinate) { r.Missing = 0 }},
				{"topology", func(r *Coordinate) { r.Topology = "echo" }},
				{"mailbox", func(r *Coordinate) { r.Mailbox = 0 }},
				{"foreign-nil", func(r *Coordinate) { r.ForeignPositions = nil }},
				{"foreign-empty", func(r *Coordinate) { r.ForeignPositions = []int{} }},
				{"foreign-two", func(r *Coordinate) { r.ForeignPositions = []int{0, 1} }},
				{"foreign-position", func(r *Coordinate) { r.ForeignPositions = []int{1} }},
				{"settings", func(r *Coordinate) { r.Settings.CoverPuts = true }},
			} {
				other := row
				mutation.edit(&other)
				if registeredOrphan(c, other) {
					t.Fatalf("orphan accepted changed %s for %s/%s", mutation.name, c.Phase, row.ID)
				}
			}
		}
		for _, c := range []Config{
			{Set: Compromise, Phase: "unknown", Suite: jcrypto.SuiteGOST},
			{Set: Compromise, Phase: Primary, Suite: 99},
			{Set: "unknown", Phase: Structural, Suite: jcrypto.SuiteGOST},
		} {
			if registeredOrphan(c, row) {
				t.Fatal("orphan accepted an unknown applicability value")
			}
		}
	}
	assertRegisteredOrphanValidation(t)
	assertRegisteredOrphanAdmissionKnownAnswers(t)
}

func assertRegisteredOrphanValidation(t *testing.T) {
	t.Helper()
	c := Config{Set: Compromise, Phase: Structural, Suite: jcrypto.SuiteC25519, Revision: strings.Repeat("a", 40)}
	if c.validate() != nil {
		t.Fatal("canonical structural config was rejected")
	}
	for _, edit := range []func(*Config){
		func(c *Config) { c.Set = "unknown" },
		func(c *Config) { c.Phase = "unknown" },
		func(c *Config) { c.Suite = 99 },
	} {
		other := c
		edit(&other)
		if other.validate() == nil {
			t.Fatal("unknown config value passed upstream validation")
		}
	}
	for _, phase := range []Phase{Train, Pilot, Primary} {
		other := c
		other.Phase = phase
		if phase == Train {
			other.Set = Mailbox
		}
		if other.validate() == nil {
			t.Fatal("nonstructural config accepted a missing plan path")
		}
		other.PlanPath = "registered"
		if other.validate() != nil {
			t.Fatal("registered nonstructural config was rejected")
		}
		other.Peer = true
		if other.validate() == nil {
			t.Fatal("nonstructural peer shortcut passed upstream validation")
		}
	}
	p := defaultPlan(c, strings.Repeat("b", 40), strings.Repeat("0", 64))
	if ValidatePlan(p) != nil {
		t.Fatal("canonical structural plan was rejected")
	}
	at := -1
	for i, row := range p.Configurations {
		if row.ID == "trust-peer-honest-k1-m1" {
			at = i
		}
	}
	if at < 0 {
		t.Fatal("registered orphan coordinate is missing")
	}
	for _, mutation := range []struct {
		name string
		edit func(*Coordinate)
	}{
		{"trust", func(r *Coordinate) { r.Trust = "trusted" }},
		{"population", func(r *Coordinate) { r.Population = "classifier" }},
		{"controlled", func(r *Coordinate) { r.Controlled = []int{1} }},
		{"nodes", func(r *Coordinate) { r.N = 6 }},
		{"hops", func(r *Coordinate) { r.H = 4 }},
		{"setup", func(r *Coordinate) { r.Setup = "concurrent" }},
		{"mode", func(r *Coordinate) { r.Mode = "fixed" }},
	} {
		other := p
		other.Configurations = append([]Coordinate(nil), p.Configurations...)
		mutation.edit(&other.Configurations[at])
		if !registeredOrphan(c, other.Configurations[at]) || ValidatePlan(other) == nil {
			t.Fatalf("canonical validation no longer owns %s", mutation.name)
		}
	}
	for _, main := range []int{30, 512} {
		other := p
		other.Configurations = append([]Coordinate(nil), p.Configurations...)
		other.Configurations[at].Main = main
		if !registeredOrphan(c, other.Configurations[at]) || ValidatePlan(other) != nil {
			t.Fatalf("legal registered Main count %d was rejected", main)
		}
	}
	for _, main := range []int{29, 513} {
		other := p
		other.Configurations = append([]Coordinate(nil), p.Configurations...)
		other.Configurations[at].Main = main
		if ValidatePlan(other) == nil {
			t.Fatalf("out-of-range registered Main count %d was accepted", main)
		}
	}
}

func registeredOrphanRoutesKnownAnswer() [12][3]uint8 {
	return [12][3]uint8{
		{0, 1, 4}, {0, 2, 4}, {0, 3, 4}, {1, 0, 4},
		{1, 2, 4}, {1, 3, 4}, {2, 0, 4}, {2, 1, 4},
		{2, 3, 4}, {3, 0, 4}, {3, 1, 4}, {3, 2, 4},
	}
}

func assertRegisteredOrphanAdmissionKnownAnswers(t *testing.T) {
	t.Helper()
	wantRoutes := registeredOrphanRoutesKnownAnswer()
	routes := exhaustiveTrustRoutes("peer", 4)
	if len(routes) != len(wantRoutes) {
		t.Fatal("honest mailbox target count changed")
	}
	for i, route := range routes {
		if route != wantRoutes[i] {
			t.Fatalf("honest mailbox target order changed at %d", i)
		}
	}
	for _, pair := range [6][2]int{{0, 1}, {2, 3}, {4, 5}, {6, 7}, {8, 9}, {10, 11}} {
		if pair[0]^1 != pair[1] || pair[1]^1 != pair[0] {
			t.Fatal("original peer pairing changed")
		}
	}
	for _, row := range []struct {
		served  [5]bool
		missing int
		want    [4]int
	}{
		{[5]bool{false, true, true, true, true}, 0, [4]int{12, 0, 0, 0}},
		{[5]bool{false, true, true, true, true}, 1, [4]int{3, 9, 8, 1}},
		{[5]bool{false, true, true, true, true}, 2, [4]int{3, 9, 8, 1}},
		{[5]bool{false, false, true, true, true}, 0, [4]int{12, 0, 0, 0}},
		{[5]bool{false, false, true, true, true}, 1, [4]int{12, 0, 0, 0}},
		{[5]bool{false, false, true, true, true}, 2, [4]int{6, 6, 6, 0}},
		{[5]bool{true, true, true, true, false}, 0, [4]int{12, 0, 0, 0}},
		{[5]bool{true, true, true, true, false}, 1, [4]int{12, 0, 0, 0}},
		{[5]bool{true, true, true, true, false}, 2, [4]int{12, 0, 0, 0}},
		{[5]bool{false, true, true, true, false}, 0, [4]int{12, 0, 0, 0}},
		{[5]bool{false, true, true, true, false}, 1, [4]int{12, 0, 0, 0}},
		{[5]bool{false, true, true, true, false}, 2, [4]int{12, 0, 0, 0}},
	} {
		var admitted [12]bool
		var got [4]int
		for i, route := range routes {
			verdict, _, _ := client.JudgeMirrorToAmong(row.served[:], nil, int(route[0]), 4, 3, row.missing)
			admitted[i] = verdict == client.MirrorTaken
			if admitted[i] {
				got[1]++
			} else {
				got[0]++
			}
		}
		for i, ready := range admitted {
			if ready {
				if admitted[i^1] {
					got[2]++
				} else {
					got[3]++
				}
			}
		}
		if got != row.want {
			t.Fatalf("original admission/pairing changed for %v/missing%d: %v", row.served, row.missing, got)
		}
	}
}

func TestDefaultsControlOffsetsAreExactlyRegistered(t *testing.T) {
	// each active ten-second segment has fifty offsets, 0.1+0.2*j seconds
	offsets := defaultsOffsets()
	if len(offsets) != 100 || offsets[0] != 100000000 || offsets[49] != 9900000000 || offsets[50] != 20100000000 || offsets[99] != 29900000000 {
		t.Fatal("defaults control cardinality or endpoints changed")
	}
	for i, offset := range offsets {
		if offset < 0 || offset >= 30000000000 || offset >= 10000000000 && offset < 20000000000 || i > 0 && offset <= offsets[i-1] {
			t.Fatal("invalid defaults source offset")
		}
		if i != 0 && i != 50 && offset-offsets[i-1] != 200000000 {
			t.Fatal("defaults period changed")
		}
	}
}
