package nodeview

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

type Coordinate struct {
	ForeignPositions []int    `json:"foreign_positions"`
	Missing          uint8    `json:"missing"`
	Mailbox          uint8    `json:"mailbox"`
	ID               string   `json:"id"`
	Topology         string   `json:"topology"`
	Trust            string   `json:"trust"`
	Population       string   `json:"population"`
	Controlled       []int    `json:"controlled"`
	Placement        string   `json:"placement"`
	Setup            string   `json:"setup"`
	Mode             string   `json:"mode"`
	N                int      `json:"n"`
	H                int      `json:"h"`
	Slots            int      `json:"slots"`
	Flows            int      `json:"flows"`
	Conversations    int      `json:"conversations"`
	Training         int      `json:"training"`
	Pilots           int      `json:"pilots"`
	Main             int      `json:"main"`
	Settings         Settings `json:"settings"`
}

type Family struct {
	IDs     []string `json:"ids"`
	M       int      `json:"m"`
	Alpha   float64  `json:"alpha"`
	Delta   float64  `json:"delta"`
	Power   float64  `json:"power"`
	Pairing string   `json:"pairing"`
}

type Limits struct {
	RelayArena      int `json:"relay_arena"`
	ControllerArena int `json:"controller_arena"`
	ClientArena     int `json:"client_arena"`
	Connections     int `json:"connections"`
	PendingFrames   int `json:"pending_frames"`
	Contexts        int `json:"contexts"`
	Lifecycles      int `json:"lifecycles"`
	Clients         int `json:"clients"`
	TrainingRows    int `json:"training_rows"`
	Messages        int `json:"messages"`
	TruthRecords    int `json:"truth_records"`
	SelectedCells   int `json:"selected_cells"`
}

type Deadlines struct {
	EnrollmentNS int64 `json:"enrollment_ns"`
	PreflightNS  int64 `json:"preflight_ns"`
	PeerReadyNS  int64 `json:"peer_ready_ns"`
	DrainMaxNS   int64 `json:"drain_max_ns"`
	ShutdownNS   int64 `json:"shutdown_ns"`
	EmergencyNS  int64 `json:"emergency_ns"`
	CohortMaxNS  int64 `json:"cohort_max_ns"`
}

type ModelReference struct {
	Configuration string `json:"configuration"`
	Population    string `json:"population"`
	Digest        string `json:"digest"`
}
type SampleCalculation struct {
	ID       string  `json:"id"`
	Slots    int     `json:"slots"`
	Expected float64 `json:"expected"`
	SD       float64 `json:"sd"`
	Power    float64 `json:"power"`
}
type PowerCalculation struct {
	ID          string    `json:"id"`
	N           int       `json:"n"`
	Seed        int64     `json:"seed"`
	Successes   int       `json:"successes"`
	Simulations int       `json:"simulations"`
	PilotX      []float64 `json:"pilot_x"`
	PilotY      []float64 `json:"pilot_y"`
	Low         float64   `json:"low"`
	High        float64   `json:"high"`
}
type Plan struct {
	Schema               string              `json:"schema"`
	Revision             string              `json:"revision"`
	Tree                 string              `json:"tree"`
	BinarySHA256         string              `json:"binary_sha256"`
	Digest               string              `json:"digest"`
	ParentDigest         string              `json:"parent_digest,omitempty"`
	MainSeedCommitment   string              `json:"main_seed_commitment,omitempty"`
	Phase                Phase               `json:"phase"`
	Suite                string              `json:"suite"`
	Set                  Set                 `json:"set"`
	ModelFamily          Family              `json:"model_family"`
	DifferenceFamily     Family              `json:"difference_family"`
	Configurations       []Coordinate        `json:"configurations"`
	WindowsNS            []int64             `json:"windows_ns"`
	BinNS                int64               `json:"bin_ns"`
	PayloadBytes         int                 `json:"payload_bytes"`
	SeedDomainVersion    int                 `json:"seed_domain_version"`
	FeatureVersion       string              `json:"feature_version"`
	TransformDigest      string              `json:"transform_digest"`
	SegmentsNS           [4]int64            `json:"segments_ns"`
	Limits               Limits              `json:"limits"`
	Deadlines            Deadlines           `json:"deadlines"`
	FrozenModels         []ModelReference    `json:"frozen_models"`
	Samples              []SampleCalculation `json:"samples"`
	Powers               []PowerCalculation  `json:"powers"`
	PowerSearch          []PairedPowerPlan   `json:"power_search"`
	TrainingReady        bool                `json:"training_ready"`
	PilotReady           bool                `json:"pilot_ready"`
	ModelReady           bool                `json:"model_ready"`
	Simulations          int                 `json:"simulations"`
	Bootstrap            int                 `json:"bootstrap"`
	ExactMax             int                 `json:"exact_max_nonzero"`
	Clock                string              `json:"clock"`
	ClockResolutionMaxNS int64               `json:"clock_resolution_max_ns"`
	ExemptionReason      string              `json:"exemption_reason"`
}

func modelIDs() []string {
	return []string{"E1.touched", "E1.content", "E1.R", "E2.ends", "E2.touched", "E2.content", "E2.R", "H1.touched", "H1.R", "H2.touched", "H2.R", "M2.ends", "M2.R"}
}
func differenceIDs() []string {
	return []string{"node-F5-L0", "node-F5-L1", "node-F5-L2", "node-F10-L0", "node-F10-L1", "node-F10-L2", "node-F20-L0", "node-F20-L1", "node-F20-L2", "mail-P0-request", "mail-P0-record", "mail-P33250000-request", "mail-P33250000-record"}
}
func canonicalLimits() Limits {
	return Limits{relayArenaBytes, controllerArenaBytes, clientArenaBytes, maxConnections, maxPendingFrames, maxContexts, maxLifecycles, maxClients, maxTrainingRows, maxMessages, maxTruthRecords, maxSelectedCells}
}
func canonicalDeadlines() Deadlines {
	return Deadlines{30000000000, 5000000000, 30000000000, 10000000000, 10000000000, 2000000000, 600000000000}
}

func canonicalCoordinates(set Set) []Coordinate {
	var out []Coordinate
	add := func(id, top, pop, placement, setup string, k, slots, flows, conversations, level int, cover bool, period int64) {
		s := echoSettings(level)
		if top == "peer" {
			s = peerSettings(cover, period)
		}
		mode := "immediate"
		if top == "echo" && level > 0 {
			mode = "fixed"
		}
		controlled := []int{0}
		if k == 2 {
			controlled = []int{0, 1}
		}
		mailbox := uint8(255)
		if top == "peer" {
			mailbox = 4
		}
		if id == "M1" || top == "peer" && pop != "H1" && pop != "H2" && k == 1 {
			controlled = []int{4}
		}
		if id == "M2" || top == "peer" && k == 2 && pop != "H2" {
			controlled = []int{0, 4}
		}
		out = append(out, Coordinate{ID: id, Topology: top, Trust: "trusted", Population: pop, Controlled: controlled, Placement: placement, Setup: setup, Mode: mode, N: 5, H: 3, Slots: slots, Flows: flows, Conversations: conversations, Training: 0, Pilots: 5, Main: 30, Settings: s, Missing: 2, Mailbox: mailbox})
	}
	switch set {
	case Compromise:
		for _, r := range []struct {
			id, top string
			k, n    int
		}{{"E1", "echo", 1, 2048}, {"E2", "echo", 2, 2048}, {"H1", "peer", 1, 2048}, {"H2", "peer", 2, 2048}, {"M1", "peer", 1, 32}, {"M2", "peer", 2, 2048}} {
			add(r.id, r.top, r.id, "drawn", "serial", r.k, r.n, 0, 0, 0, false, 0)
		}
		out = append(out, foreignTrustCoordinates()...)
	case Collude:
		for _, f := range []int{5, 10, 20} {
			for l := range 3 {
				add("node-F"+decimal(f)+"-L"+decimal(l), "echo", "link", "edges", "concurrent", 2, 0, f, 0, l, false, 0)
			}
		}
		for l := range 3 {
			add("serial-L"+decimal(l), "echo", "control", "edges", "serial", 2, 0, 5, 0, l, false, 0)
			for _, p := range []string{"adjacent-first", "adjacent-last"} {
				for _, setup := range []string{"serial", "concurrent"} {
					add(p+"-"+setup+"-L"+decimal(l), "echo", "control", p, setup, 2, 0, 5, 0, l, false, 0)
				}
			}
			add("incomplete-L"+decimal(l), "echo", "incomplete", "edges", "concurrent", 2, 0, 12, 0, l, false, 0)
		}
	case Mailbox:
		for _, p := range []int64{0, 33250000} {
			for _, cover := range []bool{false, true} {
				id := "mail-P" + decimal(int(p)) + "-C" + decimal(boolInt(cover))
				add(id, "peer", "classifier", "mailbox", "concurrent", 1, 0, 0, 8, 0, cover, p)
				out[len(out)-1].Training = 5
				for _, place := range []string{"mailbox-first", "mailbox-middle"} {
					add(id+"-"+place, "peer", "control", place, "concurrent", 2, 0, 0, 6, 0, cover, p)
				}
			}
		}
		for _, p := range []int64{0, 33250000} {
			add("mail-P"+decimal(int(p))+"-defaults", "peer", "defaults-control", "mailbox", "concurrent", 1, 0, 0, 8, 0, false, p)
			out[len(out)-1].Settings = defaultsSettings(p)
		}
		out = append(out, boundaryCoordinates()...)
	}
	return out
}

func decimal(n int) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func defaultPlan(c Config, tree, binary string) Plan {
	p := Plan{Schema: planSchema, Revision: c.Revision, Tree: tree, BinarySHA256: binary, Phase: c.Phase, Suite: c.Suite.String(), Set: c.Set, ModelFamily: Family{modelIDs(), 13, .05, .05, .8, "first-chain"}, DifferenceFamily: Family{differenceIDs(), 13, .05, .05, .8, "repeat-paired-exact-signed-rank"}, Configurations: canonicalCoordinates(c.Set), WindowsNS: []int64{1000000000, 2000000000, 5000000000, 10000000000, 20000000000}, BinNS: 100000000, PayloadBytes: 128, SeedDomainVersion: 22, FeatureVersion: featureVersion, SegmentsNS: [4]int64{0, 10000000000, 20000000000, 30000000000}, Limits: canonicalLimits(), Deadlines: canonicalDeadlines(), Simulations: 10000, Bootstrap: 2000, ExactMax: 512, Clock: "CLOCK_MONOTONIC-same-kernel", ClockResolutionMaxNS: 10000, ExemptionReason: "owned loopback processes share one source IP"}
	p.TransformDigest = publicHash([]byte(transformDescription))
	return p
}

const transformDescription = "mailbox18-release-v2;number=floor(u32/256),cap4095;delta=floor(mod32/256),cap4095;gaps=floor(ns/5000000),cap4095;residual=floor(nearest-period-ns/1000000),lower-ties;fetch=floor(min(ns,30000000000)/10000000);duration=floor(ns/10000),cap4095;support=64,4,half;columns=18"

func publicHash(b []byte) string {
	p, _ := suite.New(jcrypto.SuiteC25519)
	return hex.EncodeToString(p.Hash(b))
}

func ValidatePlan(p Plan) error {
	if p.Schema != planSchema || !revisionPattern.MatchString(p.Revision) || !revisionPattern.MatchString(p.Tree) || !digestPattern.MatchString(p.BinarySHA256) || p.Digest != "" && !digestPattern.MatchString(p.Digest) || p.ParentDigest != "" && !digestPattern.MatchString(p.ParentDigest) {
		return ErrInvalid
	}
	if p.MainSeedCommitment != "" && (!digestPattern.MatchString(p.MainSeedCommitment) || p.ParentDigest == "" || !mainSeedReadyPlan(p)) || p.Phase == Primary && p.MainSeedCommitment == "" {
		return ErrInvalid
	}
	if p.Phase != Structural && p.ParentDigest == "" {
		return ErrInvalid
	}
	c := Config{Set: p.Set, Phase: p.Phase, Revision: p.Revision, PlanPath: "registered"}
	var e error
	c.Suite, e = suite.Parse(p.Suite)
	if e != nil || c.validate() != nil {
		return ErrInvalid
	}
	canonical := defaultPlan(c, p.Tree, p.BinarySHA256)
	if !reflect.DeepEqual(p.ModelFamily, canonical.ModelFamily) || !reflect.DeepEqual(p.DifferenceFamily, canonical.DifferenceFamily) || !reflect.DeepEqual(p.WindowsNS, canonical.WindowsNS) || p.BinNS != canonical.BinNS || p.PayloadBytes != 128 || p.SeedDomainVersion != 22 || p.FeatureVersion != featureVersion || p.TransformDigest != canonical.TransformDigest || p.SegmentsNS != canonical.SegmentsNS || p.Limits != canonical.Limits || p.Deadlines != canonical.Deadlines || p.Simulations != 10000 || p.Bootstrap != 2000 || p.ExactMax != 512 || p.Clock != canonical.Clock || p.ClockResolutionMaxNS != 10000 || p.ExemptionReason != canonical.ExemptionReason {
		return ErrInvalid
	}
	if len(p.Configurations) != len(canonical.Configurations) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for i, r := range p.Configurations {
		want := canonical.Configurations[i]
		if seen[r.ID] || r.ID != want.ID {
			return ErrInvalid
		}
		seen[r.ID] = true
		if r.Slots != want.Slots {
			if r.Slots < 2048 || r.Slots > 1048576 || r.Slots%32 != 0 || want.Slots == 0 || want.ID == "M1" {
				return ErrInvalid
			}
			want.Slots = r.Slots
		}
		if want.Settings.ControlProfile != 0 {
			if r.Main != 0 || r.Training != 0 || r.Pilots != 0 {
				return ErrInvalid
			}
		} else if r.Main < 30 || r.Main > 512 {
			return ErrInvalid
		}
		want.Main = r.Main
		if !reflect.DeepEqual(r, want) || r.Settings.validate(r.Topology == "peer") != nil {
			return ErrInvalid
		}
	}
	if p.Phase == Primary && p.Suite == "c25519" && (p.Set == Compromise && !p.ModelReady || p.Set != Compromise && !p.PilotReady || p.Set == Mailbox && !p.TrainingReady) {
		return ErrInvalid
	}
	if len(p.FrozenModels) > 8 || p.TrainingReady && len(p.FrozenModels) != 8 {
		return ErrInvalid
	}
	if len(p.FrozenModels) > 0 {
		if len(p.FrozenModels) > 8 {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, m := range p.FrozenModels {
			key := m.Configuration + "/" + m.Population
			coordinateKnown := false
			for _, coordinate := range canonicalCoordinates(Mailbox) {
				if coordinate.Population == "classifier" && m.Configuration == coordinate.ID {
					coordinateKnown = true
				}
			}
			if !coordinateKnown || seen[key] || !digestPattern.MatchString(m.Digest) || m.Population != "request" && m.Population != "record" {
				return ErrInvalid
			}
			seen[key] = true
		}
	}
	if p.PilotReady {
		if len(p.Powers) != 13 {
			return ErrInvalid
		}
		for i, x := range p.Powers {
			if x.ID != differenceIDs()[i] || x.N < 30 || x.N > 512 || x.Simulations != 10000 || x.Successes < 8000 || x.Successes > 10000 || len(x.PilotX) != 5 || len(x.PilotY) != 5 {
				return ErrInvalid
			}
		}
	}
	if p.Digest != "" {
		copyPlan := p
		copyPlan.Digest = ""
		b, e := json.Marshal(copyPlan)
		if e != nil || p.Digest != publicHash(b) {
			return ErrInvalid
		}
	}
	return nil
}

func strictJSON(r io.Reader, v any) error {
	b, e := io.ReadAll(io.LimitReader(r, 8<<20))
	if e != nil || len(b) == 8<<20 {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if e = validateJSONShape(d, v); e != nil {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func loadPlan(path string, c Config, tree, binary string) (Plan, error) {
	f, e := os.Open(path)
	if e != nil {
		return Plan{}, ErrInvalid
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return Plan{}, ErrInvalid
	}
	var p Plan
	if strictJSON(f, &p) != nil || p.Digest == "" || ValidatePlan(p) != nil {
		return Plan{}, ErrInvalid
	}
	if p.Revision != c.Revision || p.Tree != tree || p.BinarySHA256 != binary || p.Suite != c.Suite.String() || p.Set != c.Set {
		return Plan{}, ErrInvalid
	}
	if c.Phase == Primary {
		commitment, err := mainSeedCommitment(p, c.Seed)
		if err != nil || p.MainSeedCommitment == "" || p.MainSeedCommitment != commitment {
			return Plan{}, ErrInvalid
		}
	} else if p.MainSeedCommitment != "" {
		return Plan{}, ErrInvalid
	}
	return p, nil
}

var buildRevision, buildTree string

func sourceIdentity(c Config) (string, string, error) {
	rev := buildRevision
	tree := buildTree
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, s := range b.Settings {
			if s.Key == "vcs.revision" && rev == "" {
				rev = s.Value
			}
			if s.Key == "vcs.modified" && s.Value == "true" && c.Phase != Structural {
				return "", "", ErrInvalid
			}
		}
	}
	if rev != "" && rev != c.Revision {
		return "", "", ErrInvalid
	}
	if tree == "" {
		return "", "", ErrInvalid
	}
	if !revisionPattern.MatchString(tree) {
		return "", "", ErrInvalid
	}
	exe, e := os.Executable()
	if e != nil {
		return "", "", ErrInvalid
	}
	b, e := os.ReadFile(exe)
	if e != nil {
		return "", "", ErrInvalid
	}
	return tree, publicHash(b), nil
}

func adjacentFile(path, name string) (string, error) {
	base, e := filepath.Abs(filepath.Dir(path))
	if e != nil {
		return "", ErrInvalid
	}
	resolved, e := filepath.EvalSymlinks(base)
	if e != nil || resolved != base {
		return "", ErrInvalid
	}
	target := filepath.Join(base, name)
	if filepath.Dir(target) != base || strings.Contains(name, "..") || filepath.IsAbs(name) {
		return "", ErrInvalid
	}
	if st, e := os.Lstat(target); e == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalid
	}
	return target, nil
}

func sortedUnique(a []string) bool {
	return sort.StringsAreSorted(a) && len(a) == len(compactStrings(a))
}
func compactStrings(a []string) []string {
	out := make([]string, 0, len(a))
	for _, v := range a {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}

func validatePlanning(ctx context.Context, p Plan) error {
	if e := ValidatePlan(p); e != nil {
		return e
	}
	select {
	case <-ctx.Done():
		return fail(ReasonCancelled)
	default:
		return validateRegisteredPlanning(ctx, p)
	}
}
