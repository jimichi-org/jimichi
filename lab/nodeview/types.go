package nodeview

import (
	"github.com/jimichi-org/jimichi/lab/metrics"
	"math"
)

type executionTask struct {
	plannedSides           int
	coordinate             Coordinate
	repeat                 int
	routes                 [][3]uint8
	foreign                []int
	missing                uint8
	structural, membership bool
}

type Number struct {
	Value  *float64 `json:"value"`
	Reason Reason   `json:"reason,omitempty"`
}

func number(v float64, r Reason) Number {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		if r == ReasonNone {
			r = ReasonIncomplete
		}
		return Number{Reason: r}
	}
	return Number{Value: &v}
}

type Counts struct {
	Planned           uint64 `json:"planned"`
	Attempted         uint64 `json:"attempted"`
	Refused           uint64 `json:"refused"`
	SetupFailed       uint64 `json:"setup_failed"`
	Established       uint64 `json:"established"`
	PreflightOK       uint64 `json:"preflight_ok"`
	MessageBearing    uint64 `json:"message_bearing"`
	Eligible          uint64 `json:"eligible"`
	Unanswered        uint64 `json:"unanswered"`
	Rebuilt           uint64 `json:"rebuilt"`
	Missing           uint64 `json:"missing"`
	LocalProcessed    uint64 `json:"local_processed"`
	TransportSealed   uint64 `json:"transport_sealed"`
	WriteComplete     uint64 `json:"write_complete"`
	TerminalUnwritten uint64 `json:"terminal_unwritten"`
	CutoffCensored    uint64 `json:"cutoff_censored"`
	Positive          uint64 `json:"positive"`
	Negative          uint64 `json:"negative"`
	Unknown           uint64 `json:"unknown"`
	Released          uint64 `json:"released"`
}

type CounterChecks struct {
	FirstChecked uint64 `json:"first_checked"`
	FirstFailed  uint64 `json:"first_failed"`
	Samples      uint64 `json:"samples"`
	Transitions  uint64 `json:"transitions"`
	Advanced     uint64 `json:"advanced"`
	Gaps         uint64 `json:"gaps"`
	Repeats      uint64 `json:"repeats"`
	Invalid      uint64 `json:"invalid"`
	Matched      uint64 `json:"matched"`
	ShiftChecks  uint64 `json:"shift_checks"`
	ShiftOK      uint64 `json:"shift_ok"`
	Missing      uint64 `json:"missing"`
	DirectionOK  uint64 `json:"direction_ok"`
	IndexOK      uint64 `json:"index_ok"`
	FirstOK      uint64 `json:"first_ok"`
}

type CaptureSummary struct {
	Counters             CounterChecks `json:"counter_checks"`
	Stages               [5]uint64     `json:"stages"`
	Roles                [3]uint64     `json:"roles"`
	NeighbourConfirmed   uint64        `json:"neighbour_confirmed"`
	NeighbourUnknown     uint64        `json:"neighbour_unknown"`
	NeighbourConflicting uint64        `json:"neighbour_conflicting"`
	Lifecycle            [6]uint64     `json:"lifecycle"`
	OperationLengths     [6]uint64     `json:"operation_lengths"`
	Calls                uint64        `json:"calls"`
	CallbackNS           uint64        `json:"callback_ns"`
	ArenaHighWater       uint64        `json:"arena_high_water"`
	ConnectionsHighWater uint64        `json:"connections_high_water"`
	PendingHighWater     uint64        `json:"pending_high_water"`
	ContextsHighWater    uint64        `json:"contexts_high_water"`
	CellsHighWater       uint64        `json:"cells_high_water"`
	ObservedStats        [16]uint64    `json:"relay_stats"`
}

type MethodResult struct {
	Method        string `json:"method"`
	WindowNS      int64  `json:"window_ns"`
	AUC           Number `json:"auc"`
	TopOne        Number `json:"top1"`
	TPR           Number `json:"tpr_at_fpr_001"`
	Candidates    int    `json:"candidates"`
	Partners      int    `json:"partners"`
	Undefined     int    `json:"undefined"`
	Impossible    int    `json:"impossible"`
	Made          int    `json:"made"`
	Wrong         int    `json:"wrong"`
	Censored      int    `json:"censored"`
	BootstrapLow  Number `json:"bootstrap_low"`
	BootstrapHigh Number `json:"bootstrap_high"`
}

type RunResult struct {
	QueueFalsePairs    uint64         `json:"queue_false_pairs"`
	RequestExclusions  [4]uint64      `json:"request_exclusions"`
	RecordClasses      [2]uint64      `json:"record_classes"`
	LinkingTimes       []LinkingTime  `json:"linking_times"`
	MembershipChecks   uint64         `json:"membership_checks"`
	MembershipRejected uint64         `json:"membership_rejected"`
	NoPartner          uint64         `json:"no_partner"`
	ModelComplete      bool           `json:"model_complete"`
	Touched            uint64         `json:"touched"`
	Ends               uint64         `json:"ends"`
	Configuration      string         `json:"configuration"`
	Repeat             int            `json:"repeat"`
	Phase              Phase          `json:"phase"`
	Seed               int64          `json:"seed"`
	Counts             Counts         `json:"counts"`
	Flags              []Reason       `json:"flags"`
	Capture            CaptureSummary `json:"capture"`
	RouteHistogram     []uint64       `json:"route_known_positions"`
	ContentFound       uint64         `json:"content_found_chains"`
	ContentMessages    uint64         `json:"content_found_messages"`
	MeasuredMessages   uint64         `json:"measured_messages"`
	Methods            []MethodResult `json:"methods"`
	SetupOverlap       uint64         `json:"setup_overlap"`
	QueueJoined        Number         `json:"queue_joined"`
	PutQ               Number         `json:"negative_no_put_q"`
	PutBaseline        Number         `json:"put_auc"`
	RequestLDA         Number         `json:"request_lda_auc"`
	RecordLDA          Number         `json:"record_lda_auc"`
	ClockResolutionNS  int64          `json:"clock_resolution_ns"`
	CostsNS            [7]int64       `json:"costs_ns"`
	MaxRSS             uint64         `json:"max_rss"`
}

type LinkingTime struct {
	Method   string `json:"method"`
	Seconds  Number `json:"seconds"`
	Censored bool   `json:"censored"`
}

type DescriptiveSummary struct {
	Configuration string `json:"configuration"`
	Method        string `json:"method"`
	WindowNS      int64  `json:"window_ns"`
	Runs          int    `json:"runs"`
	Defined       int    `json:"defined"`
	Failed        int    `json:"failed"`
	Missing       int    `json:"missing"`
	Median        Number `json:"median"`
	Low           Number `json:"low"`
	High          Number `json:"high"`
	Censored      int    `json:"censored"`
}

type Manifest struct {
	Resources          ResourcePoint `json:"resources"`
	BaseSeed           int64         `json:"base_seed"`
	Revision           string        `json:"revision"`
	Tree               string        `json:"tree"`
	BinarySHA256       string        `json:"binary_sha256"`
	Runtime            string        `json:"runtime"`
	Kernel             string        `json:"kernel"`
	Suite              string        `json:"suite"`
	Protection         string        `json:"protection"`
	Clock              string        `json:"clock"`
	LoadBefore         string        `json:"load_before"`
	LoadAfter          string        `json:"load_after"`
	LoopbackExemptions [4]int        `json:"loopback_exemptions"`
	ExemptionReason    string        `json:"exemption_reason"`
}

type Report struct {
	Planning            []PlanningResult `json:"planning"`
	Schema              string           `json:"schema"`
	Manifest            Manifest         `json:"manifest"`
	Plan                Plan             `json:"plan"`
	Runs                []RunResult      `json:"runs"`
	Audit               []RankAudit      `json:"audit"`
	Status              Reason           `json:"status"`
	Models              []FrozenModel    `json:"models"`
	ModelInference      []Inference      `json:"model_family"`
	DifferenceInference []Inference      `json:"difference_family"`
}

type PlanningResult struct {
	ID     string          `json:"id"`
	PilotX []float64       `json:"pilot_x"`
	PilotY []float64       `json:"pilot_y"`
	Power  PairedPowerPlan `json:"power"`
}

type RankBucket struct {
	Rank     int `json:"rank"`
	Positive int `json:"positive"`
	Negative int `json:"negative"`
	Category int `json:"category"`
}

type RankAudit struct {
	Configuration string         `json:"configuration"`
	Repeat        int            `json:"repeat"`
	Method        string         `json:"method"`
	WindowNS      int64          `json:"window_ns"`
	Seed          int64          `json:"seed"`
	Groups        [][]RankBucket `json:"groups"`
	TopOne        [][2]int       `json:"top1_contributions"`
	Made          int            `json:"made"`
	Wrong         int            `json:"wrong"`
}

type rawDenied struct{}

func (rawDenied) MarshalJSON() ([]byte, error) { return nil, ErrRawSerialization }
func (rawDenied) String() string               { return "nodeview: private" }
func (rawDenied) GoString() string             { return "nodeview: private" }

type publicConfig struct {
	roster            [5]uint16
	suite             uint8
	n, h              int
	controlled        []int
	settings          Settings
	binNS             int64
	windowsNS         []int64
	population        string
	epochNS, cutoffNS int64
}

type viewSet struct {
	rawDenied
	nodes []nodeView
}

type frozenTraining struct {
	request, record *metrics.Discriminant
}

type pairValue struct {
	first, second int
	value         float64
}
type predictedMethod struct {
	method   string
	windowNS int64
	values   []pairValue
	matches  []metrics.ViewEdge
}
type predictions struct {
	rawDenied
	methods             []predictedMethod
	layout              *predictionLayout
	seen                []uint64
	received, lastBatch int
}
type predictionLayout struct {
	linking              bool
	classifiers          [2]bool
	first, second, total int
	mail                 [2][][]int
	mailWindow           int64
}
