package keymem

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type Protection struct {
	RequestedPolicy            string `json:"requested_policy"`
	EffectivePolicy            string `json:"effective_policy"`
	Offheap                    bool   `json:"offheap"`
	Lock                       bool   `json:"lock"`
	Dontdump                   bool   `json:"dontdump"`
	Zero                       bool   `json:"zero"`
	Dumpable                   uint64 `json:"dumpable"`
	CoreSoft                   uint64 `json:"core_soft"`
	CoreHard                   uint64 `json:"core_hard"`
	MemlockSoft                uint64 `json:"memlock_soft"`
	MemlockHard                uint64 `json:"memlock_hard"`
	ProtectedAllocationsLocked *bool  `json:"protected_allocations_locked"`
}

type Timing struct {
	EchoReadyNS       *uint64 `json:"echo_ready_ns"`
	CloseDurationNS   *uint64 `json:"close_duration_ns"`
	CloseToCaptureNS  *uint64 `json:"close_to_capture_ns"`
	CaptureDurationNS *uint64 `json:"capture_duration_ns"`
}

type GC struct {
	EchoReady     *uint32 `json:"echo_ready"`
	BeforeCapture *uint32 `json:"before_capture"`
	AfterCapture  *uint32 `json:"after_capture"`
}

type Key struct {
	Class   string  `json:"class"`
	Hop     int     `json:"hop"`
	Matches *uint64 `json:"matches"`
}

type Trial struct {
	Schema                  string      `json:"schema"`
	ID                      uint64      `json:"id"`
	Repeat                  int         `json:"repeat"`
	Order                   int         `json:"order"`
	Suite                   string      `json:"suite"`
	Policy                  string      `json:"policy"`
	Checkpoint              string      `json:"checkpoint"`
	Status                  string      `json:"status"`
	ErrorClass              *string     `json:"error_class"`
	CleanupError            *string     `json:"cleanup_error"`
	Started                 bool        `json:"started"`
	EchoOK                  *bool       `json:"echo_ok"`
	Runtime                 *string     `json:"runtime"`
	Protection              *Protection `json:"protection"`
	SelectedCount           *uint64     `json:"selected_count"`
	AEADUses                *[3]uint64  `json:"aead_uses"`
	ActiveLengths           *[3]uint64  `json:"active_lengths"`
	ReleasedLengths         *[3]uint64  `json:"released_lengths"`
	Timing                  Timing      `json:"timing"`
	NumGC                   GC          `json:"num_gc"`
	ParseComplete           *bool       `json:"parse_complete"`
	StreamBytes             *uint64     `json:"stream_bytes"`
	ObjectRecords           *uint64     `json:"object_records"`
	ObjectBytes             *uint64     `json:"object_bytes"`
	UnscoredBlobBytes       *uint64     `json:"unscored_blob_bytes"`
	PositiveOK              *bool       `json:"positive_ok"`
	NegativeOK              *bool       `json:"negative_ok"`
	PrimaryStorageExclusion *string     `json:"primary_storage_exclusion"`
	Keys                    [3]Key      `json:"keys"`
	AnyMatch                *bool       `json:"any_match"`
}

func newTrial(c Config, cell plannedCell) Trial {
	t := Trial{Schema: schema, ID: cell.ID, Repeat: cell.Repeat, Order: cell.Order, Suite: c.Suite.String(), Policy: cell.Policy, Checkpoint: cell.Checkpoint}
	for i := range t.Keys {
		t.Keys[i] = Key{Class: "cell", Hop: i}
	}
	return t
}

func (t *Trial) terminal(status string) {
	t.Status = status
	if status == "evaluated" {
		t.ErrorClass = nil
		return
	}
	t.ErrorClass = pointer(status)
	t.AnyMatch = nil
	for i := range t.Keys {
		t.Keys[i].Matches = nil
	}
}

type Statistics struct {
	Min         *uint64 `json:"min"`
	Max         *uint64 `json:"max"`
	Sum         uint64  `json:"sum"`
	SampleCount uint64  `json:"sample_count"`
}

type HopSummary struct {
	Class               string            `json:"class"`
	Hop                 int               `json:"hop"`
	TrialsWithMatch     uint64            `json:"trials_with_match"`
	Proportion          *float64          `json:"proportion"`
	TotalOccurrences    uint64            `json:"total_occurrences"`
	MinOccurrences      *uint64           `json:"min_occurrences"`
	MaxOccurrences      *uint64           `json:"max_occurrences"`
	OccurrenceHistogram map[uint64]uint64 `json:"occurrence_histogram"`
}

type ConditionSummary struct {
	Planned            uint64                `json:"planned"`
	Started            uint64                `json:"started"`
	Evaluated          uint64                `json:"evaluated"`
	Excluded           uint64                `json:"excluded"`
	NotStarted         uint64                `json:"not_started"`
	ExcludedByStatus   map[string]uint64     `json:"excluded_by_status"`
	CleanupErrors      map[string]uint64     `json:"cleanup_errors"`
	TrialsWithAnyMatch uint64                `json:"trials_with_any_match"`
	AnyMatchProportion *float64              `json:"any_match_proportion"`
	Hops               [3]HopSummary         `json:"hops"`
	Coverage           map[string]Statistics `json:"coverage"`
	Timing             map[string]Statistics `json:"timing"`
}

type Environment struct {
	KernelRelease string `json:"kernel_release"`
	NumCPU        int    `json:"num_cpu"`
	GOMAXPROCS    int    `json:"gomaxprocs"`
	GOGC          string `json:"gogc"`
	GOMEMLIMIT    string `json:"gomemlimit"`
}

type Manifest struct {
	Schema            string             `json:"schema"`
	View              string             `json:"view"`
	Revision          string             `json:"revision"`
	BinaryDigest      *string            `json:"binary_digest"`
	BinaryDigestSuite string             `json:"binary_digest_suite"`
	Suite             string             `json:"suite"`
	Seed              int64              `json:"seed"`
	Repeats           int                `json:"repeats"`
	PlannedOrder      []plannedCell      `json:"planned_order"`
	Checkpoints       []string           `json:"checkpoints"`
	Policies          []string           `json:"policies"`
	StartedUTC        string             `json:"started_utc"`
	FinishedUTC       string             `json:"finished_utc"`
	GOOS              string             `json:"goos"`
	GOARCH            string             `json:"goarch"`
	Runtime           string             `json:"runtime"`
	Environment       Environment        `json:"environment"`
	Workload          map[string]any     `json:"workload"`
	Bounds            map[string]uint64  `json:"bounds"`
	Protection        ManifestProtection `json:"protection"`
	Limitations       []string           `json:"limitations"`
	Planned           uint64             `json:"planned"`
	Started           uint64             `json:"started"`
	Evaluated         uint64             `json:"evaluated"`
	Completion        string             `json:"completion"`
}

type ManifestProtection struct {
	Controller       *Protection            `json:"controller"`
	TargetConditions map[string]*Protection `json:"target_conditions"`
}

type Report struct {
	Manifest Manifest
	Trials   []Trial
	Summary  map[string]ConditionSummary
}

func newReport(c Config) Report {
	cells := plan(c)
	r := Report{Manifest: Manifest{
		Schema: schema, View: view, Revision: c.Revision, Suite: c.Suite.String(),
		BinaryDigestSuite: c.Suite.String(), Seed: c.Seed, Repeats: c.Repeats,
		PlannedOrder: cells, Checkpoints: []string{"active", "closed-now", "closed-1s"}, Policies: []string{"none", "all"},
		StartedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		GOOS:       runtime.GOOS, GOARCH: runtime.GOARCH, Runtime: runtime.Version(), Planned: uint64(len(cells)),
		Protection:  ManifestProtection{TargetConditions: map[string]*Protection{"none": nil, "all": nil}},
		Environment: Environment{NumCPU: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), GOGC: "runtime_default", GOMEMLIMIT: "runtime_default"},
		Workload: map[string]any{
			"payload_label": "jimichi/keymem/v1", "payload_bytes": len("jimichi/keymem/v1"),
			"hops": 3, "mode": "Immediate", "echo": true, "verified_ca_fixture": true,
			"pinned_authenticated_links": true, "separate_link_onion_roles": true, "rotation": false,
		},
		Bounds: map[string]uint64{
			"trial_timeout_ns": uint64(trialTimeout), "stream_bytes": maxStreamBytes,
			"records": 1000000, "fields_per_record": 1000000, "metadata_bytes": 1 << 20,
			"memprof_stack": 100000, "scratch_bytes": 64 << 10, "config_bytes": maxConfigBytes,
			"status_body_bytes": maxStatusBytes, "status_stream_bytes": maxStatusStream,
			"oracle_bytes": 144, "capture_body_bytes": 76,
		},
		Limitations: []string{
			"object payloads in one structurally parsed voluntary Go runtime export only",
			"not all process memory or an independently complete Go heap inventory",
			"no external acquisition, disk, swap, stacks, globals, mmap payloads or transformed-state recognition",
			"non-observation means the selected exact representation was not observed in the evaluated object payloads",
			"protected primary mmap storage lies outside this view",
			"combined policy comparison does not isolate locking, zeroing, offheap or dontdump",
			"instrumentation may induce compiler/runtime export copies; additional matches are unattributed",
			"runtime writes ignore return values; structural validity does not prove complete capture",
			"independent cross-sectional children do not establish erasure or an erasure deadline",
		},
	}}
	for _, cell := range cells {
		r.Trials = append(r.Trials, newTrial(c, cell))
	}
	return r
}

func (r *Report) finish() error {
	r.Manifest.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	r.Manifest.Started = 0
	r.Manifest.Evaluated = 0
	for _, t := range r.Trials {
		if t.Started {
			r.Manifest.Started++
		}
		if t.Status == "evaluated" {
			r.Manifest.Evaluated++
		}
		if t.Protection != nil {
			r.Manifest.Protection.TargetConditions[t.Policy] = t.Protection
		}
	}
	var err error
	r.Summary, err = aggregate(r.Trials)
	r.Manifest.Completion = "partial"
	if err != nil {
		return errControllerFailed
	}
	if r.Manifest.Evaluated == r.Manifest.Planned {
		r.Manifest.Completion = "complete"
		return nil
	}
	return errControllerFailed
}

func (r Report) Write(out string) (string, error) {
	if err := os.MkdirAll(out, 0700); err != nil {
		return "", errControllerFailed
	}
	dir, err := os.MkdirTemp(out, "keymem-")
	if err != nil {
		return "", errControllerFailed
	}
	write := func(name string, value any, rows bool) error {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errControllerFailed
		}
		e := json.NewEncoder(f)
		if rows {
			for _, row := range r.Trials {
				if err = e.Encode(row); err != nil {
					break
				}
			}
		} else {
			err = e.Encode(value)
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return errControllerFailed
		}
		return nil
	}
	if err = write("manifest.json", r.Manifest, false); err != nil {
		return dir, err
	}
	if err = write("trials.jsonl", nil, true); err != nil {
		return dir, err
	}
	if err = write("summary.json", r.Summary, false); err != nil {
		return dir, err
	}
	return dir, nil
}
