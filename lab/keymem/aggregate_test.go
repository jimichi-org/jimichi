package keymem

import (
	"errors"
	"math"
	"reflect"
	"testing"
)

func aggregateTestRow(status string, started bool, matches [3]uint64) Trial {
	row := newTrial(validTestConfig(), plannedCell{ID: 1, Policy: "none", Checkpoint: "active"})
	row.Started = started
	row.terminal(status)
	if status == "evaluated" {
		any := false
		for i, n := range matches {
			row.Keys[i].Matches = pointer(n)
			any = any || n != 0
		}
		row.AnyMatch = pointer(any)
	}
	return row
}

func assertRatio(t *testing.T, got *float64, want float64) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatal("incorrect evaluated-trial proportion")
	}
}

func assertStatistics(t *testing.T, got Statistics, min, max *uint64, sum, samples uint64) {
	t.Helper()
	if !reflect.DeepEqual(got.Min, min) || !reflect.DeepEqual(got.Max, max) || got.Sum != sum || got.SampleCount != samples {
		t.Fatalf("incorrect statistics: %+v", got)
	}
}

func TestAggregateKnownAnswer(t *testing.T) {
	rows := []Trial{
		aggregateTestRow("evaluated", true, [3]uint64{1, 0, 0}),
		aggregateTestRow("evaluated", true, [3]uint64{}),
		aggregateTestRow("capture_incomplete", true, [3]uint64{}),
		aggregateTestRow("control_failed", true, [3]uint64{}),
	}
	rows[3].CleanupError = pointer("fixture_cleanup_failed")
	result, err := aggregate(rows)
	if err != nil {
		t.Fatal(err)
	}
	s := result["c25519/none/active"]
	// four started trials minus two exclusions gives two evaluated; one positive gives 1/2
	if len(result) != 1 || s.Planned != 4 || s.Started != 4 || s.Evaluated != 2 || s.Excluded != 2 || s.NotStarted != 0 || s.TrialsWithAnyMatch != 1 {
		t.Fatal("incorrect four-trial counters")
	}
	if !reflect.DeepEqual(s.ExcludedByStatus, map[string]uint64{"capture_incomplete": 1, "control_failed": 1}) || !reflect.DeepEqual(s.CleanupErrors, map[string]uint64{"fixture_cleanup_failed": 1}) {
		t.Fatal("exclusion or cleanup populations are inconsistent")
	}
	assertRatio(t, s.AnyMatchProportion, 0.5)
	for i, h := range s.Hops {
		want := float64(0)
		if i == 0 {
			want = 0.5
			if h.TrialsWithMatch != 1 || h.TotalOccurrences != 1 || !reflect.DeepEqual(h.OccurrenceHistogram, map[uint64]uint64{0: 1, 1: 1}) || *h.MinOccurrences != 0 || *h.MaxOccurrences != 1 {
				t.Fatal("incorrect first-hop occurrences")
			}
		} else if h.TrialsWithMatch != 0 || h.TotalOccurrences != 0 || !reflect.DeepEqual(h.OccurrenceHistogram, map[uint64]uint64{0: 2}) || *h.MinOccurrences != 0 || *h.MaxOccurrences != 0 {
			t.Fatal("evaluated zero matches were omitted")
		}
		if h.Class != "cell" || h.Hop != i {
			t.Fatal("hop identity changed")
		}
		assertRatio(t, h.Proportion, want)
	}
	rows = append(rows, aggregateTestRow("not_started", false, [3]uint64{}))
	result, err = aggregate(rows)
	if err != nil {
		t.Fatal(err)
	}
	s = result["c25519/none/active"]
	// adding one unstarted row gives planned 5 = started 4 + unstarted 1 = evaluated 2 + excluded 3
	if s.Planned != 5 || s.Started != 4 || s.NotStarted != 1 || s.Evaluated != 2 || s.Excluded != 3 || s.ExcludedByStatus["not_started"] != 1 {
		t.Fatal("unstarted row changed denominators")
	}
	assertRatio(t, s.AnyMatchProportion, 0.5)
}

func TestAggregateZeroEvaluatedAndEmpty(t *testing.T) {
	rows := []Trial{aggregateTestRow("fixture_failed", false, [3]uint64{}), aggregateTestRow("not_started", false, [3]uint64{})}
	result, err := aggregate(rows)
	if err != nil {
		t.Fatal(err)
	}
	s := result["c25519/none/active"]
	// no evaluated trials means an undefined proportion, never a measured zero
	if s.Evaluated != 0 || s.Excluded != 2 || s.Started != 0 || s.NotStarted != 2 || s.AnyMatchProportion != nil {
		t.Fatal("zero-denominator condition was treated as absence")
	}
	for _, h := range s.Hops {
		if h.Proportion != nil || h.TotalOccurrences != 0 || h.MinOccurrences != nil || h.MaxOccurrences != nil || len(h.OccurrenceHistogram) != 0 {
			t.Fatal("empty hop population was not null")
		}
	}
	for _, members := range []map[string]Statistics{s.Coverage, s.Timing} {
		for _, v := range members {
			assertStatistics(t, v, nil, nil, 0, 0)
		}
	}
	result, err = aggregate(nil)
	if err != nil || len(result) != 0 {
		t.Fatal("empty input invented a condition")
	}
}

type aggregateMember struct {
	name   string
	timing bool
	set    func(*Trial, *uint64)
}

func aggregateMembers() []aggregateMember {
	return []aggregateMember{
		{"stream_bytes", false, func(r *Trial, v *uint64) { r.StreamBytes = v }},
		{"object_records", false, func(r *Trial, v *uint64) { r.ObjectRecords = v }},
		{"object_bytes", false, func(r *Trial, v *uint64) { r.ObjectBytes = v }},
		{"unscored_blob_bytes", false, func(r *Trial, v *uint64) { r.UnscoredBlobBytes = v }},
		{"echo_ready_ns", true, func(r *Trial, v *uint64) { r.Timing.EchoReadyNS = v }},
		{"close_duration_ns", true, func(r *Trial, v *uint64) { r.Timing.CloseDurationNS = v }},
		{"close_to_capture_ns", true, func(r *Trial, v *uint64) { r.Timing.CloseToCaptureNS = v }},
		{"capture_duration_ns", true, func(r *Trial, v *uint64) { r.Timing.CaptureDurationNS = v }},
	}
}

func memberStatistics(s ConditionSummary, member aggregateMember) Statistics {
	if member.timing {
		return s.Timing[member.name]
	}
	return s.Coverage[member.name]
}

func TestAggregateEveryNumericPopulation(t *testing.T) {
	for _, member := range aggregateMembers() {
		t.Run(member.name, func(t *testing.T) {
			for _, tt := range []struct {
				name          string
				first, second *uint64
				min, max      *uint64
				sum, count    uint64
			}{
				{"one-reached", pointer(uint64(100)), nil, pointer(uint64(100)), pointer(uint64(100)), 100, 1},
				{"seven-and-null", pointer(uint64(7)), nil, pointer(uint64(7)), pointer(uint64(7)), 7, 1},
				{"none-reached", nil, nil, nil, nil, 0, 0},
				{"reached-zero", pointer(uint64(0)), nil, pointer(uint64(0)), pointer(uint64(0)), 0, 1},
				{"two-reached", pointer(uint64(100)), pointer(uint64(0)), pointer(uint64(0)), pointer(uint64(100)), 100, 2},
			} {
				t.Run(tt.name, func(t *testing.T) {
					rows := []Trial{aggregateTestRow("evaluated", true, [3]uint64{}), aggregateTestRow("evaluated", true, [3]uint64{}), aggregateTestRow("parse_invalid", true, [3]uint64{})}
					member.set(&rows[0], tt.first)
					member.set(&rows[1], tt.second)
					member.set(&rows[2], pointer(uint64(10000)))
					result, err := aggregate(rows)
					if err != nil {
						t.Fatal(err)
					}
					s := result["c25519/none/active"]
					// only non-null evaluated values enter every statistic; the failed value 10000 never enters
					assertStatistics(t, memberStatistics(s, member), tt.min, tt.max, tt.sum, tt.count)
					if len(s.Coverage) != 4 || len(s.Timing) != 4 || s.ExcludedByStatus["parse_invalid"] != 1 {
						t.Fatal("exact summary members or failed-row accounting changed")
					}
				})
			}
		})
	}
}

func TestAggregateMixedConditions(t *testing.T) {
	rows := []Trial{aggregateTestRow("evaluated", true, [3]uint64{2, 3, 0}), aggregateTestRow("evaluated", true, [3]uint64{1, 0, 0}), aggregateTestRow("parse_invalid", true, [3]uint64{})}
	rows[0].StreamBytes = pointer(uint64(100))
	rows[1].Suite, rows[1].Policy, rows[1].Checkpoint = "gost", "all", "closed-1s"
	rows[1].StreamBytes = pointer(uint64(700))
	rows[2].StreamBytes = pointer(uint64(10000))
	result, err := aggregate(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatal("conditions were merged")
	}
	a, b := result["c25519/none/active"], result["gost/all/closed-1s"]
	assertStatistics(t, a.Coverage["stream_bytes"], pointer(uint64(100)), pointer(uint64(100)), 100, 1)
	assertStatistics(t, b.Coverage["stream_bytes"], pointer(uint64(700)), pointer(uint64(700)), 700, 1)
	if a.Planned != 2 || a.Excluded != 1 || b.Planned != 1 || b.Excluded != 0 || a.Hops[0].TotalOccurrences != 2 || b.Hops[0].TotalOccurrences != 1 || a.Hops[1].TotalOccurrences != 3 {
		t.Fatal("condition-specific counts leaked across groups")
	}
}

func TestAggregateOverflowAndInvalidOutcomes(t *testing.T) {
	if _, err := add(math.MaxUint64, 1); !errors.Is(err, errControllerFailed) {
		t.Fatal("counter overflow wrapped")
	}
	s := Statistics{Sum: math.MaxUint64}
	if !errors.Is(s.sample(pointer(uint64(1))), errControllerFailed) {
		t.Fatal("sum overflow wrapped")
	}
	s = Statistics{SampleCount: math.MaxUint64}
	if !errors.Is(s.sample(pointer(uint64(0))), errControllerFailed) {
		t.Fatal("sample counter overflow wrapped")
	}
	for _, member := range aggregateMembers() {
		t.Run(member.name, func(t *testing.T) {
			rows := []Trial{aggregateTestRow("evaluated", true, [3]uint64{}), aggregateTestRow("evaluated", true, [3]uint64{})}
			member.set(&rows[0], pointer(uint64(math.MaxUint64)))
			member.set(&rows[1], pointer(uint64(1)))
			if _, err := aggregate(rows); !errors.Is(err, errControllerFailed) {
				t.Fatal("aggregate sum overflow wrapped")
			}
		})
	}
	rows := []Trial{aggregateTestRow("evaluated", true, [3]uint64{math.MaxUint64, 0, 0}), aggregateTestRow("evaluated", true, [3]uint64{1, 0, 0})}
	if _, err := aggregate(rows); !errors.Is(err, errControllerFailed) {
		t.Fatal("occurrence total overflow wrapped")
	}
	for _, edit := range []func(*Trial){
		func(r *Trial) { r.AnyMatch = nil },
		func(r *Trial) { r.Keys[0].Matches = nil },
		func(r *Trial) { r.Keys[0].Class = "probe" },
		func(r *Trial) { r.Keys[0].Hop = 1 },
	} {
		row := aggregateTestRow("evaluated", true, [3]uint64{})
		edit(&row)
		if _, err := aggregate([]Trial{row}); !errors.Is(err, errControllerFailed) {
			t.Fatal("incomplete evaluated outcomes accepted")
		}
	}
}
