package nodeview

import (
	"math"
	"math/rand"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/jimichi-org/jimichi/lab"
)

func testSourceReplay(t *testing.T) *sourceReplayScratch {
	t.Helper()
	s, e := newSourceReplayScratch()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.close)
	return s
}

func TestSourceReplayOwnerLayoutAndReset(t *testing.T) {
	s := testSourceReplay(t)
	if n, e := sourceReplayBackingBytes(); e != nil || n != 10864 {
		t.Fatal("two physical RNG owners changed")
	}
	if n, e := sourceAttemptCeiling(); e != nil || n != 6354 || 6354*165+135 > clientArenaBytes || 6355*165+135 <= clientArenaBytes {
		t.Fatal("necessary complete-source ceiling changed")
	}
	for _, rng := range s.rng {
		v := reflect.ValueOf(rng).Elem()
		if v.Type().Size() != 48 || v.Field(0).Elem().Pointer() != v.Field(1).Elem().Pointer() {
			t.Fatal("Source and Source64 do not share one rngSource")
		}
	}
	first, second := s.rng[0], s.rng[1]
	_, _ = countPeerSource(899319231927783355, 6354, s)
	s.close()
	zero := rand.New(rand.NewSource(0))
	if s.valid() || s.rng != [2]*rand.Rand{} || first.Int63() != zero.Int63() {
		t.Fatal("first owner was not reset and dropped")
	}
	zero.Seed(0)
	if second.Int63() != zero.Int63() {
		t.Fatal("second owner was not reset")
	}
	s.close()
	if unsafe.Sizeof(sourceReplayStateLayout{}) != 4872 {
		t.Fatal("rngSource mirror drift")
	}
}

func TestSourceReplayRejectsInvalidOwnersLimitsAndDeniedAcquire(t *testing.T) {
	s := testSourceReplay(t)
	for _, limit := range []uint32{0, 6355, ^uint32(0)} {
		if _, e := countPeerSource(1, limit, s); reasonOf(e) != ReasonContract {
			t.Fatal("unbounded replay limit admitted")
		}
	}
	for _, scratch := range []*sourceReplayScratch{nil, {}, {rng: [2]*rand.Rand{s.rng[0], nil}}, {rng: [2]*rand.Rand{s.rng[0], s.rng[0]}}} {
		if _, e := countPeerSource(1, 1, scratch); reasonOf(e) != ReasonContract {
			t.Fatal("incomplete replay owner admitted")
		}
		if e := admitPeerSources(nil, peerSettings(false, 0), scratch); reasonOf(e) != ReasonContract {
			t.Fatal("admission concealed an invalid owner")
		}
	}
	denied, owned, e := acquireSourceReplay(Config{retainedRawBytes: controllerArenaBytes})
	if reasonOf(e) != ReasonLimit || owned || denied.sourceReplay != nil {
		t.Fatal("denied fixed reservation constructed an RNG owner")
	}
	borrowed, owned, e := acquireSourceReplay(Config{sourceReplay: s})
	if e != nil || owned || borrowed.sourceReplay != s {
		t.Fatal("defensive borrow allocated or replaced its invocation owner")
	}
}

func TestSourceReplayHostDenialPrecedesOwnedConstruction(t *testing.T) {
	for _, test := range []struct {
		name      string
		available uint64
		failure   error
		reason    Reason
	}{
		{"insufficient", (8 << 20) - 1, nil, ReasonLimit},
		{"unsupported", 0, ErrUnsupported, ReasonUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			probes, constructions := 0, 0
			c, owned, e := acquireSourceReplayWithResources(Config{}, func() (uint64, error) {
				probes++
				return test.available, test.failure
			}, func() (*sourceReplayScratch, error) {
				constructions++
				return newSourceReplayScratch()
			})
			defer c.sourceReplay.close()
			if probes != 1 || constructions != 0 || owned || c.sourceReplay != nil || reasonOf(e) != test.reason || test.failure != nil && e != test.failure {
				t.Fatal("host denial constructed or published the two-RNG owner")
			}
		})
	}
}

func TestSourceReplayAllRegisteredTuplesAndFullOffsets(t *testing.T) {
	type answer struct {
		phase                  Phase
		base, period           int64
		repeat, maximum, total int
	}
	answers := []answer{
		{Structural, 11701, 0, 0, 126, 1691}, {Structural, 11701, 33250000, 0, 130, 1644},
		{Train, 11703, 0, 0, 118, 1641}, {Train, 11703, 0, 1, 123, 1594}, {Train, 11703, 0, 2, 118, 1612}, {Train, 11703, 0, 3, 123, 1697}, {Train, 11703, 0, 4, 121, 1571},
		{Train, 11703, 33250000, 0, 124, 1678}, {Train, 11703, 33250000, 1, 124, 1634}, {Train, 11703, 33250000, 2, 113, 1614}, {Train, 11703, 33250000, 3, 114, 1575}, {Train, 11703, 33250000, 4, 124, 1620},
		{Pilot, 11702, 0, 0, 120, 1598}, {Pilot, 11702, 0, 1, 115, 1600}, {Pilot, 11702, 0, 2, 122, 1655}, {Pilot, 11702, 0, 3, 117, 1654}, {Pilot, 11702, 0, 4, 122, 1614},
		{Pilot, 11702, 33250000, 0, 118, 1632}, {Pilot, 11702, 33250000, 1, 119, 1666}, {Pilot, 11702, 33250000, 2, 120, 1630}, {Pilot, 11702, 33250000, 3, 113, 1586}, {Pilot, 11702, 33250000, 4, 115, 1655},
	}
	s := testSourceReplay(t)
	for _, answer := range answers {
		maximum, total := 0, 0
		for side := 15; side >= 0; side-- {
			seed := nodeSeed(Config{Phase: answer.phase, Seed: answer.base}, uint64(answer.period), uint64(answer.repeat), uint64(side), lab.StreamNodeGaps)
			n, e := countPeerSource(seed, 6354, s)
			if e != nil {
				t.Fatal(e)
			}
			maximum, total = max(maximum, int(n)), total+int(n)
			var expected uint32
			for j, segment := range [2][2]int64{{0, 10000000000}, {20000000000, 30000000000}} {
				fresh := newGapRand(seed, segment[0])
				// compare the state after every consumed gap, including the gap past the half-open cutoff
				s.rng[j].Seed(lab.Derive(seed, uint64(segment[0]), 0, 0, 0))
				for oldNext, newNext := segment[0], segment[0]; oldNext < segment[1]; {
					if oldNext != newNext {
						t.Fatal("reused RNG changed a nominal opportunity offset")
					}
					expected++
					oldNext += int64(fresh.ExpFloat64() * float64(200*time.Millisecond))
					candidate, more, e := sourceGapTime(newNext, segment[1], s.rng[j].ExpFloat64()*float64(200*time.Millisecond))
					if e != nil || more != (oldNext < segment[1]) {
						t.Fatal("checked gap changed the original half-open termination")
					}
					if !more {
						break
					}
					newNext = candidate
					if oldNext != newNext {
						t.Fatal("Seed reset changed gap conversion or segment state")
					}
				}
				// countPeerSource must consume this exact sequence, with no extra or missed draw
				next := fresh.Int63()
				if _, e := countPeerSource(seed, 6354, s); e != nil || s.rng[j].Int63() != next {
					t.Fatal("replay consumed a different number of gaps")
				}
			}
			if expected != n {
				t.Fatal("replay count differs from the full original offset sequence")
			}
		}
		if maximum != answer.maximum || total != answer.total {
			t.Fatalf("registered tuple %s/%d/%d: maximum=%d total=%d", answer.phase, answer.period, answer.repeat, maximum, total)
		}
	}
}

func TestSourceGapTimeHalfOpenBoundariesAndCheckedConversion(t *testing.T) {
	for _, row := range []struct {
		next, end int64
		gap       float64
		want      int64
		more      bool
	}{
		{0, 10, 0, 0, true}, {0, 10, .999, 0, true}, {10, 20, 9.999, 19, true}, {10, 20, 10, 0, false}, {10, 20, 100, 0, false},
		{math.MaxInt64 - 100, math.MaxInt64 - 10, 200, 0, false},
		{math.MaxInt64 - 100, math.MaxInt64, 100, 0, false},
		{math.MaxInt64 - 100, math.MaxInt64, 99, math.MaxInt64 - 1, true},
	} {
		if next, more, e := sourceGapTime(row.next, row.end, row.gap); e != nil || next != row.want || more != row.more {
			t.Fatal("zero gap, truncation, exact cutoff or finite overshoot changed")
		}
	}
	for _, row := range []struct {
		next, end int64
		gap       float64
		reason    Reason
	}{
		{0, 10, math.NaN(), ReasonContract}, {0, 10, math.Inf(1), ReasonContract}, {0, 10, -1, ReasonContract},
		{0, 10, float64(math.MaxInt64), ReasonLimit}, {0, 10, math.MaxFloat64, ReasonLimit},
		{-1, 10, 1, ReasonClock}, {10, 10, 0, ReasonClock}, {math.MaxInt64, math.MinInt64, 1, ReasonClock},
	} {
		if _, _, e := sourceGapTime(row.next, row.end, row.gap); reasonOf(e) != row.reason {
			t.Fatal("invalid conversion or required time wrapped")
		}
	}
}

type zeroGapSource struct{ calls int }

func (s *zeroGapSource) Int63() int64 { s.calls++; return 0 }
func (s *zeroGapSource) Seed(int64)   { s.calls = 0 }

func TestSourceReplayZeroGapsStillHaveFiniteGrantTermination(t *testing.T) {
	first, second := &zeroGapSource{}, &zeroGapSource{}
	s := &sourceReplayScratch{rng: [2]*rand.Rand{rand.New(first), rand.New(second)}}
	defer s.close()
	if n, e := countPeerSource(1, 8, s); n != 8 || reasonOf(e) != ReasonLimit || first.calls != 8 || second.calls != 0 {
		t.Fatal("legal zero gaps escaped the finite source grant")
	}
}

func TestSourceReplayNegativeWitnessAndNoPerSideAllocation(t *testing.T) {
	s := testSourceReplay(t)
	const side0, side1 = int64(899319231927783355), int64(1132114638519365038)
	if n, e := countPeerSource(side0, 128, s); n != 128 || reasonOf(e) != ReasonLimit {
		t.Fatal("real negative grant lost its refused next opportunity")
	}
	for _, seed := range []int64{side1, side0, side0, side1} {
		want := uint32(129)
		if seed == side1 {
			want = 91
		}
		if n, e := countPeerSource(seed, 6354, s); e != nil || n != want {
			t.Fatal("reused owner changed fixed negative schedule")
		}
	}
	var counts [2]int
	var last int64
	for j, segment := range [2][2]int64{{0, 10000000000}, {20000000000, 30000000000}} {
		rng := newGapRand(side0, segment[0])
		for next := segment[0]; next < segment[1]; {
			counts[j]++
			last = next
			next += int64(rng.ExpFloat64() * 200000000)
		}
	}
	if counts != [2]int{64, 65} || last != 29998867961 {
		t.Fatal("last refused opportunity changed")
	}
	plans := []workloadPlan{{topology: 2, gapSeed: side0, sourceLimit: 128}, {topology: 2, gapSeed: side1, sourceLimit: 128}}
	if allocations := testing.AllocsPerRun(20, func() {
		if _, e := countPeerSource(side0, 6354, s); e != nil {
			panic(e)
		}
		if e := admitPeerSources(plans, peerSettings(false, 0), s); e != nil {
			panic(e)
		}
	}); allocations != 0 {
		t.Fatal("cold replay allocates per side or task")
	}
}
