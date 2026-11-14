package nodeview

import (
	"math"
	"math/rand"
	"reflect"
	"runtime"
	"time"
	"unsafe"

	"github.com/jimichi-org/jimichi/lab"
)

type sourceReplayScratch struct {
	rawDenied
	rng [2]*rand.Rand
}

type sourceReplayStateLayout struct {
	rawDenied
	tap, feed int
	vec       [607]int64
}

func sourceAttemptCeiling() (uint32, error) {
	const setupBytes, messageBytes = uint64(3 * 45), uint64(165)
	if clientArenaBytes < setupBytes || maxIPCMessages <= 3 {
		return 0, fail(ReasonContract)
	}
	n := min(uint64(maxMessages), uint64(maxIPCMessages-3), (clientArenaBytes-setupBytes)/messageBytes)
	if n == 0 || n > math.MaxUint32 {
		return 0, fail(ReasonContract)
	}
	return uint32(n), nil
}

func sourceReplayBackingBytes() (uint64, error) {
	if runtime.Version() != "go1.27.4" || runtime.GOARCH != "amd64" || unsafe.Sizeof(int(0)) != 8 || unsafe.Sizeof(rand.Rand{}) != 48 || unsafe.Sizeof(sourceReplayStateLayout{}) != 4872 || unsafe.Sizeof(sourceReplayScratch{}) != 16 {
		return 0, fail(ReasonUnsupported)
	}
	// rngSource is noscan class 5376; Rand and the owner fit their scan classes without a malloc header
	return 2*5376 + 2*uint64(unsafe.Sizeof(rand.Rand{})) + uint64(unsafe.Sizeof(sourceReplayScratch{})), nil
}

func newSourceReplayScratch() (*sourceReplayScratch, error) {
	if _, e := sourceReplayBackingBytes(); e != nil {
		return nil, e
	}
	s := &sourceReplayScratch{}
	for i := range s.rng {
		source := rand.NewSource(0)
		t := reflect.TypeOf(source).Elem()
		if t.Name() != "rngSource" || t.PkgPath() != "math/rand" || t.Size() != 4872 || t.NumField() != 3 || t.Field(0).Offset != 0 || t.Field(1).Offset != 8 || t.Field(2).Offset != 16 {
			source.Seed(0)
			s.close()
			return nil, fail(ReasonUnsupported)
		}
		s.rng[i] = rand.New(source)
	}
	return s, nil
}

func (s *sourceReplayScratch) close() {
	if s == nil {
		return
	}
	for i, rng := range s.rng {
		if rng != nil {
			rng.Seed(0)
			s.rng[i] = nil
		}
	}
}

func (s *sourceReplayScratch) valid() bool {
	return s != nil && s.rng[0] != nil && s.rng[1] != nil && s.rng[0] != s.rng[1]
}

func sourceGapTime(next, end int64, gap float64) (int64, bool, error) {
	if next < 0 || end <= next {
		return 0, false, fail(ReasonClock)
	}
	if math.IsNaN(gap) || math.IsInf(gap, 0) || gap < 0 {
		return 0, false, fail(ReasonContract)
	}
	if gap >= float64(math.MaxInt64) {
		return 0, false, fail(ReasonLimit)
	}
	offset := int64(gap)
	// a half-open segment needs no absolute timestamp for its final overshooting draw
	if offset >= end-next {
		return 0, false, nil
	}
	if offset > math.MaxInt64-next {
		return 0, false, fail(ReasonLimit)
	}
	return next + offset, true, nil
}

func countPeerSource(gapSeed int64, limit uint32, scratch *sourceReplayScratch) (uint32, error) {
	ceiling, e := sourceAttemptCeiling()
	if e != nil {
		return 0, e
	}
	if limit == 0 || limit > ceiling || !scratch.valid() {
		return 0, fail(ReasonContract)
	}
	for j, start := range [2]int64{0, 20000000000} {
		scratch.rng[j].Seed(lab.Derive(gapSeed, uint64(start), 0, 0, 0))
	}
	var count uint32
	for j, segment := range [2][2]int64{{0, 10000000000}, {20000000000, 30000000000}} {
		for next := segment[0]; next < segment[1]; {
			if count == limit {
				return count, fail(ReasonLimit)
			}
			count++
			gap := scratch.rng[j].ExpFloat64() * float64(200*time.Millisecond)
			var more bool
			next, more, e = sourceGapTime(next, segment[1], gap)
			if e != nil {
				return count, e
			}
			if !more {
				break
			}
		}
	}
	return count, nil
}

func admitPeerSources(plans []workloadPlan, settings Settings, scratch *sourceReplayScratch) error {
	if !scratch.valid() || len(plans) > maxClients {
		return fail(ReasonContract)
	}
	ceiling, e := sourceAttemptCeiling()
	if e != nil {
		return e
	}
	var total uint64
	for _, plan := range plans {
		if plan.topology != 2 || settings.ControlProfile != 0 || plan.defaultsControl || plan.structural {
			continue
		}
		n, e := countPeerSource(plan.gapSeed, ceiling, scratch)
		if e != nil {
			return e
		}
		if total > maxMessages-uint64(n) {
			return fail(ReasonLimit)
		}
		total += uint64(n)
	}
	return nil
}

func acquireSourceReplay(c Config) (Config, bool, error) {
	return acquireSourceReplayWithResources(c, availableHostMemory, newSourceReplayScratch)
}

func acquireSourceReplayWithResources(c Config, probe func() (uint64, error), construct func() (*sourceReplayScratch, error)) (Config, bool, error) {
	if probe == nil || construct == nil {
		return c, false, fail(ReasonContract)
	}
	if c.sourceReplay != nil {
		if !c.sourceReplay.valid() {
			return c, false, fail(ReasonContract)
		}
		return c, false, nil
	}
	if _, e := sourceReplayBackingBytes(); e != nil {
		return c, false, e
	}
	const fixed = uint64(8 << 20)
	if c.retainedRawBytes > controllerArenaBytes-fixed {
		return c, false, fail(ReasonLimit)
	}
	available, e := probe()
	if e != nil {
		return c, false, e
	}
	if fixed > available {
		return c, false, fail(ReasonLimit)
	}
	c.sourceReplay, e = construct()
	return c, e == nil, e
}
