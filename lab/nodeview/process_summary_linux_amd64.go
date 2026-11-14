//go:build linux && amd64

package nodeview

import (
	"math"
	"os"
	"syscall"
)

type processSummary struct {
	rawDenied
	mask   byte
	values [24]uint64
}

func (s processSummary) validate() error {
	if s.mask & ^byte(7) != 0 {
		return fail(ReasonIPC)
	}
	for group, bounds := range [][2]int{{0, 16}, {16, 23}, {23, 24}} {
		if s.mask&(1<<group) != 0 {
			continue
		}
		for _, value := range s.values[bounds[0]:bounds[1]] {
			if value != 0 {
				return fail(ReasonIPC)
			}
		}
	}
	for i, limit := range [...]uint64{relayArenaBytes, maxConnections, maxPendingFrames, maxContexts, maxLifecycles} {
		if s.values[18+i] > limit {
			return fail(ReasonLimit)
		}
	}
	return nil
}

func encodeProcessSummary(s processSummary) encoder {
	var out encoder
	if s.validate() != nil {
		out.bad = true
		return out
	}
	out.u8(6)
	out.u16(1)
	out.u8(1)
	out.u8(s.mask)
	for _, value := range s.values {
		out.u64(value)
	}
	return out
}

func decodeProcessSummary(in *decoder) (processSummary, error) {
	var out processSummary
	if in == nil || in.at < 0 || in.at > len(in.b) || len(in.b)-in.at != 197 {
		return out, fail(ReasonIPC)
	}
	if in.u8() != 6 || in.u16() != 1 || in.u8() != 1 {
		return out, fail(ReasonIPC)
	}
	out.mask = in.u8()
	for i := range out.values {
		out.values[i] = in.u64()
	}
	if err := in.end(); err != nil {
		return processSummary{}, err
	}
	if err := out.validate(); err != nil {
		return processSummary{}, err
	}
	return out, nil
}

type summaryAccumulator struct {
	rawDenied
	summary CaptureSummary
	maxRSS  uint64
	count   uint8
	mask    byte
	failed  bool
}

func (a *summaryAccumulator) add(s processSummary) error {
	if a.failed || a.count >= 5 {
		a.failed = true
		return fail(ReasonIPC)
	}
	if err := s.validate(); err != nil {
		a.failed = true
		return err
	}
	next := *a
	for i, value := range s.values[:16] {
		if math.MaxUint64-next.summary.ObservedStats[i] < value {
			a.failed = true
			return fail(ReasonLimit)
		}
		next.summary.ObservedStats[i] += value
	}
	if math.MaxUint64-next.summary.Calls < s.values[16] || math.MaxUint64-next.summary.CallbackNS < s.values[17] {
		a.failed = true
		return fail(ReasonLimit)
	}
	next.summary.Calls += s.values[16]
	next.summary.CallbackNS += s.values[17]
	next.summary.ArenaHighWater = max(next.summary.ArenaHighWater, s.values[18])
	next.summary.ConnectionsHighWater = max(next.summary.ConnectionsHighWater, s.values[19])
	next.summary.PendingHighWater = max(next.summary.PendingHighWater, s.values[20])
	next.summary.ContextsHighWater = max(next.summary.ContextsHighWater, s.values[21])
	next.summary.CellsHighWater = max(next.summary.CellsHighWater, s.values[22])
	next.maxRSS = max(next.maxRSS, s.values[23])
	if next.count == 0 {
		next.mask = 7
	}
	next.mask &= s.mask
	next.count++
	*a = next
	return nil
}

func (a *summaryAccumulator) result() (CaptureSummary, uint64, error) {
	if a.failed || a.count != 5 || a.mask != 7 {
		return a.summary, a.maxRSS, fail(ReasonIncomplete)
	}
	return a.summary, a.maxRSS, nil
}

func checkedStatsDelta(before, after [16]uint64) ([16]uint64, error) {
	var delta [16]uint64
	for i := range before {
		if after[i] < before[i] {
			return [16]uint64{}, fail(ReasonContract)
		}
		delta[i] = after[i] - before[i]
	}
	return delta, nil
}

func rssBytes(kib int64) (uint64, error) {
	if kib < 0 || uint64(kib) > math.MaxUint64/1024 {
		return 0, fail(ReasonLimit)
	}
	return uint64(kib) * 1024, nil
}

func selfRSS() (uint64, error) {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return 0, fail(ReasonIncomplete)
	}
	return rssBytes(usage.Maxrss)
}

func waitRSS(state *os.ProcessState) (uint64, error) {
	if state == nil {
		return 0, fail(ReasonIncomplete)
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage == nil {
		return 0, fail(ReasonIncomplete)
	}
	return rssBytes(usage.Maxrss)
}
