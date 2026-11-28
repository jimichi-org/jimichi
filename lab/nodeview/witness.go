package nodeview

import "math"

type latchSite uint8

const (
	siteGeneric latchSite = iota
	siteConnCap
	sitePortPair
	siteFramePending
	siteFramesCap
	siteTransportPending
	siteTransportCap
	siteCellsCap
	siteContextsCap
	siteSetupDuplicate
	siteInventoryContexts
	siteInventoryPending
	siteAssociatePending
	siteGenerationWrap
	siteArena
	siteTruthRecords
	siteEqualityWrap
	siteMailboxRecords
	siteKeyContexts
	siteCallbackOverflow
	siteLast = siteCallbackOverflow
)

var latchSiteNames = [...]string{"generic", "conn_cap", "port_pair", "frame_pending", "frames_cap", "transport_pending", "transport_cap", "cells_cap", "contexts_cap", "setup_duplicate", "inventory_contexts", "inventory_pending", "associate_pending", "generation_wrap", "arena", "truth_records", "equality_wrap", "mailbox_records", "key_contexts", "callback_overflow"}

func (s latchSite) String() string {
	if int(s) < len(latchSiteNames) {
		return latchSiteNames[s]
	}
	return "unknown"
}

const (
	phaseBeforeBegin uint8 = iota
	phaseLead
	phaseWindow
	phaseDrain
	phaseCleanup
	phaseLast = phaseCleanup
)

var phaseNames = [...]string{"pre", "lead", "window", "drain", "cleanup"}

func phaseName(p uint64) string {
	if p < uint64(len(phaseNames)) {
		return phaseNames[p]
	}
	return "unknown"
}

type latchRecord struct {
	set                                   bool
	site                                  latchSite
	phase                                 uint8
	at                                    int64
	connections, pending, contexts, cells uint64
	closedAgeNS                           uint64
}

func latchPhase(at int64, begun bool, epoch, cutoff int64, cleanup bool) uint8 {
	switch {
	case !begun:
		return phaseBeforeBegin
	case cleanup:
		return phaseCleanup
	case at < epoch:
		return phaseLead
	case at < cutoff:
		return phaseWindow
	}
	return phaseDrain
}

// two's complement of the signed distance from the epoch, so a latch in the lead decodes negative
func latchOffset(at, start int64) uint64 {
	if start == 0 {
		return 0
	}
	return uint64(at - start)
}

func residenceCounts(cells []cellView, measured func(int64) bool) (atLeast3500ms, atLeast7s, maxNS uint64) {
	for _, v := range cells {
		if v.stages&(stageInput|stageWritten) != stageInput|stageWritten || !measured(v.localTime) {
			continue
		}
		var d uint64
		if v.writeTime > v.inputTime {
			d = uint64(v.writeTime - v.inputTime)
		}
		if d >= 3500000000 {
			atLeast3500ms++
		}
		if d >= 7000000000 {
			atLeast7s++
		}
		maxNS = max(maxNS, d)
	}
	return atLeast3500ms, atLeast7s, maxNS
}

func deliverThirds(rows []mailboxObservation, start, cutoff int64) (earlyCalls, earlyNS, lateCalls, lateNS uint64) {
	if cutoff <= start {
		return 0, 0, 0, 0
	}
	third := (cutoff - start) / 3
	for _, o := range rows {
		if !o.Complete || o.ReturnNS < o.CallNS {
			continue
		}
		d := uint64(o.ReturnNS - o.CallNS)
		if o.CallNS >= start && o.CallNS < start+third {
			earlyCalls++
			earlyNS += d
		}
		if o.CallNS >= cutoff-third && o.CallNS < cutoff {
			lateCalls++
			lateNS += d
		}
	}
	return earlyCalls, earlyNS, lateCalls, lateNS
}

// a circuit holds two connections at its entry and middle relay and one at its exit
func routeConnections(routes [][3]uint8, rebuilt []uint64) ([5]uint64, bool) {
	var out [5]uint64
	if len(rebuilt) != len(routes) {
		return out, false
	}
	for i, route := range routes {
		if route[0] == route[1] || route[0] == route[2] || route[1] == route[2] {
			return [5]uint64{}, false
		}
		if rebuilt[i] == math.MaxUint64 {
			return [5]uint64{}, false
		}
		circuits := rebuilt[i] + 1
		for hop, node := range route {
			if node >= 5 {
				return [5]uint64{}, false
			}
			weight := uint64(2)
			if hop == 2 {
				weight = 1
			}
			if circuits > (math.MaxUint64-out[node])/weight {
				return [5]uint64{}, false
			}
			out[node] += circuits * weight
		}
	}
	return out, true
}
