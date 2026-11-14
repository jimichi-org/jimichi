package nodeview

import (
	"errors"
	"fmt"
)

type boundOrigin uint8
type boundUnit uint8

const (
	boundNone boundOrigin = iota
	boundViewConnections
	boundViewSetups
	boundViewCells
	boundViewMailbox
	boundViewReleases
	boundTruthMessages
	boundTruthSetups
	boundTruthSeals
	boundTruthRequests
	boundTruthFragments
	boundCohortMessages
	boundCohortSetups
	boundCohortSeals
	boundCohortRequests
	boundCohortFragments
	boundBudget
	boundHostHeadroom
	boundArenaSpace
	boundArenaRecord
	boundArenaGrowth
	boundArenaUnavailable
)
const (
	boundBytes boundUnit = iota + 1
	boundRecords
)

type boundDetail struct {
	origin                  boundOrigin
	unit                    boundUnit
	have, need, limit, high uint64
}
type boundedFailure struct {
	reason Reason
	detail boundDetail
}

func (e boundedFailure) canonicalReason() Reason {
	if e.reason == ReasonNone || !validReason(e.reason) {
		return ReasonChild
	}
	return e.reason
}
func (e boundedFailure) Error() string { return fail(e.canonicalReason()).Error() }
func (e boundedFailure) Unwrap() error { return fail(e.canonicalReason()) }

func validBoundDetail(d boundDetail) bool {
	if d.origin >= boundViewConnections && d.origin <= boundCohortFragments {
		return d.unit == boundRecords && d.need > 0 && d.high == d.have && (d.have > d.limit || d.need > d.limit-d.have)
	}
	if d.unit != boundBytes {
		return false
	}
	switch d.origin {
	case boundBudget:
		return d.high >= d.have && (d.have > d.limit || d.need > d.limit-d.have)
	case boundArenaSpace:
		return d.need > 0 && d.high >= d.have && (d.have > d.limit || d.need > d.limit-d.have)
	case boundHostHeadroom, boundArenaRecord:
		return d.have == 0 && d.high == 0 && d.need > d.limit
	case boundArenaGrowth:
		return d.need > 0 && d.high == d.have
	case boundArenaUnavailable:
		return d.need > 0 && d.have == 0 && d.limit == 0 && d.high == 0
	}
	return false
}

func boundEvidence(err error) (boundDetail, bool) {
	var e boundedFailure
	if err == nil || !errors.As(err, &e) || e.reason == ReasonNone || !validReason(e.reason) || !validBoundDetail(e.detail) {
		return boundDetail{}, false
	}
	return e.detail, true
}

func attachBound(err error, d boundDetail) error {
	if err == nil {
		return nil
	}
	if _, ok := boundEvidence(err); ok {
		return err
	}
	if !validBoundDetail(d) {
		return err
	}
	reason := reasonOf(err)
	if reason == ReasonNone || !validReason(reason) {
		return err
	}
	return boundedFailure{reason, d}
}

func carryBoundReason(err error, reason Reason) error {
	if reason == ReasonNone {
		return nil
	}
	d, _ := boundEvidence(err)
	return attachBound(fail(reason), d)
}

func recordBound(origin boundOrigin, have, need, limit int) error {
	return attachBound(fail(ReasonLimit), boundDetail{origin, boundRecords, uint64(have), uint64(need), uint64(limit), uint64(have)})
}

func boundOriginName(origin boundOrigin) string {
	switch origin {
	case boundViewConnections:
		return "parent-view-connections"
	case boundViewSetups:
		return "parent-view-setups"
	case boundViewCells:
		return "parent-view-cells"
	case boundViewMailbox:
		return "parent-view-mailbox"
	case boundViewReleases:
		return "parent-view-releases"
	case boundTruthMessages:
		return "parent-truth-messages"
	case boundTruthSetups:
		return "parent-truth-setups"
	case boundTruthSeals:
		return "parent-truth-seals"
	case boundTruthRequests:
		return "parent-truth-requests"
	case boundTruthFragments:
		return "parent-truth-fragments"
	case boundCohortMessages:
		return "parent-cohort-messages"
	case boundCohortSetups:
		return "parent-cohort-setups"
	case boundCohortSeals:
		return "parent-cohort-seals"
	case boundCohortRequests:
		return "parent-cohort-requests"
	case boundCohortFragments:
		return "parent-cohort-fragments"
	case boundBudget:
		return "managed-budget"
	case boundHostHeadroom:
		return "supported-host-headroom"
	case boundArenaSpace:
		return "arena-space"
	case boundArenaRecord:
		return "arena-record-size"
	case boundArenaGrowth:
		return "arena-growth"
	case boundArenaUnavailable:
		return "arena-unavailable"
	}
	return "unknown"
}

func formatBoundEvidence(err error) string {
	d, ok := boundEvidence(err)
	if !ok {
		return "bound=unknown"
	}
	unit := "bytes"
	if d.unit == boundRecords {
		unit = "records"
	}
	switch d.origin {
	case boundHostHeadroom, boundArenaRecord:
		return fmt.Sprintf("bound=%s unit=%s need=%d limit=%d", boundOriginName(d.origin), unit, d.need, d.limit)
	case boundArenaUnavailable:
		return fmt.Sprintf("bound=%s unit=%s need=%d", boundOriginName(d.origin), unit, d.need)
	default:
		return fmt.Sprintf("bound=%s unit=%s have=%d need=%d limit=%d high=%d", boundOriginName(d.origin), unit, d.have, d.need, d.limit, d.high)
	}
}
