package nodeview

import (
	"encoding/json"
	"errors"
)

type Reason string

func (r Reason) MarshalJSON() ([]byte, error) {
	if !validReason(r) {
		return nil, ErrInvalid
	}
	return json.Marshal(string(r))
}

const (
	ReasonNone         Reason = ""
	ReasonSetup        Reason = "setup_failed"
	ReasonBroken       Reason = "flow_broken"
	ReasonRefused      Reason = "refused"
	ReasonLimit        Reason = "capture_limit"
	ReasonContract     Reason = "observation_contract"
	ReasonLabel        Reason = "label_mismatch"
	ReasonClock        Reason = "clock_invalid"
	ReasonIPC          Reason = "ipc_invalid"
	ReasonChild        Reason = "child_failed"
	ReasonCancelled    Reason = "cancelled"
	ReasonNoView       Reason = "no_view"
	ReasonNoPartner    Reason = "no_partner"
	ReasonNoPositive   Reason = "no_positive"
	ReasonNoNegative   Reason = "no_negative"
	ReasonMissingClass Reason = "missing_class"
	ReasonTraining     Reason = "training_degenerate"
	ReasonSupport      Reason = "training_support"
	ReasonFitSensitive Reason = "fit_audit_sensitive"
	ReasonProvenance   Reason = "provenance_timeout"
	ReasonCensored     Reason = "censored"
	ReasonIncomplete   Reason = "incomplete"
	ReasonPilot        Reason = "pilot_incomplete"
	ReasonPower        Reason = "power_unresolved"
	ReasonModelPower   Reason = "model_power_unresolved"
	ReasonPlanning     Reason = "planning_incomplete"
	ReasonUnsupported  Reason = "unsupported"
	ReasonConformance  Reason = "fit_conformance"
	ReasonEnrollment   Reason = "enrollment"
)

var reasons = []Reason{ReasonNone, ReasonSetup, ReasonBroken, ReasonRefused, ReasonLimit, ReasonContract, ReasonLabel, ReasonClock, ReasonIPC, ReasonChild, ReasonCancelled, ReasonNoView, ReasonNoPartner, ReasonNoPositive, ReasonNoNegative, ReasonMissingClass, ReasonTraining, ReasonSupport, ReasonFitSensitive, ReasonProvenance, ReasonCensored, ReasonIncomplete, ReasonPilot, ReasonPower, ReasonModelPower, ReasonPlanning, ReasonUnsupported, ReasonConformance, ReasonEnrollment}

var ErrInvalid = errors.New("nodeview: invalid")
var ErrUnsupported = errors.New("nodeview: unsupported")
var ErrRawSerialization = errors.New("nodeview: raw serialization forbidden")

type failure struct{ reason Reason }

func (e failure) Error() string { return "nodeview: " + string(e.reason) }
func fail(r Reason) error       { return failure{r} }
func reasonOf(e error) Reason {
	if e == nil {
		return ReasonNone
	}
	var f failure
	if errors.As(e, &f) {
		return f.reason
	}
	if errors.Is(e, ErrUnsupported) {
		return ReasonUnsupported
	}
	return ReasonIncomplete
}
