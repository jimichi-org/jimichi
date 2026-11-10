package nodeview

import "errors"

func semanticFailure(err error, fallback Reason) error {
	if err == nil {
		return nil
	}
	var structured failure
	if errors.As(err, &structured) {
		return err
	}
	if errors.Is(err, ErrUnsupported) {
		return err
	}
	return fail(fallback)
}

func mergeRuntimeFailure(current, next error) error {
	if next == nil {
		return current
	}
	if current == nil {
		return next
	}
	err := carryBoundReason(current, preferredRuntimeReason(reasonOf(current), reasonOf(next)))
	if _, ok := boundEvidence(err); !ok {
		if d, ok := boundEvidence(next); ok {
			err = attachBound(err, d)
		}
	}
	return err
}

func preferredRuntimeReason(current, next Reason) Reason {
	priority := func(reason Reason) int {
		switch reason {
		case ReasonContract, ReasonIPC, ReasonLabel, ReasonClock, ReasonLimit:
			return 5
		case ReasonChild, ReasonEnrollment:
			return 4
		case ReasonSetup, ReasonBroken, ReasonRefused:
			return 3
		case ReasonCancelled:
			return 1
		case ReasonNone:
			return 0
		default:
			return 2
		}
	}
	if priority(next) > priority(current) {
		return next
	}
	return current
}

func appendRuntimeReason(flags []Reason, reason Reason) []Reason {
	if reason == ReasonNone {
		return flags
	}
	for _, existing := range flags {
		if existing == reason {
			return flags
		}
	}
	return append(flags, reason)
}
