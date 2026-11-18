package nodeview

import "sync"

const resourceScope = "owned-process-peaks-through-finalization-v1"

type ResourcePoint struct {
	Scope  string  `json:"scope"`
	MaxRSS *uint64 `json:"max_rss"`
	Reason Reason  `json:"reason,omitempty"`
}

type resourceUsage struct {
	mu      sync.Mutex
	pending uint64
	peak    uint64
	reason  Reason
}

type resourceTicket struct {
	once  sync.Once
	usage *resourceUsage
}

func (u *resourceUsage) start() *resourceTicket {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	u.pending++
	u.mu.Unlock()
	return &resourceTicket{usage: u}
}

func (t *resourceTicket) record(peak uint64, usageErr error) {
	if t == nil || t.usage == nil {
		return
	}
	t.once.Do(func() {
		u := t.usage
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.pending == 0 {
			u.reason = ReasonContract
			return
		}
		u.pending--
		if usageErr != nil {
			reason := reasonOf(usageErr)
			if reason == ReasonNone || !validReason(reason) {
				reason = ReasonIncomplete
			}
			if u.reason == ReasonNone {
				u.reason = reason
			}
			return
		}
		u.peak = max(u.peak, peak)
	})
}

func (u *resourceUsage) snapshot(controllerPeak uint64, sampleErr error) ResourcePoint {
	point := ResourcePoint{Scope: resourceScope}
	if u != nil {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.pending != 0 {
			point.Reason = ReasonChild
			return point
		}
		if u.reason != ReasonNone {
			point.Reason = u.reason
			return point
		}
		controllerPeak = max(controllerPeak, u.peak)
	}
	if sampleErr != nil {
		point.Reason = reasonOf(sampleErr)
		if point.Reason == ReasonNone || !validReason(point.Reason) {
			point.Reason = ReasonIncomplete
		}
		return point
	}
	value := controllerPeak
	point.MaxRSS = &value
	return point
}

func validResourcePoint(p ResourcePoint) bool {
	if p.Scope != resourceScope || !validReason(p.Reason) {
		return false
	}
	if p.MaxRSS != nil {
		return p.Reason == ReasonNone
	}
	return p.Reason != ReasonNone
}
