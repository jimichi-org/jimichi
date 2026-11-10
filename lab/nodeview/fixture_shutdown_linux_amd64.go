//go:build linux && amd64

package nodeview

import (
	"context"
	"io"
	"time"
)

func (f *fixture) captureReadyReaderCauses() {
	for _, child := range f.children {
		for _, done := range []<-chan error{child.viewDone, child.truthDone} {
			select {
			case err, ok := <-done:
				if !ok || err == nil {
					continue
				}
				reason := reasonOf(semanticFailure(err, ReasonChild))
				if reason == ReasonNone || !validReason(reason) {
					reason = ReasonChild
				}
				child.flags = appendRuntimeReason(child.flags, reason)
				if !validBoundDetail(f.closedBound) {
					if d, ok := boundEvidence(err); ok {
						f.closedBound = d
					}
				}
			default:
			}
		}
	}
}

func (f *fixture) freezeCauses(reason Reason) {
	f.closedCauses = appendRuntimeReason(f.closedCauses, reason)
	for _, child := range f.children {
		for _, known := range child.flags {
			f.closedCauses = appendRuntimeReason(f.closedCauses, known)
		}
		if child.waitErr != nil {
			f.closedCauses = appendRuntimeReason(f.closedCauses, ReasonChild)
		}
		queued := len(child.status)
		for range queued {
			select {
			case frame := <-child.status:
				if frame.err != nil {
					if frame.err != io.EOF {
						f.closedCauses = appendRuntimeReason(f.closedCauses, reasonOf(semanticFailure(frame.err, ReasonChild)))
					}
				} else if frame.op == opError {
					row := decoder{b: frame.body}
					known := decodeReason(&row)
					if row.end() != nil || known == ReasonNone {
						known = ReasonIPC
					}
					f.closedCauses = appendRuntimeReason(f.closedCauses, known)
				}
				clear(frame.body)
				child.statusBudget.release(frame.charged)
			default:
			}
		}
	}
}

func (f *fixture) closedFailure() error {
	reason := ReasonNone
	for _, known := range f.closedCauses {
		reason = preferredRuntimeReason(reason, known)
	}
	if reason == ReasonNone {
		return nil
	}
	return attachBound(fail(reason), f.closedBound)
}

func (f *fixture) causeSnapshot() []Reason {
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	return append([]Reason(nil), f.closedCauses...)
}

func (c *ownedChild) expectReady(ctx context.Context, kind byte, until time.Time) error {
	r, e := c.expect(ctx, opReady, until)
	if e != nil {
		return e
	}
	actual, success := r.u8(), r.bool()
	if r.end() != nil || actual != kind {
		return fail(ReasonIPC)
	}
	if success {
		return nil
	}
	r, e = c.expect(ctx, opError, until)
	if e != nil {
		return e
	}
	reason := decodeReason(r)
	if r.end() != nil || reason == ReasonNone {
		return fail(ReasonIPC)
	}
	c.flags = append(c.flags, reason)
	return fail(reason)
}

func (c *ownedChild) preflightFailure(r *decoder) error {
	reason := decodeReason(r)
	if r.end() != nil || reason == ReasonNone {
		return fail(ReasonIPC)
	}
	if reason != ReasonRefused {
		return fail(reason)
	}
	c.reason = reason
	return nil
}

func (f *fixture) shutdownDeadlines() (time.Time, time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.shutdownUntil.IsZero() {
		f.shutdownUntil = time.Now().Add(10 * time.Second)
		f.emergencyUntil = f.shutdownUntil.Add(2 * time.Second)
	}
	return f.shutdownUntil, f.emergencyUntil
}

func (f *fixture) sendStop(ch *ownedChild, reason byte, until time.Time) error {
	if ch.reaped || ch.stopSent {
		return nil
	}
	ch.stopSent = true
	remaining := time.Until(until)
	if remaining <= 0 {
		return fail(ReasonIPC)
	}
	ch.writer.setTimeout(remaining)
	w := encoder{budget: ch.writer.budget}
	w.u8(reason)
	return ch.writer.send(opStop, w)
}

func (f *fixture) collectWaits(until time.Time) bool {
	timer := time.NewTimer(max(time.Duration(0), time.Until(until)))
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		complete := true
		for _, ch := range f.children {
			if ch.reaped {
				continue
			}
			select {
			case e := <-ch.exited:
				ch.waitErr = e
				ch.reaped = true
				ch.watchOnce.Do(func() { close(ch.watchDone) })
			default:
				complete = false
			}
		}
		if complete {
			return true
		}
		select {
		case <-timer.C:
			return false
		case <-tick.C:
		}
	}
}

func (f *fixture) closeOutputs() {
	for _, ch := range f.children {
		ch.statusFile.Close()
		ch.viewFile.Close()
		ch.truthFile.Close()
	}
}

func (f *fixture) joinReaders(until time.Time) bool {
	for _, ch := range f.children {
		if !ch.joinReaders(until) {
			return false
		}
	}
	return true
}

func (ch *ownedChild) joinReaders(until time.Time) bool {
	if !ch.readersStarted {
		return true
	}
	for _, done := range []<-chan struct{}{ch.statusJoined, ch.viewJoined, ch.truthJoined} {
		select {
		case <-done:
			continue
		default:
		}
		timer := time.NewTimer(max(time.Duration(0), time.Until(until)))
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
			return false
		}
	}
	return true
}

func (f *fixture) joinReadersFinally() {
	for _, ch := range f.children {
		if ch.readersStarted {
			<-ch.statusJoined
			<-ch.viewJoined
			<-ch.truthJoined
		}
	}
}
