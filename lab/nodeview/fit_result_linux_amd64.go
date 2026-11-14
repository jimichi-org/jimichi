//go:build linux && amd64

package nodeview

import "time"

func latchFitRoleError(c *ownedChild) {
	c.dataMu.Lock()
	c.fitReason |= 128
	c.dataMu.Unlock()
}

func observedFitReaderError(c *ownedChild) error {
	for _, done := range [2]chan error{c.viewDone, c.truthDone} {
		select {
		case err := <-done:
			select {
			case done <- err:
			default:
			}
			if err != nil {
				return err
			}
		default:
		}
	}
	return nil
}

func (f *fixture) waitFitResult(ch *ownedChild, until time.Time) error {
	timer := time.NewTimer(max(time.Duration(0), time.Until(until)))
	defer timer.Stop()
	for ch.viewFrames.Load() < 1 {
		select {
		case err := <-ch.viewDone:
			select {
			case ch.viewDone <- err:
			default:
			}
			if err != nil {
				return err
			}
			return fail(ReasonIPC)
		case <-ch.viewProgress:
		case <-f.ctx.Done():
			return fail(ReasonCancelled)
		case <-timer.C:
			return fail(ReasonIPC)
		}
	}
	return nil
}

func validFitFailure(reason Reason) bool {
	switch reason {
	case ReasonSupport, ReasonContract, ReasonTraining, ReasonConformance, ReasonFitSensitive:
		return true
	}
	return false
}

func canonicalMailboxTraining(t *MailboxTraining, count uint32) bool {
	if t == nil || !validateMailboxTraining(*t) || t.Support.Rows[0]+t.Support.Rows[1] != int(count) {
		return false
	}
	if t.Releasable {
		return t.Reason == "" && t.Support.RAMConformance && t.Support.Stable
	}
	return !t.Support.Stable && validFitFailure(Reason(t.Reason)) && t.Support.RAMConformance == (Reason(t.Reason) == ReasonFitSensitive)
}

func validCommittedFitResult(c *ownedChild) bool {
	if c == nil || c.fitExpected>>63 != 1 || !c.fitSeen || !c.fitCommitted || c.fitReason&128 != 0 || uint32(c.fitExpected) > maxTrainingRows {
		return false
	}
	if c.role == roleTrainer {
		return canonicalMailboxTraining(&c.training, uint32(c.fitExpected))
	}
	if c.role != roleFitAuditor || c.fitCount != uint32(c.fitExpected) || c.fitCount > maxTrainingRows {
		return false
	}
	released := c.fitExpected>>32&1 != 0
	reason := uint8(c.fitExpected >> 33)
	return c.fitOK == released && c.fitReason == reason && (c.fitOK && c.fitReason == reasonByte(ReasonNone) || !c.fitOK && int(c.fitReason) < len(reasons) && validFitFailure(reasons[c.fitReason]))
}

func acceptFitRoleResult(c *ownedChild, r *decoder, decode func(*decoder) (MailboxTraining, error)) error {
	if c == nil || r == nil || decode == nil {
		return fail(ReasonIPC)
	}
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if c.fitSeen || c.fitExpected>>63 != 1 {
		c.fitReason |= 128
		return fail(ReasonIPC)
	}
	c.fitSeen = true
	if c.role == roleTrainer {
		training, err := decode(r)
		committed := false
		defer func() {
			if !committed {
				wipeMailboxTraining(&training)
			}
		}()
		if err != nil || !canonicalMailboxTraining(&training, uint32(c.fitExpected)) {
			return fail(ReasonIPC)
		}
		c.training = training
		c.fitCommitted = true
		committed = true
		return nil
	}
	if c.role != roleFitAuditor || r.u8() != 2 {
		return fail(ReasonIPC)
	}
	c.fitOK = r.bool()
	reason := decodeReason(r)
	c.fitReason = reasonByte(reason)
	c.fitCount = r.u32()
	if r.end() != nil {
		return fail(ReasonIPC)
	}
	c.fitCommitted = true
	if !validCommittedFitResult(c) {
		c.fitCommitted = false
		return fail(ReasonIPC)
	}
	return nil
}
