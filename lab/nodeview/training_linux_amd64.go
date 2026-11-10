//go:build linux && amd64

package nodeview

import "time"

func trainingChild(c *childIO) error {
	w := encoder{}
	w.u8(c.role)
	w.u8(byte(c.suite))
	w.u16(0)
	w.u8(1)
	if e := c.status.send(opBoot, w); e != nil {
		return e
	}
	var rows []encodedTrainingRow
	complete, joined := false, false
	header := false
	defer func() {
		for i := range rows {
			rows[i].wipe()
		}
	}()
	for {
		r, e := c.receive(opTrain)
		if e != nil {
			return e
		}
		version := r.u8()
		kind := r.u8()
		if version != 2 {
			return fail(ReasonIPC)
		}
		switch kind {
		case 0:
			if header {
				return fail(ReasonIPC)
			}
			header = true
			complete, joined = r.bool(), r.bool()
			if r.end() != nil {
				return fail(ReasonIPC)
			}
		case 1:
			if !header {
				return fail(ReasonIPC)
			}
			n := int(r.u16())
			if n < 1 || n > 512 || len(rows)+n > maxTrainingRows {
				return fail(ReasonLimit)
			}
			for range n {
				row := encodedTrainingRow{}
				for j := range row.Values {
					row.Values[j] = int16(r.u16())
				}
				row.Positive = r.bool()
				row.Conversation = r.u16()
				row.OriginalSeal = r.bool()
				if !validEncodedMailboxRow(row.Values) {
					return fail(ReasonIPC)
				}
				rows = append(rows, row)
			}
			if r.end() != nil {
				return fail(ReasonIPC)
			}
		case 255:
			if !header || r.end() != nil {
				return fail(ReasonIPC)
			}
			training := trainMailbox(rows, featureVersion, complete, joined)
			if c.role == roleTrainer {
				w = encodeTraining(training)
				if e := c.view.send(opTrained, w); e != nil {
					return e
				}
			} else {
				w = encoder{}
				w.u8(2)
				w.bool(training.Releasable && training.Support.RAMConformance && training.Support.Stable)
				w.u8(reasonByte(Reason(training.Reason)))
				w.u32(uint32(len(rows)))
				if e := c.view.send(opFitCheck, w); e != nil {
					return e
				}
			}
			if e = c.terminal(Counts{}, ReasonNone); e != nil {
				return e
			}
			for i := range rows {
				rows[i].wipe()
			}
			return c.cleaned()
		default:
			return fail(ReasonIPC)
		}
	}
}

func encodeTraining(t MailboxTraining) encoder {
	w := encoder{}
	w.bool(t.Releasable)
	w.u8(reasonByte(Reason(t.Reason)))
	s := t.Support
	for _, a := range [][2]int{s.Rows, s.Conversations, s.LargestConversation, s.OriginalSeals} {
		for _, v := range a {
			w.u32(uint32(v))
		}
	}
	w.bool(s.CompleteClean)
	w.bool(s.LabelsJoined)
	w.bool(s.RAMConformance)
	w.bool(s.Stable)
	if !t.Releasable {
		return w
	}
	if !validateMailboxTraining(t) {
		w.bad = true
		return w
	}
	encodeModel(&w, t.Model)
	x := t.Witness
	w.u32(uint32(x.Count))
	for _, v := range x.ClassCount {
		w.u32(uint32(v))
	}
	for _, a := range x.ClassSum {
		for _, v := range a {
			w.i64(v)
		}
	}
	for _, v := range x.Sum {
		w.i64(v)
	}
	for _, a := range x.Cross {
		for _, v := range a {
			w.i64(v)
		}
	}
	for _, v := range x.Minimum {
		w.u16(uint16(v))
	}
	for _, v := range x.Maximum {
		w.u16(uint16(v))
	}
	for _, a := range x.Scatter {
		for _, v := range a {
			w.f64(v)
		}
	}
	for _, v := range x.Scale {
		w.f64(v)
	}
	for _, a := range x.Cholesky {
		for _, v := range a {
			w.f64(v)
		}
	}
	w.u16(uint16(len(x.Kept)))
	for _, v := range x.Kept {
		w.u8(byte(v))
	}
	w.u16(uint16(len(x.Unused)))
	for _, v := range x.Unused {
		w.u8(byte(v))
	}
	return w
}

func decodeTraining(r *decoder) (MailboxTraining, error) {
	t := MailboxTraining{FeatureVersion: featureVersion, Releasable: r.bool(), Reason: string(decodeReason(r))}
	s := &t.Support
	for _, a := range []*[2]int{&s.Rows, &s.Conversations, &s.LargestConversation, &s.OriginalSeals} {
		for i := range a {
			a[i] = int(r.u32())
		}
	}
	s.CompleteClean, s.LabelsJoined, s.RAMConformance, s.Stable = r.bool(), r.bool(), r.bool(), r.bool()
	if !t.Releasable {
		if r.end() != nil {
			return t, fail(ReasonIPC)
		}
		return t, nil
	}
	t.Model = decodeModel(r)
	x := &MailboxFitWitness{FeatureVersion: featureVersion, Count: int(r.u32())}
	t.Witness = x
	for i := range x.ClassCount {
		x.ClassCount[i] = int(r.u32())
	}
	for i := range x.ClassSum {
		for j := range x.ClassSum[i] {
			x.ClassSum[i][j] = r.i64()
		}
	}
	for i := range x.Sum {
		x.Sum[i] = r.i64()
	}
	for i := range x.Cross {
		for j := range x.Cross[i] {
			x.Cross[i][j] = r.i64()
		}
	}
	for i := range x.Minimum {
		x.Minimum[i] = int16(r.u16())
	}
	for i := range x.Maximum {
		x.Maximum[i] = int16(r.u16())
	}
	for i := range x.Scatter {
		for j := range x.Scatter[i] {
			x.Scatter[i][j] = r.f64()
		}
	}
	for i := range x.Scale {
		x.Scale[i] = r.f64()
	}
	for i := range x.Cholesky {
		for j := range x.Cholesky[i] {
			x.Cholesky[i][j] = r.f64()
		}
	}
	n := int(r.u16())
	if n > 18 {
		return t, fail(ReasonIPC)
	}
	for range n {
		x.Kept = append(x.Kept, int(r.u8()))
	}
	n = int(r.u16())
	if n > 18 {
		return t, fail(ReasonIPC)
	}
	for range n {
		x.Unused = append(x.Unused, int(r.u8()))
	}
	if r.end() != nil || !validateMailboxTraining(t) {
		return t, fail(ReasonIPC)
	}
	return t, nil
}

func (f *fixture) train(rows []encodedTrainingRow, complete, joined bool) (MailboxTraining, error) {
	var trained MailboxTraining
	for _, role := range []byte{roleTrainer, roleFitAuditor} {
		reservation := uint64(len(rows))*512 + 8<<20
		if e := f.budget.reserve(reservation); e != nil {
			return trained, e
		}
		if e := f.budget.checkAllocation(reservation); e != nil {
			f.budget.release(reservation)
			return trained, e
		}
		f.scorerReservation += reservation
		ch, e := f.spawn(role, false)
		if e != nil {
			return trained, e
		}
		r, e := ch.expect(f.ctx, opBoot, time.Now().Add(30*time.Second))
		if e != nil {
			return trained, e
		}
		if r.u8() != role || r.u8() != byte(f.suite) || r.u16() != 0 || r.u8() != 1 || r.end() != nil {
			return trained, fail(ReasonIPC)
		}
		w := encoder{budget: f.budget}
		w.u8(2)
		w.u8(0)
		w.bool(complete)
		w.bool(joined)
		if e := ch.writer.send(opTrain, w); e != nil {
			return trained, e
		}
		for at := 0; at < len(rows); {
			w = encoder{budget: f.budget}
			w.u8(2)
			w.u8(1)
			n := min(512, len(rows)-at)
			w.u16(uint16(n))
			for _, row := range rows[at : at+n] {
				for _, v := range row.Values {
					w.u16(uint16(v))
				}
				w.bool(row.Positive)
				w.u16(row.Conversation)
				w.bool(row.OriginalSeal)
			}
			if e := ch.writer.send(opTrain, w); e != nil {
				return trained, e
			}
			at += n
		}
		w = encoder{budget: f.budget}
		w.u8(2)
		w.u8(255)
		if e := ch.writer.send(opTrain, w); e != nil {
			return trained, e
		}
		if e = f.finishOne(ch); e != nil {
			return trained, e
		}
		f.budget.release(reservation)
		f.scorerReservation -= reservation
		if role == roleTrainer {
			trained = ch.training
		} else if trained.Releasable && !ch.fitOK {
			return MailboxTraining{}, fail(ReasonConformance)
		}
	}
	return trained, nil
}
