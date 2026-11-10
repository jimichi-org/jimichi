package nodeview

import "math"

type streamSize struct{ bytes, frames uint64 }

func (s *streamSize) add(records, width, batch uint64) error {
	if records == 0 {
		return nil
	}
	if batch == 0 || width > 0 && records > math.MaxUint64/width {
		return fail(ReasonLimit)
	}
	frames := (records-1)/batch + 1
	if frames > math.MaxUint64/33 {
		return fail(ReasonLimit)
	}
	bytes := records * width
	if bytes > math.MaxUint64-33*frames || s.bytes > math.MaxUint64-bytes-33*frames || s.frames > math.MaxUint64-frames {
		return fail(ReasonLimit)
	}
	s.bytes += bytes + 33*frames
	s.frames += frames
	return nil
}

func selectedStreamSize(node nodeView, transports int, aggregate bool) (streamSize, error) {
	var s streamSize
	for _, row := range [][3]uint64{{uint64(len(node.connections)), 25, 1}, {uint64(len(node.setups)), 65, 1}, {uint64(len(node.cells)), 81, 256}, {uint64(transports), 81, 256}, {uint64(len(node.releases)), 23, 256}} {
		if e := s.add(row[0], row[1], row[2]); e != nil {
			return s, e
		}
	}
	if e := s.add(uint64(len(node.mailbox)), 48, 128); e != nil {
		return s, e
	}
	for _, o := range node.mailbox {
		if o.record.size != 0 && o.record.size != 392 {
			return s, fail(ReasonContract)
		}
		s.bytes += uint64(o.record.size)
	}
	if aggregate {
		s.bytes += 227
		s.frames++
	}
	if s.bytes > relayArenaBytes || s.frames > maxIPCMessages {
		return s, fail(ReasonLimit)
	}
	return s, nil
}

func truthStreamSize(t privateTruth) (streamSize, error) {
	var s streamSize
	for _, row := range [][3]uint64{{uint64(len(t.messages)), 132, 1}, {uint64(len(t.setups)), 12, 1}, {uint64(len(t.seals)), 399, 128}, {uint64(len(t.requests)), 12, 128}, {uint64(len(t.fragments)), 7, 64}} {
		if e := s.add(row[0], row[1], row[2]); e != nil {
			return s, e
		}
	}
	for _, q := range t.requests {
		if q.record.size != 0 && q.record.size != 392 {
			return s, fail(ReasonContract)
		}
		if uint64(q.record.size) > math.MaxUint64-s.bytes {
			return s, fail(ReasonLimit)
		}
		s.bytes += uint64(q.record.size)
	}
	for _, f := range t.fragments {
		if f.data.size < 0 {
			return s, fail(ReasonContract)
		}
		if uint64(f.data.size) > math.MaxUint64-s.bytes {
			return s, fail(ReasonLimit)
		}
		s.bytes += uint64(f.data.size)
	}
	return s, nil
}
