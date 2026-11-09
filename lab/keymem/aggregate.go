package keymem

import "math"

func add(a, b uint64) (uint64, error) {
	if b > math.MaxUint64-a {
		return 0, errControllerFailed
	}
	return a + b, nil
}

func (s *Statistics) sample(value *uint64) error {
	if value == nil {
		return nil
	}
	var err error
	s.Sum, err = add(s.Sum, *value)
	if err != nil {
		return err
	}
	s.SampleCount, err = add(s.SampleCount, 1)
	if err != nil {
		return err
	}
	if s.Min == nil || *value < *s.Min {
		s.Min = pointer(*value)
	}
	if s.Max == nil || *value > *s.Max {
		s.Max = pointer(*value)
	}
	return nil
}

func aggregate(rows []Trial) (map[string]ConditionSummary, error) {
	out := make(map[string]ConditionSummary)
	for _, row := range rows {
		key := row.Suite + "/" + row.Policy + "/" + row.Checkpoint
		s, ok := out[key]
		if !ok {
			s = ConditionSummary{ExcludedByStatus: map[string]uint64{}, CleanupErrors: map[string]uint64{}, Coverage: map[string]Statistics{}, Timing: map[string]Statistics{}}
			for _, n := range []string{"stream_bytes", "object_records", "object_bytes", "unscored_blob_bytes"} {
				s.Coverage[n] = Statistics{}
			}
			for _, n := range []string{"echo_ready_ns", "close_duration_ns", "close_to_capture_ns", "capture_duration_ns"} {
				s.Timing[n] = Statistics{}
			}
			for i := range s.Hops {
				s.Hops[i] = HopSummary{Class: "cell", Hop: i, OccurrenceHistogram: map[uint64]uint64{}}
			}
		}
		inc := func(p *uint64) error { v, e := add(*p, 1); *p = v; return e }
		if err := inc(&s.Planned); err != nil {
			return nil, err
		}
		if row.Started {
			if err := inc(&s.Started); err != nil {
				return nil, err
			}
		} else {
			if err := inc(&s.NotStarted); err != nil {
				return nil, err
			}
		}
		if row.CleanupError != nil {
			v, e := add(s.CleanupErrors[*row.CleanupError], 1)
			if e != nil {
				return nil, e
			}
			s.CleanupErrors[*row.CleanupError] = v
		}
		if row.Status != "evaluated" {
			if err := inc(&s.Excluded); err != nil {
				return nil, err
			}
			v, e := add(s.ExcludedByStatus[row.Status], 1)
			if e != nil {
				return nil, e
			}
			s.ExcludedByStatus[row.Status] = v
			out[key] = s
			continue
		}
		if row.AnyMatch == nil {
			return nil, errControllerFailed
		}
		if err := inc(&s.Evaluated); err != nil {
			return nil, err
		}
		if *row.AnyMatch {
			if err := inc(&s.TrialsWithAnyMatch); err != nil {
				return nil, err
			}
		}
		for i, k := range row.Keys {
			if k.Matches == nil || k.Hop != i || k.Class != "cell" {
				return nil, errControllerFailed
			}
			h := &s.Hops[i]
			n := *k.Matches
			if n > 0 {
				if err := inc(&h.TrialsWithMatch); err != nil {
					return nil, err
				}
			}
			var e error
			h.TotalOccurrences, e = add(h.TotalOccurrences, n)
			if e != nil {
				return nil, e
			}
			if h.MinOccurrences == nil || n < *h.MinOccurrences {
				h.MinOccurrences = pointer(n)
			}
			if h.MaxOccurrences == nil || n > *h.MaxOccurrences {
				h.MaxOccurrences = pointer(n)
			}
			h.OccurrenceHistogram[n], e = add(h.OccurrenceHistogram[n], 1)
			if e != nil {
				return nil, e
			}
		}
		for n, v := range map[string]*uint64{"stream_bytes": row.StreamBytes, "object_records": row.ObjectRecords, "object_bytes": row.ObjectBytes, "unscored_blob_bytes": row.UnscoredBlobBytes} {
			x := s.Coverage[n]
			if e := x.sample(v); e != nil {
				return nil, e
			}
			s.Coverage[n] = x
		}
		for n, v := range map[string]*uint64{"echo_ready_ns": row.Timing.EchoReadyNS, "close_duration_ns": row.Timing.CloseDurationNS, "close_to_capture_ns": row.Timing.CloseToCaptureNS, "capture_duration_ns": row.Timing.CaptureDurationNS} {
			x := s.Timing[n]
			if e := x.sample(v); e != nil {
				return nil, e
			}
			s.Timing[n] = x
		}
		out[key] = s
	}
	for key, s := range out {
		if s.Evaluated > 0 {
			s.AnyMatchProportion = pointer(float64(s.TrialsWithAnyMatch) / float64(s.Evaluated))
			for i := range s.Hops {
				s.Hops[i].Proportion = pointer(float64(s.Hops[i].TrialsWithMatch) / float64(s.Evaluated))
			}
		}
		out[key] = s
	}
	return out, nil
}
