package metrics

import (
	"fmt"
	"math"
	"sort"
	"time"
)

type MarkObservation struct {
	Candidates   [][]time.Duration `json:"candidates"`
	CaptureStart time.Duration     `json:"capture_start"`
	CaptureEnd   time.Duration     `json:"capture_end"`
}

type MarkDetector struct {
	Code  []int8          `json:"code"`
	Slot  time.Duration   `json:"slot"`
	Lags  []time.Duration `json:"lags"`
	Alpha float64         `json:"alpha"`
}

type MarkDetection struct {
	CandidateScores          []float64       `json:"candidate_scores"`
	CandidateQuantizedScores []int64         `json:"candidate_quantized_scores"`
	BestLags                 []time.Duration `json:"best_lags"`
	EmptyPairs               [][]int         `json:"empty_pairs"`
	FamilyMaximum            int64           `json:"family_maximum"`
	ExtremeCodes             int             `json:"extreme_codes"`
	TotalCodes               int             `json:"total_codes"`
	PValue                   float64         `json:"p_value"`
	Decision                 string          `json:"decision"`
	SelectedCandidate        *int            `json:"selected_candidate"`
}

const (
	markScoreScale       = 1_000_000_000
	markMaxSymbols       = 12
	markMaxCandidates    = 64
	markMaxLags          = 1024
	markMaxContributions = 10_000_000
)

type markPair struct {
	aStart, aEnd time.Duration
	bStart, bEnd time.Duration
}

func DetectMark(observation MarkObservation, epoch time.Duration, detector MarkDetector) (MarkDetection, error) {
	total, err := validateMark(observation, epoch, detector)
	if err != nil {
		return MarkDetection{}, err
	}
	intervals := make([][]markPair, len(detector.Lags))
	for l, lag := range detector.Lags {
		intervals[l] = make([]markPair, len(detector.Code))
		for k := range detector.Code {
			start := epoch + time.Duration(4*k)*detector.Slot + lag
			intervals[l][k] = markPair{
				aStart: start,
				aEnd:   start + detector.Slot,
				bStart: start + 2*detector.Slot,
				bEnd:   start + 3*detector.Slot,
			}
		}
	}

	out := MarkDetection{
		CandidateScores:          make([]float64, len(observation.Candidates)),
		CandidateQuantizedScores: make([]int64, len(observation.Candidates)),
		BestLags:                 make([]time.Duration, len(observation.Candidates)),
		EmptyPairs:               make([][]int, len(observation.Candidates)),
		FamilyMaximum:            -markScoreScale - 1,
		TotalCodes:               total,
		Decision:                 "none",
	}
	contrasts := make([][][]float64, len(observation.Candidates))
	for j, timestamps := range observation.Candidates {
		contrasts[j] = make([][]float64, len(detector.Lags))
		out.EmptyPairs[j] = make([]int, len(detector.Lags))
		out.CandidateQuantizedScores[j] = -markScoreScale - 1
		for l, pairs := range intervals {
			contrasts[j][l] = make([]float64, len(detector.Code))
			for k, pair := range pairs {
				a := markCount(timestamps, pair.aStart, pair.aEnd)
				b := markCount(timestamps, pair.bStart, pair.bEnd)
				// disjoint intervals make a+b no larger than the timestamp slice
				if a+b == 0 {
					out.EmptyPairs[j][l]++
				} else {
					contrasts[j][l][k] = float64(b-a) / float64(a+b)
				}
			}
			q := markScore(contrasts[j][l], detector.Code)
			if q > out.CandidateQuantizedScores[j] {
				out.CandidateQuantizedScores[j] = q
				out.BestLags[j] = detector.Lags[l]
			}
		}
		out.CandidateScores[j] = float64(out.CandidateQuantizedScores[j]) / markScoreScale
		out.FamilyMaximum = max(out.FamilyMaximum, out.CandidateQuantizedScores[j])
	}
	forEachBalancedMarkCode(len(detector.Code), func(code []int8) {
		familyMaximum := int64(-markScoreScale - 1)
		for _, candidate := range contrasts {
			for _, contrast := range candidate {
				familyMaximum = max(familyMaximum, markScore(contrast, code))
			}
		}
		if familyMaximum >= out.FamilyMaximum {
			out.ExtremeCodes++
		}
	})
	out.PValue = float64(out.ExtremeCodes) / float64(out.TotalCodes)
	if out.PValue > detector.Alpha || out.FamilyMaximum <= 0 {
		return out, nil
	}
	selected, tied := 0, 0
	for j, score := range out.CandidateQuantizedScores {
		if score == out.FamilyMaximum {
			selected = j
			tied++
		}
	}
	if tied > 1 {
		out.Decision = "ambiguous"
	} else {
		out.Decision = "declared"
		out.SelectedCandidate = &selected
	}
	return out, nil
}

func validateMark(observation MarkObservation, epoch time.Duration, detector MarkDetector) (int, error) {
	k := len(detector.Code)
	if k == 0 || k%2 != 0 || k > markMaxSymbols {
		return 0, fmt.Errorf("mark: code length must be even and between 2 and %d", markMaxSymbols)
	}
	positive := 0
	for _, symbol := range detector.Code {
		if symbol != -1 && symbol != 1 {
			return 0, fmt.Errorf("mark: code symbols must be -1 or 1")
		}
		if symbol == 1 {
			positive++
		}
	}
	if positive != k/2 {
		return 0, fmt.Errorf("mark: code must be balanced")
	}
	if detector.Slot <= 0 {
		return 0, fmt.Errorf("mark: slot must be positive")
	}
	if !(detector.Alpha > 0 && detector.Alpha <= 1) || math.IsInf(detector.Alpha, 0) {
		return 0, fmt.Errorf("mark: alpha must be finite and in (0,1]")
	}
	if len(observation.Candidates) == 0 || len(observation.Candidates) > markMaxCandidates {
		return 0, fmt.Errorf("mark: candidate count must be between 1 and %d", markMaxCandidates)
	}
	if len(detector.Lags) == 0 || len(detector.Lags) > markMaxLags {
		return 0, fmt.Errorf("mark: lag count must be between 1 and %d", markMaxLags)
	}
	for l, lag := range detector.Lags {
		if lag < 0 || l > 0 && lag <= detector.Lags[l-1] {
			return 0, fmt.Errorf("mark: lags must be nonnegative and strictly increasing")
		}
	}
	total := 1
	for n := 1; n <= k/2; n++ {
		total = total * (k - n + 1) / n
	}
	if total*k*len(observation.Candidates)*len(detector.Lags) > markMaxContributions {
		return 0, fmt.Errorf("mark: exhaustive search exceeds %d symbol contributions", markMaxContributions)
	}
	if observation.CaptureStart >= observation.CaptureEnd {
		return 0, fmt.Errorf("mark: capture bounds must be increasing")
	}
	if detector.Slot > time.Duration(math.MaxInt64)/time.Duration(4*k-1) {
		return 0, fmt.Errorf("mark: interval duration overflows")
	}
	span := time.Duration(4*k-1) * detector.Slot
	last, ok := addMarkDuration(epoch, span)
	if !ok {
		return 0, fmt.Errorf("mark: interval epoch overflows")
	}
	last, ok = addMarkDuration(last, detector.Lags[len(detector.Lags)-1])
	if !ok {
		return 0, fmt.Errorf("mark: interval lag overflows")
	}
	first, ok := addMarkDuration(epoch, detector.Lags[0])
	if !ok {
		return 0, fmt.Errorf("mark: interval epoch overflows")
	}
	if first < observation.CaptureStart || last > observation.CaptureEnd {
		return 0, fmt.Errorf("mark: capture does not cover every searched interval")
	}
	for j, timestamps := range observation.Candidates {
		for i, timestamp := range timestamps {
			if timestamp < observation.CaptureStart || timestamp >= observation.CaptureEnd {
				return 0, fmt.Errorf("mark: candidate %d timestamp outside capture bounds", j)
			}
			if i > 0 && timestamp < timestamps[i-1] {
				return 0, fmt.Errorf("mark: candidate %d timestamps must be nondecreasing", j)
			}
		}
	}
	return total, nil
}

func addMarkDuration(a, b time.Duration) (time.Duration, bool) {
	if b > 0 && a > time.Duration(math.MaxInt64)-b || b < 0 && a < time.Duration(math.MinInt64)-b {
		return 0, false
	}
	return a + b, true
}

func markCount(timestamps []time.Duration, start, end time.Duration) int {
	first := sort.Search(len(timestamps), func(i int) bool { return timestamps[i] >= start })
	last := sort.Search(len(timestamps), func(i int) bool { return timestamps[i] >= end })
	return last - first
}

func markScore(contrasts []float64, code []int8) int64 {
	var sum float64
	for k, contrast := range contrasts {
		sum += float64(code[k]) * contrast
	}
	return int64(math.Round(sum / float64(len(code)) * markScoreScale))
}

func forEachBalancedMarkCode(symbols int, visit func([]int8)) {
	code := make([]int8, symbols)
	var walk func(int, int)
	walk = func(position, positive int) {
		if position == symbols {
			visit(code)
			return
		}
		if positive > 0 {
			code[position] = 1
			walk(position+1, positive-1)
		}
		if symbols-position > positive {
			code[position] = -1
			walk(position+1, positive)
		}
	}
	walk(0, symbols/2)
}
