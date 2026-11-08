package metrics

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMarkTwelveSymbolKnownAnswer(t *testing.T) {
	observation, epoch, detector := twelveSymbolMarkFixture()
	got := mustDetectMark(t, observation, epoch, detector)
	// the target has d=c, so sum(c*c)/12=1; five decoys have a=b=2, so d=0
	// exchanging r positives and r negatives gives 1-r/3 with choose(6,r)^2 codes
	// multiplicities 1+36+225+400+225+36+1=924; only one family maximum reaches 1
	if got.FamilyMaximum != 1_000_000_000 || got.ExtremeCodes != 1 || got.TotalCodes != 924 || got.PValue != 1.0/924 {
		t.Fatalf("family result = %+v", got)
	}
	if got.Decision != "declared" || got.SelectedCandidate == nil || *got.SelectedCandidate != 2 {
		t.Fatalf("decision = %s, selected = %v", got.Decision, got.SelectedCandidate)
	}
	for j := range observation.Candidates {
		want := int64(0)
		if j == 2 {
			want = 1_000_000_000
		}
		if got.CandidateQuantizedScores[j] != want || got.CandidateScores[j] != float64(want)/1e9 || got.BestLags[j] != 0 || got.EmptyPairs[j][0] != 0 {
			t.Errorf("candidate %d: scores=%v/%v, lag=%v, empty=%v", j, got.CandidateQuantizedScores[j], got.CandidateScores[j], got.BestLags[j], got.EmptyPairs[j])
		}
	}
	if auc := markAUC(got, 2); auc != 1 {
		t.Fatalf("AUC = %v, want 1", auc)
	}
}

func TestMarkBalancedEnumerationKnownAnswer(t *testing.T) {
	// choosing six positive positions among twelve gives 12!/(6!*6!)=924
	// r exchanged pairs have choose(6,r)^2 arrangements and dot product 12-4*r
	seen := make(map[string]bool)
	histogram := make(map[int]int)
	forEachBalancedMarkCode(12, func(code []int8) {
		key := make([]byte, len(code))
		positive, dot := 0, 0
		for k, symbol := range code {
			if symbol == 1 {
				positive++
				key[k] = '+'
			} else if symbol == -1 {
				key[k] = '-'
			} else {
				t.Fatalf("invalid symbol %d", symbol)
			}
			if k < 6 {
				dot += int(symbol)
			} else {
				dot -= int(symbol)
			}
		}
		if positive != 6 || seen[string(key)] {
			t.Fatalf("unbalanced or duplicate code %s", key)
		}
		seen[string(key)] = true
		histogram[dot]++
	})
	if len(seen) != 924 || !reflect.DeepEqual(histogram, map[int]int{12: 1, 8: 36, 4: 225, 0: 400, -4: 225, -8: 36, -12: 1}) {
		t.Fatalf("enumeration count=%d, histogram=%v", len(seen), histogram)
	}
}

func TestMarkZeroEvidenceKnownAnswers(t *testing.T) {
	for _, empty := range []bool{false, true} {
		name := "balanced counts"
		if empty {
			name = "empty and closed candidates"
		}
		t.Run(name, func(t *testing.T) {
			observation, epoch, detector := twelveSymbolMarkFixture()
			for j := range observation.Candidates {
				observation.Candidates[j] = observation.Candidates[0]
				if empty {
					observation.Candidates[j] = nil
				}
			}
			got := mustDetectMark(t, observation, epoch, detector)
			// all d=0, including empty pairs; every code ties at zero and p=924/924=1
			if got.FamilyMaximum != 0 || got.ExtremeCodes != 924 || got.TotalCodes != 924 || got.PValue != 1 || got.Decision != "none" || got.SelectedCandidate != nil {
				t.Fatalf("zero evidence = %+v", got)
			}
			for j := range observation.Candidates {
				wantEmpty := 0
				if empty {
					wantEmpty = 12
				}
				if got.CandidateScores[j] != 0 || got.CandidateQuantizedScores[j] != 0 || got.EmptyPairs[j][0] != wantEmpty {
					t.Errorf("candidate %d = %v/%v, empty=%v", j, got.CandidateScores[j], got.CandidateQuantizedScores[j], got.EmptyPairs[j])
				}
			}
			// one positive and five negatives have five ties, each worth one half
			if auc := markAUC(got, 2); auc != 0.5 {
				t.Fatalf("AUC = %v, want 0.5", auc)
			}
		})
	}
}

func TestMarkFourSymbolSearchCorrectionKnownAnswers(t *testing.T) {
	first := []time.Duration{25, 45, 105, 125}
	second := []time.Duration{25, 65, 85, 125}
	for _, tc := range []struct {
		name       string
		candidates [][]time.Duration
		lags       []time.Duration
		end        time.Duration
		extreme    int
		decision   string
	}{
		{"single pattern", [][]time.Duration{first}, []time.Duration{0}, 150, 1, "declared"},
		{"candidate correction", [][]time.Duration{first, second}, []time.Duration{0}, 150, 2, "declared"},
		{"lag correction", [][]time.Duration{{25, 45, 105, 125, 225, 265, 285, 325}}, []time.Duration{0, 200}, 350, 2, "declared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := MarkObservation{Candidates: tc.candidates, CaptureEnd: tc.end}
			detector := MarkDetector{Code: []int8{1, -1, 1, -1}, Slot: 10, Lags: tc.lags, Alpha: 1}
			got := mustDetectMark(t, observation, 0, detector)
			// choose(4,2)=6; only c=(+,-,+,-) reaches 1 for the first pattern
			// the second pattern has d=(+,+,-,-), adding one extreme code at its candidate or lag
			if got.FamilyMaximum != 1_000_000_000 || got.ExtremeCodes != tc.extreme || got.TotalCodes != 6 || got.PValue != float64(tc.extreme)/6 || got.Decision != tc.decision || got.SelectedCandidate == nil || *got.SelectedCandidate != 0 {
				t.Fatalf("search result = %+v", got)
			}
			if tc.name == "candidate correction" && got.CandidateQuantizedScores[1] != 0 {
				t.Fatalf("second candidate score = %v, want 0", got.CandidateQuantizedScores[1])
			}
		})
	}
}

func TestMarkNormalizedCountsAndEmptyDenominatorKnownAnswer(t *testing.T) {
	observation := MarkObservation{Candidates: [][]time.Duration{{1, 21, 22, 23, 41, 42, 43, 61, 121, 122, 141, 142}}, CaptureEnd: 150}
	detector := MarkDetector{Code: []int8{1, -1, 1, -1}, Slot: 10, Lags: []time.Duration{0}, Alpha: 1}
	got := mustDetectMark(t, observation, 0, detector)
	// (a,b)=(1,3),(3,1),(0,0),(2,2) gives d=(1/2,-1/2,0,0)
	// the fixed denominator gives s=(1/2+1/2)/4=1/4, not 1/2
	// six codes score {1/4,1/4,0,0,-1/4,-1/4}; the inclusive tail has two codes
	if got.CandidateQuantizedScores[0] != 250_000_000 || got.CandidateScores[0] != 0.25 || got.EmptyPairs[0][0] != 1 || got.ExtremeCodes != 2 || got.TotalCodes != 6 || got.PValue != 1.0/3 {
		t.Fatalf("normalized result = %+v", got)
	}
}

func TestMarkClosedTraceRetainsEmptySymbols(t *testing.T) {
	observation := MarkObservation{Candidates: [][]time.Duration{{25, 45}, nil}, CaptureEnd: 150}
	detector := MarkDetector{Code: []int8{1, -1, 1, -1}, Slot: 10, Lags: []time.Duration{0}, Alpha: 1}
	got := mustDetectMark(t, observation, 0, detector)
	// silence after the second symbol gives d=(1,-1,0,0), s=2/4=1/2
	// two balanced codes agree on the occupied symbols; their inclusive tail is 2/6
	if !reflect.DeepEqual(got.CandidateQuantizedScores, []int64{500_000_000, 0}) || !reflect.DeepEqual(got.EmptyPairs, [][]int{{2}, {4}}) || got.PValue != 1.0/3 {
		t.Fatalf("closed trace = %+v", got)
	}
}

func TestMarkCandidateTieAndInclusiveAlpha(t *testing.T) {
	observation, epoch, detector := twelveSymbolMarkFixture()
	detector.Alpha = 1.0 / 924
	got := mustDetectMark(t, observation, epoch, detector)
	if got.Decision != "declared" {
		t.Fatalf("p=alpha must declare, got %s", got.Decision)
	}
	detector.Alpha = math.Nextafter(detector.Alpha, 0)
	got = mustDetectMark(t, observation, epoch, detector)
	if got.Decision != "none" || got.SelectedCandidate != nil {
		t.Fatalf("p>alpha must abstain: %+v", got)
	}
	detector.Alpha = 0.05
	observation.Candidates[4] = observation.Candidates[2]
	got = mustDetectMark(t, observation, epoch, detector)
	// duplicating a candidate does not add an extreme code; it prevents unique attribution
	if got.PValue != 1.0/924 || got.ExtremeCodes != 1 || got.Decision != "ambiguous" || got.SelectedCandidate != nil {
		t.Fatalf("duplicate candidate = %+v", got)
	}
}

func TestMarkQuantizedTieKnownAnswer(t *testing.T) {
	first := append(repeatedMarkTime(1, 1), repeatedMarkTime(21, 49_999)...)
	first = append(first, 41)
	second := append(repeatedMarkTime(1, 1), repeatedMarkTime(21, 50_000)...)
	second = append(second, 41)
	observation := MarkObservation{Candidates: [][]time.Duration{first, second}, CaptureEnd: 70}
	detector := MarkDetector{Code: []int8{1, -1}, Slot: 10, Lags: []time.Duration{0}, Alpha: 1}
	got := mustDetectMark(t, observation, 0, detector)
	// s0=((49999-1)/50000+1)/2=1-1/50000=.99998
	// s1=1-1/50001=.999980000399992; both round to q=999980000
	// the reversed code is negative, so the inclusive exhaustive p-value is 1/2
	if !reflect.DeepEqual(got.CandidateQuantizedScores, []int64{999_980_000, 999_980_000}) || !reflect.DeepEqual(got.CandidateScores, []float64{0.99998, 0.99998}) || got.PValue != 0.5 || got.Decision != "ambiguous" || got.SelectedCandidate != nil {
		t.Fatalf("quantized tie = %+v", got)
	}
}

func TestMarkLagTieUsesSmallestLag(t *testing.T) {
	observation := MarkObservation{Candidates: [][]time.Duration{{25, 45, 225, 245}}, CaptureEnd: 270}
	detector := MarkDetector{Code: []int8{1, -1}, Slot: 10, Lags: []time.Duration{0, 200}, Alpha: 1}
	got := mustDetectMark(t, observation, 0, detector)
	// both lags have d=(1,-1), so s=1; the smallest tied lag is zero
	if got.CandidateQuantizedScores[0] != 1_000_000_000 || got.BestLags[0] != 0 || got.PValue != 0.5 || got.Decision != "declared" {
		t.Fatalf("lag tie = %+v", got)
	}
}

func TestMarkHalfOpenBoundaries(t *testing.T) {
	// intervals are a0=[23,33), b0=[43,53), a1=[63,73), b1=[83,93) ns
	// one counted event contributes +/-1 divided by two symbols; recovery contributes zero
	for _, tc := range []struct {
		boundary time.Duration
		before   int64
		at       int64
		after    int64
	}{
		{23, 0, -500_000_000, -500_000_000},
		{33, -500_000_000, 0, 0},
		{43, 0, 500_000_000, 500_000_000},
		{53, 500_000_000, 0, 0},
		{63, 0, 500_000_000, 500_000_000},
		{73, 500_000_000, 0, 0},
		{83, 0, -500_000_000, -500_000_000},
		{93, -500_000_000, 0, 0},
	} {
		for i, want := range []int64{tc.before, tc.at, tc.after} {
			timestamp := tc.boundary + time.Duration(i-1)
			observation := MarkObservation{Candidates: [][]time.Duration{{timestamp}}, CaptureEnd: 100}
			detector := MarkDetector{Code: []int8{1, -1}, Slot: 10, Lags: []time.Duration{3}, Alpha: 1}
			got := mustDetectMark(t, observation, 20, detector)
			wantEmpty := 1
			if want == 0 {
				wantEmpty = 2
			}
			if got.CandidateQuantizedScores[0] != want || got.EmptyPairs[0][0] != wantEmpty {
				t.Errorf("event %dns: q=%d empty=%d, want %d/%d", timestamp, got.CandidateQuantizedScores[0], got.EmptyPairs[0][0], want, wantEmpty)
			}
		}
	}
}

func TestMarkPresetCaptureBoundary(t *testing.T) {
	observation, epoch, detector := twelveSymbolMarkFixture()
	for lag := time.Duration(25 * time.Millisecond); lag <= 600*time.Millisecond; lag += 25 * time.Millisecond {
		detector.Lags = append(detector.Lags, lag)
	}
	// the last b end is 2s+(4*11+3)*200ms+600ms=12s, not the 11.6s mark end
	observation.CaptureEnd = 12 * time.Second
	if _, err := DetectMark(observation, epoch, detector); err != nil {
		t.Fatalf("capture ending exactly at final interval: %v", err)
	}
	observation.CaptureEnd--
	if _, err := DetectMark(observation, epoch, detector); err == nil {
		t.Fatal("capture missing the last nanosecond must fail")
	}
}

func TestMarkPermutationAndObservationOnlyReplay(t *testing.T) {
	observation, epoch, detector := twelveSymbolMarkFixture()
	want := mustDetectMark(t, observation, epoch, detector)
	permutation := []int{4, 2, 0, 5, 1, 3}
	permuted := observation
	permuted.Candidates = make([][]time.Duration, len(permutation))
	for j, original := range permutation {
		permuted.Candidates[j] = observation.Candidates[original]
	}
	got := mustDetectMark(t, permuted, epoch, detector)
	if got.SelectedCandidate == nil || *got.SelectedCandidate != 1 || got.PValue != want.PValue || got.ExtremeCodes != want.ExtremeCodes || got.FamilyMaximum != want.FamilyMaximum || got.Decision != want.Decision {
		t.Fatalf("permuted result = %+v", got)
	}
	for j, original := range permutation {
		if got.CandidateQuantizedScores[j] != want.CandidateQuantizedScores[original] || got.CandidateScores[j] != want.CandidateScores[original] || got.BestLags[j] != want.BestLags[original] || !reflect.DeepEqual(got.EmptyPairs[j], want.EmptyPairs[original]) {
			t.Fatalf("candidate %d does not follow permutation", j)
		}
	}
	input := struct {
		Observation MarkObservation `json:"observation"`
		Epoch       time.Duration   `json:"epoch"`
		Detector    MarkDetector    `json:"detector"`
	}{observation, epoch, detector}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded := input
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	// detector replay loads no truth, closure, entry trace, or intervention record
	if replay := mustDetectMark(t, decoded.Observation, decoded.Epoch, decoded.Detector); !reflect.DeepEqual(replay, want) {
		t.Fatalf("replay = %+v, want %+v", replay, want)
	}
	if after, err := json.Marshal(input); err != nil || string(after) != string(encoded) {
		t.Fatalf("detector mutated inputs: %v", err)
	}
}

func TestMarkValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*MarkObservation, *time.Duration, *MarkDetector)
		want   string
	}{
		{"empty code", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Code = nil }, "code length"},
		{"odd code", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Code = []int8{1, -1, 1} }, "code length"},
		{"unbalanced code", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Code = []int8{1, 1} }, "balanced"},
		{"invalid symbol", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Code[0] = 0 }, "symbols"},
		{"unsupported code length", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Code = make([]int8, 14) }, "code length"},
		{"zero slot", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Slot = 0 }, "slot"},
		{"negative slot", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Slot = -1 }, "slot"},
		{"zero alpha", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Alpha = 0 }, "alpha"},
		{"negative alpha", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Alpha = -0.1 }, "alpha"},
		{"large alpha", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Alpha = 1.1 }, "alpha"},
		{"nan alpha", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Alpha = math.NaN() }, "alpha"},
		{"infinite alpha", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Alpha = math.Inf(1) }, "alpha"},
		{"no candidates", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) { o.Candidates = nil }, "candidate count"},
		{"too many candidates", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) {
			o.Candidates = make([][]time.Duration, 65)
		}, "candidate count"},
		{"no lags", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Lags = nil }, "lag count"},
		{"too many lags", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Lags = make([]time.Duration, 1025) }, "lag count"},
		{"negative lag", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Lags = []time.Duration{-1} }, "lags"},
		{"duplicate lag", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Lags = []time.Duration{0, 0} }, "lags"},
		{"unsorted lags", func(_ *MarkObservation, _ *time.Duration, d *MarkDetector) { d.Lags = []time.Duration{2, 1} }, "lags"},
		{"search cost", func(o *MarkObservation, _ *time.Duration, d *MarkDetector) {
			d.Code = []int8{1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1}
			o.Candidates = make([][]time.Duration, 64)
			d.Lags = make([]time.Duration, 15)
			for l := range d.Lags {
				d.Lags[l] = time.Duration(l)
			}
		}, "symbol contributions"},
		{"empty capture", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) { o.CaptureEnd = o.CaptureStart }, "capture bounds"},
		{"reversed capture", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) { o.CaptureEnd = -1 }, "capture bounds"},
		{"incomplete start", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) { o.CaptureStart = 1 }, "does not cover"},
		{"incomplete end", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) { o.CaptureEnd = 69 }, "does not cover"},
		{"unsorted timestamps", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) { o.Candidates[0] = []time.Duration{2, 1} }, "nondecreasing"},
		{"timestamp before capture", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) { o.Candidates[0] = []time.Duration{-1} }, "outside capture"},
		{"timestamp at capture end", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) {
			o.Candidates[0] = []time.Duration{o.CaptureEnd}
		}, "outside capture"},
		{"timestamp after capture", func(o *MarkObservation, _ *time.Duration, _ *MarkDetector) {
			o.Candidates[0] = []time.Duration{o.CaptureEnd + 1}
		}, "outside capture"},
		{"slot overflow", func(o *MarkObservation, _ *time.Duration, d *MarkDetector) {
			o.CaptureEnd = math.MaxInt64
			d.Slot = math.MaxInt64/7 + 1
		}, "duration overflows"},
		{"epoch overflow", func(o *MarkObservation, e *time.Duration, _ *MarkDetector) {
			o.CaptureEnd = math.MaxInt64
			*e = math.MaxInt64 - 69
		}, "epoch overflows"},
		{"lag overflow", func(o *MarkObservation, _ *time.Duration, d *MarkDetector) {
			o.CaptureEnd = math.MaxInt64
			d.Lags = []time.Duration{math.MaxInt64}
		}, "lag overflows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := MarkObservation{Candidates: [][]time.Duration{{}}, CaptureEnd: 100}
			epoch := time.Duration(0)
			detector := MarkDetector{Code: []int8{1, -1}, Slot: 10, Lags: []time.Duration{0}, Alpha: 0.05}
			tc.change(&observation, &epoch, &detector)
			got, err := DetectMark(observation, epoch, detector)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !reflect.DeepEqual(got, MarkDetection{}) {
				t.Fatalf("result=%+v, error=%v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestMarkValidRepeatedTimestampsAndSignedClock(t *testing.T) {
	observation := MarkObservation{Candidates: [][]time.Duration{{-99, -99, -75, -55}}, CaptureStart: -100, CaptureEnd: -30}
	detector := MarkDetector{Code: []int8{1, -1}, Slot: 10, Lags: []time.Duration{0}, Alpha: 1}
	got := mustDetectMark(t, observation, -100, detector)
	// a0=2,b0=1 gives -1/3; a1=1,b1=0 gives -1, so s=(-1/3+1)/2=1/3
	if got.CandidateQuantizedScores[0] != 333_333_333 || got.PValue != 0.5 {
		t.Fatalf("signed-clock result = %+v", got)
	}
}

func twelveSymbolMarkFixture() (MarkObservation, time.Duration, MarkDetector) {
	code := []int8{1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1}
	target := markMilliseconds(
		2450, 2500, 3250, 3300, 4050, 4100, 4850, 4900, 5650, 5700, 6450, 6500,
		6850, 6900, 7650, 7700, 8450, 8500, 9250, 9300, 10050, 10100, 10850, 10900,
	)
	decoy := markMilliseconds(
		2050, 2100, 2450, 2500, 2850, 2900, 3250, 3300, 3650, 3700, 4050, 4100,
		4450, 4500, 4850, 4900, 5250, 5300, 5650, 5700, 6050, 6100, 6450, 6500,
		6850, 6900, 7250, 7300, 7650, 7700, 8050, 8100, 8450, 8500, 8850, 8900,
		9250, 9300, 9650, 9700, 10050, 10100, 10450, 10500, 10850, 10900, 11250, 11300,
	)
	return MarkObservation{Candidates: [][]time.Duration{decoy, decoy, target, decoy, decoy, decoy}, CaptureEnd: 12 * time.Second},
		2 * time.Second,
		MarkDetector{Code: code, Slot: 200 * time.Millisecond, Lags: []time.Duration{0}, Alpha: 0.05}
}

func mustDetectMark(t *testing.T, observation MarkObservation, epoch time.Duration, detector MarkDetector) MarkDetection {
	t.Helper()
	got, err := DetectMark(observation, epoch, detector)
	if err != nil {
		t.Fatal(err)
	}
	if got.PValue <= 0 || got.ExtremeCodes < 1 || got.ExtremeCodes > got.TotalCodes {
		t.Fatalf("invalid exhaustive tail: %+v", got)
	}
	return got
}

func markMilliseconds(values ...int) []time.Duration {
	timestamps := make([]time.Duration, len(values))
	for i, value := range values {
		timestamps[i] = time.Duration(value) * time.Millisecond
	}
	return timestamps
}

func repeatedMarkTime(timestamp time.Duration, count int) []time.Duration {
	timestamps := make([]time.Duration, count)
	for i := range timestamps {
		timestamps[i] = timestamp
	}
	return timestamps
}

func markAUC(detection MarkDetection, positive int) float64 {
	scores := make([]Score, len(detection.CandidateScores))
	for j, value := range detection.CandidateScores {
		scores[j] = Score{Value: value, True: j == positive}
	}
	return AUC(scores)
}
