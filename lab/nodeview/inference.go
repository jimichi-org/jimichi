package nodeview

import (
	"math"
	"reflect"
	"strings"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

// callers bind any joined reports to the same source, models and registered plan
func summarizeInferences(p Plan, runs []RunResult) ([]Inference, []Inference, error) {
	model := emptyInferenceFamily(modelIDs(), ReasonNoView)
	difference := emptyInferenceFamily(differenceIDs(), ReasonNoView)
	coordinates, err := inferenceCoordinates(p)
	if err != nil {
		return nil, nil, err
	}
	if p.Suite == "gost" {
		return emptyInferenceFamily(modelIDs(), ReasonUnsupported), emptyInferenceFamily(differenceIDs(), ReasonUnsupported), nil
	}
	indexed := make(map[string]map[int]RunResult)
	for _, run := range runs {
		if run.Phase != Structural && run.Phase != Train && run.Phase != Pilot && run.Phase != Primary {
			return nil, nil, ErrInvalid
		}
		if run.Phase != Primary {
			continue
		}
		coordinate, ok := coordinates[run.Configuration]
		if !ok || run.Repeat < 0 {
			return nil, nil, ErrInvalid
		}
		repeats, units := coordinate.Main, coordinate.Flows
		if p.Set == Compromise {
			repeats, units = coordinate.Slots/32, 32
		} else if coordinate.Population == "classifier" {
			units = 2 * coordinate.Conversations
		}
		if run.Repeat >= repeats || p.Set != Compromise && coordinate.Population != "link" && coordinate.Population != "classifier" || !validInferenceCounts(run, units) {
			return nil, nil, ErrInvalid
		}
		for _, flag := range run.Flags {
			if flag == ReasonNone || !validReason(flag) {
				return nil, nil, ErrInvalid
			}
		}
		if coordinate.Population == "classifier" {
			for _, value := range []Number{run.RequestLDA, run.RecordLDA} {
				if _, _, err := inferenceAUC(value); err != nil {
					return nil, nil, err
				}
			}
		}
		if indexed[run.Configuration] == nil {
			indexed[run.Configuration] = make(map[int]RunResult)
		}
		if _, duplicate := indexed[run.Configuration][run.Repeat]; duplicate {
			return nil, nil, ErrInvalid
		}
		indexed[run.Configuration][run.Repeat] = run
	}
	if p.Set == Compromise {
		for i, claim := range ModelRegistry() {
			row := coordinates[claim.Row]
			item, err := summarizeModelClaim(claim, row, indexed[claim.Row], p.Phase == Primary)
			if err != nil {
				return nil, nil, err
			}
			model[i] = item
		}
		return model, difference, nil
	}
	tests := make([]metrics.Test, nodeFamilySize)
	for i := range tests {
		tests[i].P = math.NaN()
	}
	for i, id := range differenceIDs() {
		var x, y []float64
		planned := 0
		if i < 9 {
			planned = coordinates[id].Main
			for repeat := range planned {
				run, exists := indexed[id][repeat]
				if !exists {
					continue
				}
				a, b, usable, err := inferenceLinkPair(run)
				if err != nil {
					return nil, nil, err
				}
				if usable {
					x, y = append(x, a), append(y, b)
				}
			}
		} else {
			period := strings.TrimSuffix(strings.TrimSuffix(id, "-request"), "-record")
			offID, onID := period+"-C0", period+"-C1"
			planned = coordinates[offID].Main
			if planned != coordinates[onID].Main {
				return nil, nil, ErrInvalid
			}
			for repeat := range planned {
				off, offExists := indexed[offID][repeat]
				on, onExists := indexed[onID][repeat]
				if !offExists || !onExists {
					continue
				}
				a, b := on.RequestLDA, off.RequestLDA
				if strings.HasSuffix(id, "-record") {
					a, b = on.RecordLDA, off.RecordLDA
				}
				xv, xd, err := inferenceAUC(a)
				if err != nil {
					return nil, nil, err
				}
				yv, yd, err := inferenceAUC(b)
				if err != nil {
					return nil, nil, err
				}
				if xd && yd && cleanInferenceRun(off) && cleanInferenceRun(on) {
					x, y = append(x, xv), append(y, yv)
				}
			}
		}
		item := emptyInference(id, ReasonIncomplete)
		item.Planned, item.Usable, item.Failures = planned, len(x), planned-len(x)
		if p.Phase != Primary || len(x) != planned {
			difference[i] = item
			continue
		}
		analysis, err := AnalyzePaired(x, y)
		if err != nil {
			return nil, nil, err
		}
		deltas := make([]float64, len(x))
		for j := range deltas {
			deltas[j] = x[j] - y[j]
		}
		interval := metrics.QuantileInterval(deltas, .5, .95)
		item.Defined, item.Reason, item.Method = true, ReasonNone, analysis.Test.Method
		item.Point, item.Low, item.High = number(interval.Point, ReasonIncomplete), number(interval.Low, ReasonIncomplete), number(interval.High, ReasonIncomplete)
		item.MedianDelta = number(analysis.MedianDelta, ReasonIncomplete)
		item.P, item.Effect = number(analysis.Test.P, ReasonIncomplete), number(analysis.Test.Effect, ReasonIncomplete)
		item.AdjustedP = Number{Reason: ReasonIncomplete}
		if analysis.Test.Method == "degenerate" {
			item.Verdict = "degenerate"
			item.AdjustedP = Number{Reason: ReasonNoView}
		}
		tests[i] = analysis.Test
		difference[i] = item
	}
	if !jointInferenceAccounted(p, coordinates, indexed) {
		return model, difference, nil
	}
	for i, adjusted := range metrics.HolmTests(tests) {
		if math.IsNaN(adjusted) {
			continue
		}
		difference[i].AdjustedP = number(adjusted, ReasonIncomplete)
		difference[i].Verdict = "not rejected"
		if adjusted <= nodeAlpha {
			difference[i].Verdict = "rejected"
		}
	}
	return model, difference, nil
}

func inferenceCoordinates(p Plan) (map[string]Coordinate, error) {
	if p.Set != Compromise && p.Set != Collude && p.Set != Mailbox || p.Suite != "c25519" && p.Suite != "gost" || p.Phase != Structural && p.Phase != Train && p.Phase != Pilot && p.Phase != Primary {
		return nil, ErrInvalid
	}
	if !reflect.DeepEqual(p.ModelFamily, Family{modelIDs(), 13, .05, .05, .8, "first-chain"}) || !reflect.DeepEqual(p.DifferenceFamily, Family{differenceIDs(), 13, .05, .05, .8, "repeat-paired-exact-signed-rank"}) {
		return nil, ErrInvalid
	}
	canonical := canonicalCoordinates(p.Set)
	if len(p.Configurations) != len(canonical) {
		return nil, ErrInvalid
	}
	out := make(map[string]Coordinate, len(canonical))
	for i, row := range p.Configurations {
		want := canonical[i]
		if row.Population == "boundary" || row.Settings.ControlProfile != 0 {
			if !reflect.DeepEqual(row, want) || !planningBoundaryCoordinate(row) {
				return nil, ErrInvalid
			}
			continue
		}
		if p.Set == Compromise && i >= 6 {
			if !reflect.DeepEqual(row, want) || row.Population != "trust" && row.Population != "membership" {
				return nil, ErrInvalid
			}
			continue
		}
		if row.ID != want.ID || row.Topology != want.Topology || row.Population != want.Population || row.Main < 30 || row.Main > nodeMaxPairs {
			return nil, ErrInvalid
		}
		if p.Set == Compromise {
			if row.ID == "M1" && row.Slots != 32 || row.ID != "M1" && (row.Slots < 2048 || row.Slots > 1048576 || row.Slots%32 != 0) {
				return nil, ErrInvalid
			}
		} else if row.Flows != want.Flows || row.Conversations != want.Conversations {
			return nil, ErrInvalid
		}
		out[row.ID] = row
	}
	if p.Set != Compromise && p.Suite == "c25519" {
		if len(p.Powers) != nodeFamilySize {
			return nil, ErrInvalid
		}
		counts := make(map[string]int, nodeFamilySize)
		for i, calculation := range p.Powers {
			if calculation.ID != differenceIDs()[i] || calculation.N < 30 || calculation.N > nodeMaxPairs {
				return nil, ErrInvalid
			}
			counts[calculation.ID] = calculation.N
		}
		for _, i := range []int{9, 11} {
			if p.Powers[i].N != p.Powers[i+1].N {
				return nil, ErrInvalid
			}
		}
		for _, set := range []Set{Collude, Mailbox} {
			for _, row := range canonicalCoordinates(set) {
				if n, incident := configurationIncidentCount(row, counts); incident {
					if existing, ok := out[row.ID]; ok && existing.Main != n {
						return nil, ErrInvalid
					}
					row.Main = n
					out[row.ID] = row
				}
			}
		}
	}
	return out, nil
}

func jointInferenceAccounted(p Plan, coordinates map[string]Coordinate, runs map[string]map[int]RunResult) bool {
	if p.Phase != Primary {
		return false
	}
	for _, row := range coordinates {
		if row.Population != "link" && row.Population != "classifier" {
			continue
		}
		for repeat := range row.Main {
			if _, exists := runs[row.ID][repeat]; !exists {
				return false
			}
		}
	}
	return true
}

func validInferenceCounts(run RunResult, units int) bool {
	counts := run.Counts
	if units < 1 || counts.Planned != uint64(units) || counts.Attempted > counts.Planned || counts.Established > counts.Attempted || counts.PreflightOK > counts.Established || counts.MessageBearing > counts.PreflightOK || counts.Refused > counts.Attempted || counts.SetupFailed > counts.Attempted || counts.Unanswered > maxMessages || counts.Missing > maxSelectedCells || run.Touched > counts.Planned || run.Ends > run.Touched || run.ContentFound > counts.MessageBearing || run.ContentMessages > run.MeasuredMessages {
		return false
	}
	unestablished := counts.Attempted - counts.Established
	if counts.Refused > unestablished || counts.SetupFailed > unestablished-counts.Refused {
		return false
	}
	return !run.ModelComplete || cleanInferenceRun(run)
}

func cleanInferenceRun(run RunResult) bool {
	counts := run.Counts
	return len(run.Flags) == 0 && counts.Planned > 0 && counts.Attempted == counts.Planned && counts.Established == counts.Planned && counts.PreflightOK == counts.Planned && counts.MessageBearing == counts.Planned && counts.Refused == 0 && counts.SetupFailed == 0
}

func summarizeModelClaim(claim ModelClaim, row Coordinate, runs map[int]RunResult, primary bool) (Inference, error) {
	item := emptyInference(claim.ID, ReasonIncomplete)
	item.Planned = row.Slots
	denominator := 4
	if row.Topology == "peer" {
		denominator = 3
	}
	var values []float64
	if claim.Kind == "mean" {
		values = make([]float64, 0, row.Slots)
	}
	var successes uint64
	for repeat := range row.Slots / 32 {
		run, exists := runs[repeat]
		if !exists {
			continue
		}
		var total uint64
		if len(run.RouteHistogram) != 0 && len(run.RouteHistogram) != denominator+1 {
			return Inference{}, ErrInvalid
		}
		for _, count := range run.RouteHistogram {
			if count > run.Counts.Planned-total {
				return Inference{}, ErrInvalid
			}
			total += count
		}
		if run.ModelComplete && total != run.Counts.Planned {
			return Inference{}, ErrInvalid
		}
		if !run.ModelComplete || !cleanInferenceRun(run) {
			continue
		}
		item.Usable += int(run.Counts.Planned)
		switch {
		case claim.Kind == "mean":
			for recovered, count := range run.RouteHistogram {
				for range count {
					values = append(values, float64(recovered)/float64(denominator))
				}
			}
		case strings.HasSuffix(claim.ID, ".touched"):
			successes += run.Touched
		case strings.HasSuffix(claim.ID, ".ends"):
			successes += run.Ends
		case strings.HasSuffix(claim.ID, ".content"):
			successes += run.ContentFound
		default:
			return Inference{}, ErrInvalid
		}
	}
	item.Failures = item.Planned - item.Usable
	if !primary || item.Usable != item.Planned {
		return item, nil
	}
	interval := metrics.WilsonInterval(int(successes), item.Planned, 1-nodeAlpha/nodeFamilySize)
	if claim.Kind == "mean" {
		interval = metrics.MeanInterval(values, 1-nodeAlpha/nodeFamilySize)
	}
	item.Defined, item.Reason, item.Method = true, ReasonNone, interval.Method
	item.Point, item.Low, item.High = number(interval.Point, ReasonIncomplete), number(interval.Low, ReasonIncomplete), number(interval.High, ReasonIncomplete)
	item.P, item.AdjustedP, item.Effect, item.MedianDelta = Number{Reason: ReasonNoView}, Number{Reason: ReasonNoView}, Number{Reason: ReasonNoView}, Number{Reason: ReasonNoView}
	item.Verdict = metrics.Equivalence(interval, claim.Mean, nodeDelta)
	return item, nil
}

func inferenceLinkPair(run RunResult) (float64, float64, bool, error) {
	var x, y float64
	var haveX, haveY bool
	seen := make(map[struct {
		method string
		window int64
	}]bool, len(run.Methods))
	for _, method := range run.Methods {
		key := struct {
			method string
			window int64
		}{method.Method, method.WindowNS}
		if seen[key] || !knownMethod(method.Method) {
			return 0, 0, false, ErrInvalid
		}
		seen[key] = true
		v, defined, err := inferenceAUC(method.AUC)
		if err != nil {
			return 0, 0, false, err
		}
		if method.WindowNS == 20000000000 {
			if method.Method == "cells" {
				x, haveX = v, defined
			} else if method.Method == "frames" {
				y, haveY = v, defined
			}
		}
	}
	return x, y, haveX && haveY && cleanInferenceRun(run), nil
}

func inferenceAUC(value Number) (float64, bool, error) {
	if value.Value == nil {
		if value.Reason == ReasonNone || !validReason(value.Reason) {
			return 0, false, ErrInvalid
		}
		return 0, false, nil
	}
	if value.Reason != ReasonNone || !(*value.Value >= 0 && *value.Value <= 1) {
		return 0, false, ErrInvalid
	}
	return *value.Value, true, nil
}

func emptyInferenceFamily(ids []string, reason Reason) []Inference {
	out := make([]Inference, len(ids))
	for i, id := range ids {
		out[i] = emptyInference(id, reason)
	}
	return out
}

func emptyInference(id string, reason Reason) Inference {
	null := Number{Reason: reason}
	return Inference{ID: id, Reason: reason, Point: null, Low: null, High: null, P: null, AdjustedP: null, Effect: null, MedianDelta: null}
}
