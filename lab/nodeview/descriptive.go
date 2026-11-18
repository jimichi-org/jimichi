package nodeview

import (
	"math"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

var linkingGrid = [5]int64{1000000000, 2000000000, 5000000000, 10000000000, 20000000000}

type linkingAcquisition struct {
	Requested bool
	Setup     bool
	Windows   [2][5]bool
	Reasons   [2][5]Reason
}

type summaryMethod struct {
	name   string
	window int64
}

func linkingTimes(methods []MethodResult, acquisition linkingAcquisition) ([]LinkingTime, error) {
	var present [2][5]bool
	var points [2][5]Number
	setupSeen, setupPerfect := false, false
	for _, method := range methods {
		if method.Method == "setup" && method.WindowNS == 0 {
			if setupSeen || !validTopOne(method.TopOne) {
				return nil, ErrInvalid
			}
			setupSeen = true
			setupPerfect = acquisition.Setup && method.TopOne.Value != nil && *method.TopOne.Value == 1
		}
		mi := -1
		if method.Method == "cells" {
			mi = 0
		} else if method.Method == "frames" {
			mi = 1
		}
		if mi < 0 {
			continue
		}
		wi := -1
		for i, window := range linkingGrid {
			if method.WindowNS == window {
				wi = i
			}
		}
		if wi < 0 || present[mi][wi] || !validTopOne(method.TopOne) {
			return nil, ErrInvalid
		}
		present[mi][wi], points[mi][wi] = true, method.TopOne
	}
	if !acquisition.Requested {
		if present != ([2][5]bool{}) {
			return nil, ErrInvalid
		}
		return nil, nil
	}
	out := make([]LinkingTime, 0, 2)
	for mi, name := range []string{"cells", "frames"} {
		result := LinkingTime{Method: name, Seconds: Number{Reason: ReasonIncomplete}}
		if setupPerfect {
			result.Seconds = number(0, ReasonNone)
			out = append(out, result)
			continue
		}
		var state [5]byte
		var cause [5]Reason
		for wi, point := range points[mi] {
			cause[wi] = acquisition.Reasons[mi][wi]
			if cause[wi] == ReasonNone || !validReason(cause[wi]) || cause[wi] == ReasonCensored {
				cause[wi] = ReasonIncomplete
			}
			if !present[mi][wi] || !acquisition.Windows[mi][wi] {
				continue
			}
			if point.Value != nil {
				state[wi] = 1
				if *point.Value == 1 {
					state[wi] = 2
				}
				continue
			}
			switch point.Reason {
			case ReasonNoView, ReasonNoPartner, ReasonNoPositive, ReasonNoNegative:
				state[wi] = 1
			default:
				cause[wi] = point.Reason
			}
		}
		switch state[4] {
		case 0:
			result.Seconds.Reason = cause[4]
		case 1:
			result.Seconds.Reason, result.Censored = ReasonCensored, true
		case 2:
			first := 4
			for first > 0 && state[first-1] == 2 {
				first--
			}
			result.Seconds = number(float64(linkingGrid[first])/1e9, ReasonNone)
		}
		out = append(out, result)
	}
	return out, nil
}

func validTopOne(point Number) bool {
	if !validNumber(point) {
		return false
	}
	if point.Value == nil {
		return point.Reason != ReasonNone
	}
	return point.Reason == ReasonNone && *point.Value >= 0 && *point.Value <= 1
}

func validLinkingTime(link LinkingTime) bool {
	if link.Method != "cells" && link.Method != "frames" || !validNumber(link.Seconds) {
		return false
	}
	if link.Seconds.Value == nil {
		return link.Seconds.Reason != ReasonNone && link.Censored == (link.Seconds.Reason == ReasonCensored)
	}
	if link.Censored || link.Seconds.Reason != ReasonNone {
		return false
	}
	if *link.Seconds.Value == 0 {
		return true
	}
	for _, window := range linkingGrid {
		if *link.Seconds.Value == float64(window)/1e9 {
			return true
		}
	}
	return false
}

func requestedSummaryMethods(p Plan, coordinate Coordinate) ([16]summaryMethod, int) {
	var methods [16]summaryMethod
	count := 0
	add := func(method string, window int64) {
		methods[count] = summaryMethod{method, window}
		count++
	}
	if len(coordinate.Controlled) == 2 {
		for _, name := range []string{"setup", "close", "shared", "mixed"} {
			add(name, 0)
		}
		for _, window := range linkingGrid {
			add("cells", window)
			add("frames", window)
		}
	}
	if p.Set == Mailbox && (p.Phase == Pilot || p.Phase == Primary) && p.TrainingReady {
		for _, name := range []string{"request", "record"} {
			for _, model := range p.FrozenModels {
				if model.Configuration == coordinate.ID && model.Population == name {
					add(name, coordinate.Settings.DurationNS)
					break
				}
			}
		}
	}
	return methods, count
}

func descriptiveSummaries(r Report) []DescriptiveSummary {
	var out []DescriptiveSummary
	for _, coordinate := range r.Plan.Configurations {
		runs, failures := 0, 0
		for _, run := range r.Runs {
			if run.Configuration == coordinate.ID {
				runs++
				if len(run.Flags) != 0 {
					failures++
				}
			}
		}
		if runs == 0 {
			continue
		}
		keys, count := requestedSummaryMethods(r.Plan, coordinate)
		for _, key := range keys[:count] {
			var values []float64
			for _, run := range r.Runs {
				if run.Configuration != coordinate.ID {
					continue
				}
				for _, method := range run.Methods {
					if method.Method == key.name && method.WindowNS == key.window {
						if method.AUC.Value != nil && method.AUC.Reason == ReasonNone && !math.IsNaN(*method.AUC.Value) && !math.IsInf(*method.AUC.Value, 0) {
							values = append(values, *method.AUC.Value)
						}
						break
					}
				}
			}
			interval := metrics.QuantileInterval(values, .5, .95)
			out = append(out, DescriptiveSummary{Configuration: coordinate.ID, Method: key.name, WindowNS: key.window, Runs: runs, Defined: len(values), Failed: failures, Missing: runs - len(values), Median: number(interval.Point, ReasonIncomplete), Low: number(interval.Low, ReasonIncomplete), High: number(interval.High, ReasonIncomplete)})
		}
		if len(coordinate.Controlled) != 2 {
			continue
		}
		for _, name := range []string{"cells", "frames"} {
			var values []float64
			censored, defined := 0, 0
			for _, run := range r.Runs {
				if run.Configuration != coordinate.ID {
					continue
				}
				for _, link := range run.LinkingTimes {
					if link.Method != name {
						continue
					}
					if link.Seconds.Value != nil && validLinkingTime(link) {
						values = append(values, *link.Seconds.Value)
						defined++
					} else if link.Censored && validLinkingTime(link) {
						values = append(values, math.NaN())
						censored++
					}
					break
				}
			}
			median, _ := metrics.CensoredMedian(values)
			reason := ReasonCensored
			if len(values) == 0 {
				reason = ReasonIncomplete
			}
			point := DescriptiveSummary{Configuration: coordinate.ID, Method: name + "-time", Runs: runs, Defined: defined, Failed: failures, Missing: runs - defined - censored, Censored: censored, Median: number(median, reason), Low: Number{Reason: reason}, High: Number{Reason: reason}}
			if censored == 0 {
				interval := metrics.QuantileInterval(values, .5, .95)
				point.Median, point.Low, point.High = number(interval.Point, ReasonIncomplete), number(interval.Low, ReasonIncomplete), number(interval.High, ReasonIncomplete)
			}
			out = append(out, point)
		}
	}
	return out
}
