package nodeview

import (
	"math"
	"testing"
)

func TestLinkingTimeCertifiedGridStates(t *testing.T) {
	for _, test := range []struct {
		states   string
		want     float64
		reason   Reason
		censored bool
	}{
		{"RPRPP", 10, ReasonNone, false},
		{"UPUPP", 10, ReasonNone, false},
		{"UUUUP", 20, ReasonNone, false},
		{"PPPPU", 0, ReasonIncomplete, false},
		{"UUUUR", 0, ReasonCensored, true},
	} {
		t.Run(test.states, func(t *testing.T) {
			acquisition := linkingAcquisition{Requested: true}
			var methods []MethodResult
			for i, state := range test.states {
				point := Number{Reason: ReasonNoView}
				if state == 'P' {
					point = number(1, ReasonNone)
				} else if state == 'R' {
					point = number(.5, ReasonNone)
				}
				acquisition.Windows[0][i] = state != 'U'
				methods = append(methods, MethodResult{Method: "cells", WindowNS: linkingGrid[i], TopOne: point})
			}
			got, err := linkingTimes(methods, acquisition)
			if err != nil || len(got) != 2 || got[0].Censored != test.censored || got[0].Seconds.Reason != test.reason {
				t.Fatal("grid certificate or unavailable reason changed")
			}
			if test.reason == ReasonNone {
				if got[0].Seconds.Value == nil || *got[0].Seconds.Value != test.want {
					t.Fatal("earliest certified perfect suffix changed")
				}
			} else if got[0].Seconds.Value != nil {
				t.Fatal("unavailable or censored grid became a numeric time")
			}
			if got[1].Seconds.Reason != ReasonIncomplete || got[1].Censored {
				t.Fatal("absent frames grid became censor evidence")
			}
		})
	}
}

func TestLinkingTimeSeparatesEmptyCaptureAndMissingAcquisition(t *testing.T) {
	methods := []MethodResult{{Method: "cells", WindowNS: linkingGrid[4], TopOne: Number{Reason: ReasonNoPartner}}}
	acquisition := linkingAcquisition{Requested: true}
	missing, err := linkingTimes(methods, acquisition)
	if err != nil || missing[0].Censored || missing[0].Seconds.Reason != ReasonIncomplete {
		t.Fatal("nil top1 certified its own acquisition")
	}
	acquisition.Windows[0][4] = true
	observed, err := linkingTimes(methods, acquisition)
	if err != nil || !observed[0].Censored || observed[0].Seconds.Reason != ReasonCensored {
		t.Fatal("complete observed empty population lost censor evidence")
	}
	methods = append(methods, MethodResult{Method: "setup", TopOne: number(1, ReasonNone)})
	acquisition.Setup = true
	setup, err := linkingTimes(methods, acquisition)
	if err != nil || setup[0].Seconds.Value == nil || *setup[0].Seconds.Value != 0 || setup[1].Seconds.Value == nil || *setup[1].Seconds.Value != 0 {
		t.Fatal("genuine perfect setup did not retain independent time zero")
	}
}

func TestLinkingTimeRejectsDuplicateAndInvalidGrid(t *testing.T) {
	base := MethodResult{Method: "cells", WindowNS: linkingGrid[4], TopOne: number(1, ReasonNone)}
	for _, methods := range [][]MethodResult{
		{base, base},
		{{Method: "cells", WindowNS: 3e9, TopOne: number(1, ReasonNone)}},
		{{Method: "cells", WindowNS: linkingGrid[4], TopOne: number(1.1, ReasonNone)}},
		{{Method: "cells", WindowNS: linkingGrid[4]}},
	} {
		if _, err := linkingTimes(methods, linkingAcquisition{Requested: true}); err == nil {
			t.Fatal("invalid or duplicate method window accepted")
		}
	}
}

func summaryFixture() Report {
	return Report{Plan: Plan{Set: Collude, Phase: Primary, Configurations: []Coordinate{{ID: "x", Controlled: []int{0, 4}}}}}
}

func findSummary(t *testing.T, rows []DescriptiveSummary, method string, window int64) DescriptiveSummary {
	t.Helper()
	for _, row := range rows {
		if row.Method == method && row.WindowNS == window {
			return row
		}
	}
	t.Fatal("requested summary position disappeared")
	return DescriptiveSummary{}
}

func TestDescriptiveRetainsFailedAndUnstartedSlots(t *testing.T) {
	r := summaryFixture()
	r.Runs = []RunResult{
		{Configuration: "x", Flags: []Reason{ReasonBroken}, Methods: []MethodResult{{Method: "cells", WindowNS: linkingGrid[0], AUC: number(.6, ReasonNone)}}},
		{Configuration: "x", Methods: []MethodResult{{Method: "cells", WindowNS: linkingGrid[0], AUC: number(.8, ReasonNone)}}},
		{Configuration: "x", Flags: []Reason{ReasonCancelled}},
	}
	row := findSummary(t, descriptiveSummaries(r), "cells", linkingGrid[0])
	// available .6 and .8 give median .7; the failed empty slot still belongs to all three runs
	if row.Runs != 3 || row.Defined != 2 || row.Failed != 2 || row.Missing != 1 || row.Median.Value == nil || math.Abs(*row.Median.Value-.7) > 1e-15 {
		t.Fatal("descriptive population dropped flagged finite or unavailable data")
	}
	r.Runs = r.Runs[2:]
	rows := descriptiveSummaries(r)
	row = findSummary(t, rows, "cells", linkingGrid[0])
	if len(rows) != 16 || row.Runs != 1 || row.Failed != 1 || row.Missing != 1 || row.Defined != 0 || row.Median.Value != nil {
		t.Fatal("all-failed coordinate lost its requested positions")
	}
}

func TestDescriptiveMedianSeparatesUnavailableAndCensoredRuns(t *testing.T) {
	r := summaryFixture()
	for _, link := range []LinkingTime{
		{Method: "cells", Seconds: number(1, ReasonNone)},
		{Method: "cells", Seconds: number(2, ReasonNone)},
		{Method: "cells", Seconds: Number{Reason: ReasonCensored}, Censored: true},
		{Method: "cells", Seconds: Number{Reason: ReasonIncomplete}},
	} {
		r.Runs = append(r.Runs, RunResult{Configuration: "x", LinkingTimes: []LinkingTime{link}})
	}
	row := findSummary(t, descriptiveSummaries(r), "cells-time", 0)
	// [1,2,C,U] has acquired median 2, with U retained only in the missing denominator
	if row.Runs != 4 || row.Defined != 2 || row.Censored != 1 || row.Missing != 1 || row.Median.Value == nil || *row.Median.Value != 2 {
		t.Fatal("unavailable acquisition was dropped or used as censor evidence")
	}
	r.Runs = append(r.Runs, RunResult{Configuration: "x", LinkingTimes: []LinkingTime{{Method: "cells", Seconds: Number{Reason: ReasonCensored}, Censored: true}}})
	row = findSummary(t, descriptiveSummaries(r), "cells-time", 0)
	// [1,2,C,C,U] has a censored middle acquired order statistic
	if row.Runs != 5 || row.Defined != 2 || row.Censored != 2 || row.Missing != 1 || row.Median.Value != nil || row.Median.Reason != ReasonCensored {
		t.Fatal("conditional censored median became a fabricated finite value")
	}
}

func TestDescriptiveDoesNotInventClassifierOrTrafficPositions(t *testing.T) {
	r := summaryFixture()
	r.Plan.Set, r.Plan.Phase = Mailbox, Train
	r.Plan.Configurations[0].Controlled = []int{4}
	r.Plan.TrainingReady = true
	r.Plan.FrozenModels = []ModelReference{{Configuration: "x", Population: "request"}, {Configuration: "x", Population: "record"}}
	r.Runs = []RunResult{{Configuration: "x", Flags: []Reason{ReasonChild}}}
	if rows := descriptiveSummaries(r); len(rows) != 0 {
		t.Fatal("training traffic acquired a fitted evaluation position")
	}
	r.Plan.Phase = Primary
	rows := descriptiveSummaries(r)
	if len(rows) != 2 || rows[0].Runs != 1 || rows[0].Missing != 1 || rows[1].Missing != 1 {
		t.Fatal("registered classifier positions vanished after early failure")
	}
	r.Runs = nil
	if rows := descriptiveSummaries(r); len(rows) != 0 {
		t.Fatal("planning-only output invented requested traffic")
	}
}

func TestLinkingTimeTypedUnavailableStates(t *testing.T) {
	for _, link := range []LinkingTime{
		{Method: "cells", Seconds: number(0, ReasonNone)},
		{Method: "frames", Seconds: Number{Reason: ReasonCensored}, Censored: true},
		{Method: "cells", Seconds: Number{Reason: ReasonIncomplete}},
	} {
		if !validLinkingTime(link) {
			t.Fatal("valid finite, censored or unavailable state rejected")
		}
	}
	for _, link := range []LinkingTime{
		{Method: "cells"},
		{Method: "cells", Seconds: number(3, ReasonNone)},
		{Method: "cells", Seconds: number(20, ReasonNone), Censored: true},
		{Method: "cells", Seconds: Number{Reason: ReasonCensored}},
		{Method: "cells", Seconds: Number{Reason: ReasonIncomplete}, Censored: true},
	} {
		if validLinkingTime(link) {
			t.Fatal("inconsistent time state accepted")
		}
	}
}
