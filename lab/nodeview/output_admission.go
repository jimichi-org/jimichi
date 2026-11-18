package nodeview

import "github.com/jimichi-org/jimichi/lab"

func auditMethodOrdinal(a RankAudit, pair bool) (int, bool) {
	switch a.Method {
	case "setup", "close", "shared", "mixed":
		if !pair || a.WindowNS != 0 {
			return 0, false
		}
		for i, name := range []string{"setup", "close", "shared", "mixed"} {
			if a.Method == name {
				return i, true
			}
		}
	case "cells", "frames":
		if !pair {
			return 0, false
		}
		for i, w := range []int64{1000000000, 2000000000, 5000000000, 10000000000, 20000000000} {
			if a.WindowNS == w {
				return 4 + 2*i + boolInt(a.Method == "frames"), true
			}
		}
	case "request", "record":
		base := 0
		if pair {
			base = 14
		}
		return base + boolInt(a.Method == "record"), true
	}
	return 0, false
}

func admitTaskOutput(c Config, task executionTask, row RunResult, audits []RankAudit, charge *resultCharge) error {
	if row.Configuration != task.coordinate.ID || row.Phase != c.Phase || row.Repeat != task.repeat || len(row.Flags) > 128 || len(row.RouteHistogram) > 5 {
		return fail(ReasonContract)
	}
	for _, flag := range row.Flags {
		if !validReason(flag) {
			return fail(ReasonContract)
		}
	}
	if row.Seed != nodeSeed(c, coordinateID(row.Configuration), uint64(row.Repeat), 0, lab.StreamNodeMain) {
		return fail(ReasonContract)
	}
	seen := map[struct {
		method string
		window int64
	}]bool{}
	defer clear(seen)
	for _, a := range audits {
		key := struct {
			method string
			window int64
		}{a.Method, a.WindowNS}
		if seen[key] {
			return fail(ReasonContract)
		}
		seen[key] = true
		ordinal, ok := auditMethodOrdinal(a, len(task.coordinate.Controlled) == 2)
		if !ok || a.Configuration != row.Configuration || a.Repeat != row.Repeat || a.Seed != nodeSeed(c, coordinateID(row.Configuration), uint64(row.Repeat), uint64(ordinal), lab.StreamNodeBootstrap) || (a.Method == "request" || a.Method == "record") && a.WindowNS != task.coordinate.Settings.DurationNS {
			return fail(ReasonContract)
		}
		matches := 0
		for _, m := range row.Methods {
			if m.Method == a.Method && m.WindowNS == a.WindowNS {
				matches++
				if e := validateRankRelease(m, a, charge.budget); e != nil {
					return e
				}
			}
		}
		if matches != 1 {
			return fail(ReasonContract)
		}
	}
	if charge.budget == nil {
		charge.cleaned()
	}
	return charge.admit(len(audits), c.outputBudget)
}
