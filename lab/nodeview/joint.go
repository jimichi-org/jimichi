package nodeview

import (
	"context"
	"reflect"
)

func JointMainInference(collude, mailbox Report) ([]Inference, error) {
	if collude.validate() != nil || mailbox.validate() != nil || collude.Plan.Set != Collude || mailbox.Plan.Set != Mailbox || collude.Plan.Phase != Primary || mailbox.Plan.Phase != Primary || collude.Plan.Suite != "c25519" || mailbox.Plan.Suite != "c25519" || collude.Plan.Digest == "" || mailbox.Plan.Digest == "" {
		return nil, ErrInvalid
	}
	a, b := collude.Plan, mailbox.Plan
	if a.ParentDigest == "" || b.ParentDigest == "" {
		return nil, ErrInvalid
	}
	if !a.PilotReady || !b.PilotReady || !a.TrainingReady || !b.TrainingReady || !samePlanningContract(a, b) || !reflect.DeepEqual(a.Powers, b.Powers) || !reflect.DeepEqual(a.PowerSearch, b.PowerSearch) || !reflect.DeepEqual(a.FrozenModels, b.FrozenModels) || len(a.Powers) != 13 || len(a.PowerSearch) != 13 {
		return nil, ErrInvalid
	}
	if collude.Manifest.Revision != mailbox.Manifest.Revision || collude.Manifest.Tree != mailbox.Manifest.Tree || collude.Manifest.BinarySHA256 != mailbox.Manifest.BinarySHA256 || collude.Manifest.Runtime != mailbox.Manifest.Runtime || collude.Manifest.Suite != mailbox.Manifest.Suite {
		return nil, ErrInvalid
	}
	for _, plan := range []Plan{a, b} {
		if e := validateRegisteredPlanning(context.Background(), plan); e != nil {
			return nil, e
		}
	}
	for _, report := range []Report{collude, mailbox} {
		for _, row := range report.Plan.Configurations {
			if row.Population != "link" && row.Population != "classifier" {
				continue
			}
			n := row.Main
			if row.Population == "link" {
				found := false
				for _, power := range a.Powers {
					if power.ID == row.ID {
						if n != power.N {
							return nil, ErrInvalid
						}
						found = true
					}
				}
				if !found {
					return nil, ErrInvalid
				}
			} else {
				period := "mail-P" + decimal(int(row.Settings.RelayPeriodNS))
				expected := 0
				for _, power := range a.Powers {
					if power.ID == period+"-request" || power.ID == period+"-record" {
						expected = max(expected, power.N)
					}
				}
				if expected == 0 || n != expected {
					return nil, ErrInvalid
				}
			}
		}
	}
	runs := make([]RunResult, 0, len(collude.Runs)+len(mailbox.Runs))
	runs = append(runs, collude.Runs...)
	runs = append(runs, mailbox.Runs...)
	_, difference, e := summarizeInferences(a, runs)
	return difference, e
}
