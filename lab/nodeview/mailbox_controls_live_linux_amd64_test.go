//go:build linux && amd64

package nodeview

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func TestNodeViewMailboxControlsOptimized(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("optimized owned-process integration")
	}
	if e := protectProcess(controllerArenaBytes); e != nil {
		t.Fatal(e)
	}
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			for _, name := range []string{"defaults-P0", "defaults-P33250000", "boundary-rebuild", "boundary-pre-session"} {
				t.Run(name, func(t *testing.T) {
					c := Config{Set: Mailbox, Phase: Structural, Suite: s, Seed: 11701, Revision: strings.Repeat("1", 40), resources: &resourceUsage{}}
					task := canonicalMailboxControl(t, c, name)
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
					defer cancel()
					result, audit, training, e := executeTask(ctx, c, task, nil)
					defer func() {
						for i := range audit {
							wipeRankAudit(&audit[i])
						}
						clear(audit[:cap(audit)])
						for i := range training {
							training[i].wipe()
						}
						clear(training[:cap(training)])
					}()
					if e != nil || len(result.Flags) != 0 {
						t.Fatalf("control execution: reason=%s flags=%v counts=%+v %s", reasonOf(e), result.Flags, result.Counts, formatBoundEvidence(e))
					}
					population := uint64(2)
					if strings.HasPrefix(name, "defaults-") {
						population = 16
					}
					if result.Counts.Planned != population || result.Counts.Attempted != population || result.Counts.Established != population || result.Counts.PreflightOK != population {
						t.Fatalf("canonical control population incomplete: %+v", result.Counts)
					}
					switch name {
					case "defaults-P0", "defaults-P33250000":
						if result.Counts.MessageBearing != 16 || result.MeasuredMessages != 1600 {
							t.Fatal("defaults did not retain all 100 accepted attempts per original side")
						}
					case "boundary-rebuild":
						if result.Counts.MessageBearing != 2 || result.MeasuredMessages != 4 || result.Counts.Rebuilt < 1 || result.Counts.Unanswered != 0 {
							t.Fatal("rebuild lacked actual attachment or all four delivered sources")
						}
					case "boundary-pre-session":
						if result.Counts.MessageBearing != 0 || result.MeasuredMessages != 0 {
							t.Fatal("pre-session control manufactured a source message")
						}
					}
					if len(training) != 0 || result.CostsNS[6] <= 0 || quarantinedFixtures.Load() != 0 {
						t.Fatal("control retained training or incomplete fixture ownership")
					}
					point := c.resources.snapshot(result.MaxRSS, nil)
					if point.MaxRSS == nil || *point.MaxRSS == 0 || point.Reason != ReasonNone {
						t.Fatal("control resource receipts did not finish through owned Wait")
					}
				})
			}
		})
	}
}

func canonicalMailboxControl(t *testing.T, c Config, name string) executionTask {
	t.Helper()
	id := name
	if strings.HasPrefix(name, "defaults-") {
		id = "mail-" + strings.TrimPrefix(name, "defaults-") + "-defaults"
	}
	var task executionTask
	count := 0
	for _, candidate := range registeredTasks(c, Plan{Configurations: canonicalCoordinates(Mailbox)}) {
		if candidate.coordinate.ID == id {
			task, count = candidate, count+1
		}
	}
	if count != 1 || task.repeat != 0 || task.missing != 2 || task.coordinate.Topology != "peer" || task.coordinate.Trust != "trusted" || !reflect.DeepEqual(task.coordinate.Controlled, []int{4}) {
		t.Fatal("canonical Structural11701 control is absent or ambiguous")
	}
	if strings.HasPrefix(name, "defaults-") {
		period := int64(0)
		if name == "defaults-P33250000" {
			period = 33250000
		}
		if task.coordinate.Settings != defaultsSettings(period) || task.coordinate.Settings.DurationNS != int64(30*time.Second) || task.coordinate.Population != "defaults-control" || task.coordinate.Conversations != 8 || task.plannedSides != 16 || task.structural || len(task.routes) != 0 {
			t.Fatal("defaults scientific settings, source contract or full population changed")
		}
		routes := drawRoutes(c, task.coordinate, task.plannedSides, task.repeat)
		defer clear(routes)
		if len(routes) != 16 {
			t.Fatal("defaults canonical route machinery omitted an original side")
		}
		for _, route := range routes {
			if route[2] != 4 || route[0] == route[1] || route[0] == 4 || route[1] == 4 {
				t.Fatal("defaults route left the canonical mailbox population")
			}
		}
	} else {
		profile, ok := boundaryProfileFor(task.coordinate.Settings.ControlProfile)
		settings, settingsOK := boundaryProfileSettings(task.coordinate.Settings.ControlProfile)
		if !ok || !settingsOK || profile.name != name || task.coordinate.Settings != settings || settings.DurationNS != int64(20*time.Second) || task.coordinate.Population != "boundary" || task.coordinate.Conversations != 1 || task.plannedSides != 0 || !task.structural || !reflect.DeepEqual(task.routes, profile.routes[:]) {
			t.Fatal("boundary scientific settings, sources or canonical routes changed")
		}
		if name == "boundary-rebuild" && (profile.sourceCount != 2 || profile.sourceOffsetsNS != [2]int64{int64(time.Second), int64(10 * time.Second)} || profile.actionAtNS != int64(5*time.Second) || profile.actions[0] != boundaryCloseInitialAtTime) {
			t.Fatal("registered rebuild actions changed")
		}
		if name == "boundary-pre-session" && (profile.sourceCount != 0 || profile.pairedBeforeBegin || profile.actionAtNS != int64(5*time.Second) || profile.actions != [2]boundaryAction{boundaryPairAtTime, boundaryPairAtTime}) {
			t.Fatal("registered delayed-pair actions changed")
		}
	}
	return task
}
