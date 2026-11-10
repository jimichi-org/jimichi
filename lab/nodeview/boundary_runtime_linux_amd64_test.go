//go:build linux && amd64

package nodeview

import (
	"reflect"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
)

func TestBoundarySharedSettingsCodec(t *testing.T) {
	for id := uint8(0); id <= 7; id++ {
		s := peerSettings(false, 0)
		if id > 0 {
			s, _ = boundaryProfileSettings(id)
		}
		w := encoder{}
		encodeSettings(&w, s)
		if len(w.b) != 93 || w.b[92] != id {
			t.Fatal("shared profile field moved or disappeared")
		}
		r := decoder{b: w.b}
		got := decodeSettings(&r)
		if r.end() != nil || got != s || got.validate(true) != nil {
			t.Fatal("settings round trip")
		}
		for n := 0; n < len(w.b); n++ {
			r := decoder{b: w.b[:n]}
			decodeSettings(&r)
			if r.end() == nil {
				t.Fatal("legacy/truncated settings accepted")
			}
		}
		w.b[92] = 8
		r = decoder{b: w.b}
		decodeSettings(&r)
		if r.end() == nil {
			t.Fatal("unknown profile accepted")
		}
	}
}

func TestBoundaryPublicCardSettingsAndPhaseTasks(t *testing.T) {
	own, peer := e2e.Card{Static: []byte{1}}, e2e.Card{Static: []byte{2}}
	s, _ := boundaryProfileSettings(6)
	for _, side := range []uint16{0, 1} {
		initiator, responder, e := boundaryClientSettings(s, side, own, peer)
		want, _ := boundaryProfileSideSettings(6, 0)
		if e != nil || responder || initiator != want {
			t.Fatal("smaller public Static did not select initiator settings")
		}
		got, responder, e := boundaryClientSettings(s, side, peer, own)
		want, _ = boundaryProfileSideSettings(6, 1)
		if e != nil || !responder || got != want {
			t.Fatal("larger public Static did not select responder settings")
		}
	}
	if _, _, e := boundaryClientSettings(s, 0, own, own); e == nil {
		t.Fatal("equal Static accepted")
	}
	for _, phase := range []Phase{Structural, Train, Pilot, Primary} {
		c := Config{Set: Mailbox, Phase: phase, Suite: jcrypto.SuiteC25519}
		p := Plan{Configurations: canonicalCoordinates(Mailbox)}
		count := 0
		for _, task := range registeredTasks(c, p) {
			if task.coordinate.Settings.ControlProfile == 0 {
				continue
			}
			count++
			profile, _ := boundaryProfileFor(task.coordinate.Settings.ControlProfile)
			if phase != Structural || task.repeat != 0 || !reflect.DeepEqual(task.routes, profile.routes[:]) {
				t.Fatal("boundary escaped its exact structural route recipe")
			}
		}
		if phase == Structural && count != 7 || phase != Structural && count != 0 {
			t.Fatal("boundary phase membership")
		}
	}
}

func TestTrainingTasksRandomizeCoverPairsWithoutRefill(t *testing.T) {
	c := Config{Set: Mailbox, Phase: Train, Suite: jcrypto.SuiteC25519, Seed: 117}
	tasks := pairedMailboxTasks(c, Plan{Configurations: canonicalCoordinates(Mailbox)})
	if len(tasks) != 20 {
		t.Fatal("five runs per four configurations required")
	}
	seen := map[string]map[int]bool{}
	for i := 0; i < len(tasks); i += 2 {
		a, b := tasks[i], tasks[i+1]
		if a.repeat != b.repeat || a.coordinate.Settings.RelayPeriodNS != b.coordinate.Settings.RelayPeriodNS || a.coordinate.Settings.CoverPuts == b.coordinate.Settings.CoverPuts {
			t.Fatal("cover pair lost its repeat")
		}
		for _, task := range []executionTask{a, b} {
			if task.coordinate.Population != "classifier" || task.coordinate.Settings.ControlProfile != 0 || task.repeat < 0 || task.repeat >= 5 {
				t.Fatal("nontraining coordinate")
			}
			if seen[task.coordinate.ID] == nil {
				seen[task.coordinate.ID] = map[int]bool{}
			}
			if seen[task.coordinate.ID][task.repeat] {
				t.Fatal("training refill")
			}
			seen[task.coordinate.ID][task.repeat] = true
		}
	}
	if len(seen) != 4 {
		t.Fatal("training matrix missing")
	}
}
