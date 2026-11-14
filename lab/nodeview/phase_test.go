package nodeview

import (
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"testing"
)

func TestPhasePredecessorsNeverRefillTrainingOrPilot(t *testing.T) {
	c := Config{Set: Mailbox, Phase: Train, Suite: jcrypto.SuiteC25519}
	p := Plan{Set: Mailbox, Suite: "c25519", Phase: Structural}
	if !validPhasePredecessor(c, p) {
		t.Fatal("initial training registration rejected")
	}
	p.Phase = Train
	if validPhasePredecessor(c, p) {
		t.Fatal("training plan retrained")
	}
	p.TrainingReady = true
	p.FrozenModels = make([]ModelReference, 8)
	c.Phase = Pilot
	if !validPhasePredecessor(c, p) {
		t.Fatal("trained mailbox pilot rejected")
	}
	p.Phase = Pilot
	if validPhasePredecessor(c, p) {
		t.Fatal("pilot rerun from its own outcome")
	}
	c.Phase = Primary
	p.PilotReady = true
	if !validPhasePredecessor(c, p) {
		t.Fatal("registered main successor rejected")
	}
	p.Phase = Primary
	if validPhasePredecessor(c, p) {
		t.Fatal("main outcome used as a predecessor")
	}
	c.Suite = jcrypto.SuiteGOST
	p.Suite = "gost"
	p.Phase = Train
	p.PilotReady = false
	if !validPhasePredecessor(c, p) {
		t.Fatal("GOST dedicated evaluation rejected")
	}
	p.Phase = Pilot
	if validPhasePredecessor(c, p) {
		t.Fatal("GOST evaluation duplicated after pilot")
	}
}
