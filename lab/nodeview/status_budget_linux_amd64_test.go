//go:build linux && amd64

package nodeview

import (
	"bytes"
	"context"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
)

func TestStatusCloneReservesBeforeCopyAndSurvivesUntilConsumption(t *testing.T) {
	source := []byte{1, 2, 3}
	b := &memoryBudget{limit: 2}
	if body, n, e := copyStatusBody(&decoder{b: source}, b); reasonOf(e) != ReasonLimit || body != nil || n != 0 || b.used != 0 {
		t.Fatal("over-budget status was copied")
	}
	b.limit = 8
	first, n, e := copyStatusBody(&decoder{b: source}, b)
	if e != nil || n != 3 || cap(first) != 3 || b.used != 3 {
		t.Fatal("exact status backing not charged")
	}
	child := &ownedChild{status: make(chan statusFrame, 2), statusBudget: b}
	child.status <- statusFrame{op: opBoot, body: first, charged: n}
	r, e := child.expect(context.Background(), opBoot, time.Now().Add(time.Second))
	if e != nil || r.u8() != 1 || b.used != 3 {
		t.Fatal("status released while borrowed decoder is live")
	}
	next, n, e := copyStatusBody(&decoder{b: []byte{4}}, b)
	if e != nil {
		t.Fatal(e)
	}
	child.status <- statusFrame{op: opReady, body: next, charged: n}
	if _, e := child.expect(context.Background(), opReady, time.Now().Add(time.Second)); e != nil || b.used != 1 {
		t.Fatal("previous status ownership not released")
	}
	for _, v := range first {
		if v != 0 {
			t.Fatal("previous status body not wiped")
		}
	}
	child.releaseStatusBody()
	if b.used != 0 || next[0] != 0 {
		t.Fatal("last status body not wiped and released")
	}
}

func TestClientPhysicalCommandStatusAndTerminalBudgets(t *testing.T) {
	a := outcomeTestArena(t)
	ref := outcomeTestCopy(t, a, bytes.Repeat([]byte{7}, 128))
	grant, e := sourceAttemptCeiling()
	if e != nil {
		t.Fatal(e)
	}
	plan := workloadPlan{route: [3]uint8{0, 1, 4}, topology: 2, sourceLimit: grant, bodyArena: a, bodies: make([]arenaRef, 128), contact: make([]byte, 2048)}
	for i := range plan.bodies {
		plan.bodies[i] = ref
	}
	w := encodeWorkload(plan)
	if len(w.b) != 18471 || len(w.b)+30 != 18501 {
		t.Fatal("maximum private plan framing changed")
	}
	w.wipe()
	cfg := applicationConfig{suite: jcrypto.SuiteC25519, topology: 2, anchor: pki.Anchor{Suite: jcrypto.SuiteC25519, Pub: make([]byte, 186)}, settings: peerSettings(false, 0), roster: make([]publicRelay, 5)}
	for i := range cfg.roster {
		cfg.roster[i] = publicRelay{port: uint16(i + 1), bundle: make([]byte, 4096)}
	}
	configure := encodeApplication(cfg)
	// the 256-byte anchor field is conservative: c25519 plus base64 reaches 255 bytes
	if len(cfg.anchor.String()) != 255 || len(configure.b)+30+1 != 20889 {
		t.Fatal("configure upper field-width bound changed")
	}
	configure.wipe()
	contact := encoder{}
	contact.u16(1)
	contact.bytes(make([]byte, 2048), 2048)
	begin := encoder{}
	begin.i64(1)
	begin.i64(30000000000)
	begin.i64(30000000001)
	stop := encoder{}
	stop.u8(0)
	ack := encoder{}
	ack.u8(0)
	if len(contact.b)+30 != 2082 || len(begin.b)+30 != 54 || len(stop.b)+30 != 31 || len(ack.b)+30 != 31 || 20889+18501+2082+54+31+31 != 41588 {
		t.Fatal("whole command stream or reserved Stop/Ack margin changed")
	}
	contact.wipe()
	begin.wipe()
	stop.wipe()
	var commands, output bytes.Buffer
	command := protocolWriter{w: &commands, limit: controllerArenaBytes}
	if e := command.send(opAck, ack); e != nil {
		t.Fatal(e)
	}
	status := &protocolWriter{w: &output, limit: clientArenaBytes}
	reader, e := newProtocolReader(&commands, [16]byte{}, controllerArenaBytes)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.close()
	c := &childIO{command: reader, status: status, view: &protocolWriter{}, truth: &protocolWriter{}}
	boot := encoder{}
	boot.u8(roleClient)
	boot.u8(byte(jcrypto.SuiteC25519))
	boot.u16(0)
	boot.u8(1)
	if e := status.send(opBoot, boot); e != nil {
		t.Fatal(e)
	}
	for i := range 3 {
		if e := c.ready(byte(i + 1)); e != nil {
			t.Fatal(e)
		}
	}
	contact = encoder{}
	contact.u16(1)
	contact.bytes(make([]byte, 2048), 2048)
	if e := status.send(opContact, contact); e != nil {
		t.Fatal(e)
	}
	for range 5 {
		if e := c.errorStatus(ReasonLimit); e != nil {
			t.Fatal(e)
		}
	}
	before := status.bytes
	if e := c.terminal(Counts{}, ReasonLimit); e != nil || status.bytes-before != 216 {
		t.Fatal("actual full End no longer occupies 216 wire bytes")
	}
	cleaned := encoder{}
	cleaned.bool(true)
	cleaned.bool(true)
	if e := status.send(opCleaned, cleaned); e != nil {
		t.Fatal(e)
	}
	if status.bytes != 2616 || status.frames != 12 || output.Len() != 2616 || 216+32+2*31 != 310 || 1+1+2 != 4 || 31+31 != 62 {
		t.Fatal("independent status stream or terminal margins changed")
	}
}
