package nodeview

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/wire"
)

func setupRecord(side uint16, hop uint8, id uint64) actualSetup {
	return actualSetup{side, hop, id, hop}
}
func appendSetupSeal(p *privateCapture, hop uint8, id uint64) {
	var nonce [24]byte
	binary.BigEndian.PutUint64(nonce[1:9], id)
	p.afterSeal(keyTag{purpose: "setup"}, nonce[:], nil, []byte{wire.Version, byte(wire.KindControl), hop})
}

func TestSetupGenerationFailedAndPartialAttempts(t *testing.T) {
	for _, partial := range [][]uint8{nil, {2}, {2, 1}, {2, 1, 0}} {
		p := &privateCapture{nextSetupHop: 255, route: [3]uint8{0, 1, 2}}
		mark := p.constructionMark()
		for i, h := range []uint8{2, 1, 0} {
			appendSetupSeal(p, h, uint64(i+1))
		}
		group, _, e := p.completedSince(mark)
		if e != nil || group != 1 {
			t.Fatal("initial group")
		}
		for i, h := range partial {
			appendSetupSeal(p, h, uint64(i+4))
		}
		retry := p.constructionMark()
		for i, h := range []uint8{2, 1, 0} {
			appendSetupSeal(p, h, uint64(i+10))
		}
		got, _, e := p.completedSince(retry)
		want := uint32(2)
		if len(partial) > 0 {
			want = 3
		}
		if e != nil || got != want {
			t.Fatalf("partial %v: group %d, %v", partial, got, e)
		}
		owners, e := parseSetupOwnership(p.truth.setups)
		if e != nil {
			t.Fatal(e)
		}
		owner, _ := owners.lookup(setupIdentity{10, 2})
		if !owner.complete || owner.group != want {
			t.Fatal("controller ordinal differs")
		}
		if len(partial) == 1 || len(partial) == 2 {
			partialOwner, _ := owners.lookup(setupIdentity{4, 2})
			if partialOwner.complete {
				t.Fatal("partial group became complete")
			}
		}
		if _, _, e = p.completedSince(p.constructionMark()); e == nil {
			t.Fatal("stale completion accepted")
		}
	}
}

func TestSetupGenerationGrammarAndInterleaving(t *testing.T) {
	for _, hops := range [][]uint8{{1}, {0}, {2, 0}, {2, 1, 1}, {2, 1, 0, 0}} {
		var records []actualSetup
		for i, h := range hops {
			records = append(records, setupRecord(0, h, uint64(i+1)))
		}
		if _, e := parseSetupOwnership(records); e == nil {
			t.Fatalf("invalid sequence %v accepted", hops)
		}
	}
	records := []actualSetup{setupRecord(0, 2, 1), setupRecord(1, 2, 2), setupRecord(0, 1, 3), setupRecord(1, 1, 4), setupRecord(1, 0, 5), setupRecord(0, 0, 6)}
	owners, e := parseSetupOwnership(records)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range owners {
		owner := entry.owner
		if !owner.complete || owner.group != 1 {
			t.Fatal("interleaving changed generation")
		}
	}
	p := &privateCapture{generation: math.MaxUint32, nextSetupHop: 255}
	appendSetupSeal(p, 2, 1)
	if p.err != ReasonLimit {
		t.Fatal("ordinal overflow accepted")
	}
}

func TestSetupGenerationFullAADAndNonceDomain(t *testing.T) {
	for _, ad := range [][]byte{{1, 3, 2}, {2, 1, 2}, {2, 3, 3}} {
		p := &privateCapture{nextSetupHop: 255}
		var nonce [24]byte
		p.afterSeal(keyTag{purpose: "setup"}, nonce[:], nil, ad)
		if p.err != ReasonContract {
			t.Fatal("invalid setup AAD accepted")
		}
	}
}
