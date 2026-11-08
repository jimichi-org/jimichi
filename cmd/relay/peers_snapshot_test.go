package main

import (
	"bytes"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
	"testing"
	"time"
)

func TestPeerLookupReturnsAnAdmissionSnapshot(t *testing.T) {
	now := time.Unix(100, 0)
	addr := "peer.test:9000"
	c := &peerCache{listed: map[string]bool{addr: true}, entries: map[string]*peerEntry{addr: {peer: relay.Peer{LinkPub: []byte{1, 2}, Identity: []byte{3, 4}}, expires: 200}}, now: func() time.Time { return now }, refused: map[string]*pki.Conflict{}}
	snapshot, ok := c.peer(addr)
	if !ok {
		t.Fatal("current admitted peer missing")
	}
	snapshot.LinkPub[0] = 9
	snapshot.Identity[0] = 9
	again, ok := c.peer(addr)
	if !ok || !bytes.Equal(again.LinkPub, []byte{1, 2}) || !bytes.Equal(again.Identity, []byte{3, 4}) {
		t.Fatal("lookup aliases cache public slices")
	}
	c.mu.Lock()
	c.entries[addr] = &peerEntry{peer: relay.Peer{LinkPub: []byte{5, 6}}, expires: 200}
	c.mu.Unlock()
	if !bytes.Equal(again.LinkPub, []byte{1, 2}) || !bytes.Equal(again.Identity, []byte{3, 4}) {
		t.Fatal("cache replacement mutated admitted snapshot")
	}
	now = time.Unix(200, 0)
	if _, ok := c.peer(addr); ok {
		t.Fatal("expired peer admitted")
	}
	if !bytes.Equal(again.LinkPub, []byte{1, 2}) {
		t.Fatal("expiry mutated earlier snapshot")
	}
}
