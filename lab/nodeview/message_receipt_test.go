package nodeview

import (
	"bytes"
	"testing"
)

func TestJoinedMessageReceiptsCountOnlyUnmatchedSends(t *testing.T) {
	type message struct {
		side          uint16
		body          byte
		sent, replied bool
	}
	for _, entry := range []struct {
		name     string
		messages []message
		replied  []bool
		want     uint64
	}{
		{"cross-peer", []message{{0, 1, true, false}, {1, 1, false, true}}, []bool{true, true}, 0},
		{"missing-receipt", []message{{0, 1, true, false}, {1, 2, false, true}}, []bool{false, true}, 1},
		{"unsent", []message{{0, 1, false, false}, {1, 1, false, true}}, []bool{false, true}, 0},
		{"echo", []message{{0, 1, true, true}, {1, 2, true, false}}, []bool{true, false}, 1},
		{"two-missing", []message{{0, 1, true, false}, {1, 2, true, false}, {2, 3, false, true}}, []bool{false, false, true}, 2},
		{"no-sends", nil, nil, 0},
	} {
		t.Run(entry.name, func(t *testing.T) {
			truth := privateTruth{arena: logicalChunkArena(t, 4096, 4096, 4096, nil)}
			var bodies [][]byte
			for _, row := range entry.messages {
				body := bytes.Repeat([]byte{0x53}, 128)
				body[len(body)-1] = row.body
				ref, ok := truth.arena.copy(body)
				if !ok {
					t.Fatal("receipt fixture allocation failed")
				}
				truth.messages = append(truth.messages, actualMessage{side: row.side, body: ref, sent: row.sent, replied: row.replied})
				bodies = append(bodies, bytes.Clone(body))
			}
			if got := truth.resolveMessageReceipts(); got != entry.want {
				t.Fatalf("unmatched sent messages: got %d, want %d", got, entry.want)
			}
			for i, got := range truth.messages {
				if got.side != entry.messages[i].side || got.sent != entry.messages[i].sent || got.replied != entry.replied[i] || !bytes.Equal(truth.arena.bytes(got.body), bodies[i]) {
					t.Fatal("receipt join changed a sender, send fact, body or unmatched receive fact")
				}
			}
			if got := truth.resolveMessageReceipts(); got != entry.want {
				t.Fatal("repeating the receipt join changed its count")
			}
		})
	}
}
