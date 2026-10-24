package client_test

import (
	"testing"

	"github.com/jimichi-org/jimichi/client"
)

// five listed nodes and chains of three: a refused node shortens the list, so
// the bound min(missing, listed - hops) follows the shorter list; a refused
// entry or exit is one the mirror does not hold; without refused nodes the
// rule is JudgeMirror
func TestJudgeMirrorAmongKnownAnswers(t *testing.T) {
	all := []bool{true, true, true, true, true}
	for _, c := range []struct {
		name            string
		served, refused []bool
		entry, exit     int
		missing         int
		want            client.MirrorVerdict
		absent, allowed int
	}{
		{"nothing refused", all, nil, 0, -1, 1, client.MirrorTaken, 0, 1},
		{"one refused, missing 0", []bool{true, true, true, false, true}, []bool{false, false, false, true, false}, 0, -1, 0, client.MirrorTaken, 0, 0},
		{"one refused and one left out, missing 1", []bool{true, false, true, false, true}, []bool{false, false, false, true, false}, 0, -1, 1, client.MirrorTaken, 1, 1},
		{"one refused and one left out, missing 0", []bool{true, false, true, false, true}, []bool{false, false, false, true, false}, 0, -1, 0, client.MirrorLacksTooMany, 1, 0},
		{"the entry refused", []bool{false, true, true, true, true}, []bool{true, false, false, false, false}, 0, -1, 1, client.MirrorLacksEntry, 0, 1},
		{"two refused", []bool{true, true, true, false, false}, []bool{false, false, false, true, true}, 0, -1, 1, client.MirrorTaken, 0, 0},
		{"three refused, fewer than hops stay", []bool{true, true, false, false, false}, []bool{false, false, true, true, true}, 0, -1, 1, client.MirrorLacksTooMany, 0, -1},
		{"a refused exit", []bool{true, true, true, false, true}, []bool{false, false, false, true, false}, 0, 3, 1, client.MirrorLacksExit, 0, 1},
		{"an exit that is held", []bool{true, true, true, false, true}, []bool{false, false, false, true, false}, 0, 4, 1, client.MirrorTaken, 0, 1},
	} {
		var verdict client.MirrorVerdict
		var absent, allowed int
		if c.exit < 0 {
			verdict, absent, allowed = client.JudgeMirrorAmong(c.served, c.refused, c.entry, 3, c.missing)
		} else {
			verdict, absent, allowed = client.JudgeMirrorToAmong(c.served, c.refused, c.entry, c.exit, 3, c.missing)
		}
		if verdict != c.want || absent != c.absent || allowed != c.allowed {
			t.Errorf("%s: %d with %d absent of %d allowed, want %d with %d of %d", c.name, verdict, absent, allowed, c.want, c.absent, c.allowed)
		}
	}
	for _, served := range [][]bool{all, {true, false, true, true, true}, {false, true, true, true, true}, {true, false, false, true, true}} {
		for missing := 0; missing <= 2; missing++ {
			v1, a1, l1 := client.JudgeMirror(served, 0, 3, missing)
			v2, a2, l2 := client.JudgeMirrorAmong(served, nil, 0, 3, missing)
			v3, a3, l3 := client.JudgeMirrorAmong(served, make([]bool, 5), 0, 3, missing)
			if v1 != v2 || a1 != a2 || l1 != l2 || v1 != v3 || a1 != a3 || l1 != l3 {
				t.Errorf("served %v missing %d: JudgeMirror %d %d %d, Among %d %d %d and %d %d %d", served, missing, v1, a1, l1, v2, a2, l2, v3, a3, l3)
			}
		}
	}
}
