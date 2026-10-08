package client_test

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/jimichi-org/jimichi/client"
)

// every sequence of draws, draw i taking each of its bounds[i] values once. A
// draw among m reads m+k: no rejection throws that away (2^64 mod m < m) and
// it leaves k, so the streams enumerate the choices of a uniform source
func everyDraw(bounds []int, visit func(values []uint64)) {
	values := make([]uint64, len(bounds))
	var walk func(i int)
	walk = func(i int) {
		if i == len(bounds) {
			visit(slices.Clone(values))
			return
		}
		for k := range bounds[i] {
			values[i] = uint64(bounds[i] + k)
			walk(i + 1)
		}
	}
	walk(0)
}

// the bounds of the draws for the middle hops: n-2 nodes, then one fewer
func middleBounds(n, hops int) []int {
	b := make([]int, 0, hops-2)
	for i := 0; i < hops-2; i++ {
		b = append(b, n-2-i)
	}
	return b
}

func distinctInRange(path []int, n int) bool {
	seen := make(map[int]bool, len(path))
	for _, node := range path {
		if node < 0 || node >= n || seen[node] {
			return false
		}
		seen[node] = true
	}
	return true
}

// one draw among n-1 values gives each node but except exactly once, so a
// uniform source makes every other node equally likely
func TestChooseEntryExceptIsEveryOtherNodeOnce(t *testing.T) {
	for n := 2; n <= 8; n++ {
		for except := range n {
			got := make(map[int]int, n)
			everyDraw([]int{n - 1}, func(values []uint64) {
				stream := words(values...)
				entry, err := client.ChooseEntryExcept(n, except, stream)
				if err != nil || stream.Len() != 0 {
					t.Fatalf("ChooseEntryExcept(%d, %d) on %v = %d, %v with %d bytes left", n, except, values, entry, err, stream.Len())
				}
				got[entry]++
			})
			for node := range n {
				want := 1
				if node == except {
					want = 0
				}
				if got[node] != want {
					t.Fatalf("ChooseEntryExcept(%d, %d) gave node %d %d times over all draws, want %d", n, except, node, got[node], want)
				}
			}
		}
	}
}

// every draw sequence for the middle hops gives a different path, there are
// as many sequences as ordered choices of the middle hops among the n-2 nodes
// left, so each ordered path to the exit comes out exactly once
func TestChooseRestToIsEveryPathOnce(t *testing.T) {
	for n := 2; n <= 7; n++ {
		for hops := 2; hops <= n; hops++ {
			for entry := range n {
				for exit := range n {
					if entry == exit {
						continue
					}
					bounds := middleBounds(n, hops)
					paths := map[string]bool{}
					everyDraw(bounds, func(values []uint64) {
						stream := words(values...)
						path, err := client.ChooseRestTo(entry, exit, n, hops, stream)
						if err != nil || stream.Len() != 0 {
							t.Fatalf("ChooseRestTo(%d, %d, %d, %d) on %v = %v, %v with %d bytes left", entry, exit, n, hops, values, path, err, stream.Len())
						}
						if len(path) != hops || path[0] != entry || path[hops-1] != exit || !distinctInRange(path, n) {
							t.Fatalf("ChooseRestTo(%d, %d, %d, %d) on %v = %v", entry, exit, n, hops, values, path)
						}
						paths[fmt.Sprint(path)] = true
					})
					if want := orderings(n-2, hops-2); len(paths) != want {
						t.Fatalf("ChooseRestTo(%d, %d, %d, %d): %d different paths, want %d", entry, exit, n, hops, len(paths), want)
					}
				}
			}
		}
	}
}

// the entry drawn by ChooseEntryExcept and the rest by ChooseRestTo on one
// stream: every ordered chain of distinct nodes that ends on the exit comes
// out of exactly one draw sequence, (n-1)!/(n-hops)! chains in all
func TestEveryChainToTheExitIsEquallyLikely(t *testing.T) {
	for n := 2; n <= 7; n++ {
		for hops := 2; hops <= n; hops++ {
			for exit := range n {
				bounds := append([]int{n - 1}, middleBounds(n, hops)...)
				chains := map[string]int{}
				everyDraw(bounds, func(values []uint64) {
					stream := words(values...)
					entry, err := client.ChooseEntryExcept(n, exit, stream)
					if err != nil {
						t.Fatal(err)
					}
					path, err := client.ChooseRestTo(entry, exit, n, hops, stream)
					if err != nil || stream.Len() != 0 {
						t.Fatalf("n %d, hops %d, exit %d on %v: %v, %v with %d bytes left", n, hops, exit, values, path, err, stream.Len())
					}
					if path[len(path)-1] != exit || !distinctInRange(path, n) {
						t.Fatalf("n %d, hops %d, exit %d on %v: %v", n, hops, exit, values, path)
					}
					chains[fmt.Sprint(path)]++
				})
				if want := orderings(n-1, hops-1); len(chains) != want {
					t.Fatalf("n %d, hops %d, exit %d: %d different chains, want %d", n, hops, exit, len(chains), want)
				}
				for chain, count := range chains {
					if count != 1 {
						t.Fatalf("n %d, hops %d, exit %d: chain %s from %d draw sequences", n, hops, exit, chain, count)
					}
				}
			}
		}
	}
}

// k ordered picks among m without repeats, m!/(m-k)!
func orderings(m, k int) int {
	out := 1
	for i := range k {
		out *= m - i
	}
	return out
}

// worked by hand for 5 nodes:
//
//	ChooseEntryExcept(5, 1) on 7: 7 mod 4 = 3, at or past 1, so node 4
//	ChooseEntryExcept(5, 3) on 6: 6 mod 4 = 2, below 3, so node 2
//	ChooseRestTo(4, 1, 5, 3) on 6: the others are 0 2 3; 2^64 mod 3 = 1 throws
//	away only 0, and 6 mod 3 = 0 takes node 0, so the path is 4 0 1
//	ChooseRestTo(0, 4, 5, 4) on 4, 7: the others are 1 2 3; 4 mod 3 = 1 takes
//	node 2 and they become 2 1 3; 7 mod 2 = 1 takes node 3; the path is 0 2 3 4
func TestChooseToAFixedExitKnownAnswers(t *testing.T) {
	if entry, err := client.ChooseEntryExcept(5, 1, words(7)); err != nil || entry != 4 {
		t.Fatalf("ChooseEntryExcept(5, 1) on 7 = %d, %v, want 4", entry, err)
	}
	if entry, err := client.ChooseEntryExcept(5, 3, words(6)); err != nil || entry != 2 {
		t.Fatalf("ChooseEntryExcept(5, 3) on 6 = %d, %v, want 2", entry, err)
	}
	if path, err := client.ChooseRestTo(4, 1, 5, 3, words(6)); err != nil || !slices.Equal(path, []int{4, 0, 1}) {
		t.Fatalf("ChooseRestTo(4, 1, 5, 3) on 6 = %v, %v, want [4 0 1]", path, err)
	}
	if path, err := client.ChooseRestTo(0, 4, 5, 4, words(4, 7)); err != nil || !slices.Equal(path, []int{0, 2, 3, 4}) {
		t.Fatalf("ChooseRestTo(0, 4, 5, 4) on 4, 7 = %v, %v, want [0 2 3 4]", path, err)
	}
	// two hops are the entry and the exit, and nothing is drawn
	stream := words(9)
	if path, err := client.ChooseRestTo(3, 1, 5, 2, stream); err != nil || !slices.Equal(path, []int{3, 1}) || stream.Len() != 8 {
		t.Fatalf("ChooseRestTo(3, 1, 5, 2) = %v, %v with %d bytes left, want [3 1] and 8", path, err, stream.Len())
	}
}

func TestChooseToAFixedExitRefusesAnImpossibleChoice(t *testing.T) {
	for _, c := range []struct{ n, except int }{{1, 0}, {0, 0}, {-1, 0}, {5, -1}, {5, 5}} {
		if _, err := client.ChooseEntryExcept(c.n, c.except, words(1, 2, 3)); !errors.Is(err, client.ErrChoice) {
			t.Errorf("ChooseEntryExcept(%d, %d) = %v, want ErrChoice", c.n, c.except, err)
		}
	}
	for _, c := range []struct{ entry, exit, n, hops int }{
		{0, 0, 5, 3},  // the entry is the exit
		{0, 1, 5, 1},  // one hop would make the exit the entry
		{0, 1, 5, 0},  // no hops
		{0, 1, 5, 6},  // more hops than nodes
		{0, 1, 1, 2},  // one node
		{-1, 1, 5, 3}, // an entry before the list
		{5, 1, 5, 3},  // an entry past it
		{0, -1, 5, 3}, // an exit before the list
		{0, 5, 5, 3},  // an exit past it
	} {
		if path, err := client.ChooseRestTo(c.entry, c.exit, c.n, c.hops, words(1, 2, 3)); !errors.Is(err, client.ErrChoice) || path != nil {
			t.Errorf("ChooseRestTo(%d, %d, %d, %d) = %v, %v, want ErrChoice", c.entry, c.exit, c.n, c.hops, path, err)
		}
	}
}

func TestChooseToAFixedExitFailsWhenTheStreamEnds(t *testing.T) {
	if _, err := client.ChooseEntryExcept(5, 0, words()); !errors.Is(err, io.EOF) {
		t.Fatalf("ChooseEntryExcept on an empty stream = %v, want io.EOF", err)
	}
	if path, err := client.ChooseRestTo(0, 4, 5, 4, words(4)); !errors.Is(err, io.EOF) || path != nil {
		t.Fatalf("ChooseRestTo with one draw of two = %v, %v, want io.EOF", path, err)
	}
	// among the three other nodes of four the value 0 is the one thrown away
	if _, err := client.ChooseEntryExcept(4, 0, zeros{}); !errors.Is(err, client.ErrChoice) {
		t.Fatalf("ChooseEntryExcept on a stuck source = %v, want ErrChoice", err)
	}
}

// the verdicts JudgeMirror gives keep their values, and the one for the
// fixed exit comes after them
func TestMirrorVerdictValues(t *testing.T) {
	if client.MirrorTaken != 0 || client.MirrorLacksEntry != 1 || client.MirrorLacksTooMany != 2 || client.MirrorLacksExit != 3 {
		t.Fatalf("verdicts %d %d %d %d", client.MirrorTaken, client.MirrorLacksEntry, client.MirrorLacksTooMany, client.MirrorLacksExit)
	}
}

// five listed nodes, entry 0, exit 4, chains of three unless said otherwise
func TestJudgeMirrorToKnownAnswers(t *testing.T) {
	const y, n = true, false
	for _, c := range []struct {
		name                       string
		served                     []bool
		entry, exit, hops, missing int
		want                       client.MirrorVerdict
		absent, allowed            int
	}{
		{"a full mirror", []bool{y, y, y, y, y}, 0, 4, 3, 1, client.MirrorTaken, 0, 1},
		{"a middle left out", []bool{y, n, y, y, y}, 0, 4, 3, 1, client.MirrorTaken, 1, 1},
		{"the exit left out, within the bound", []bool{y, y, y, y, n}, 0, 4, 3, 1, client.MirrorLacksExit, 1, 1},
		{"the exit left out and too many", []bool{y, y, y, n, n}, 0, 4, 3, 1, client.MirrorLacksTooMany, 2, 1},
		{"the exit and the entry left out", []bool{n, y, y, y, n}, 0, 4, 3, 2, client.MirrorLacksEntry, 2, 2},
		{"the entry left out", []bool{n, y, y, y, y}, 0, 4, 3, 1, client.MirrorLacksEntry, 1, 1},
		{"two hops, only the ends", []bool{y, n, n, n, y}, 0, 4, 2, 3, client.MirrorTaken, 3, 3},
		{"an exit outside the list", []bool{y, y, y, y, y}, 0, 5, 3, 1, client.MirrorLacksExit, 0, 1},
		{"an exit before the list", []bool{y, y, y, y, y}, 0, -1, 3, 1, client.MirrorLacksExit, 0, 1},
	} {
		verdict, absent, allowed := client.JudgeMirrorTo(c.served, c.entry, c.exit, c.hops, c.missing)
		if verdict != c.want || absent != c.absent || allowed != c.allowed {
			t.Errorf("%s: JudgeMirrorTo = %d with %d absent of %d allowed, want %d with %d of %d",
				c.name, verdict, absent, allowed, c.want, c.absent, c.allowed)
		}
	}
}

// every mirror of five nodes, every entry and exit, every chain length and
// bound: JudgeMirrorTo follows the rule as stated (the entry first, then the
// count, then the exit) and differs from JudgeMirror only by MirrorLacksExit
func TestJudgeMirrorToEveryMirror(t *testing.T) {
	const nodes = 5
	for mask := range 1 << nodes {
		served := make([]bool, nodes)
		absent := 0
		for i := range served {
			served[i] = mask&(1<<i) != 0
			if !served[i] {
				absent++
			}
		}
		for entry := range nodes {
			for exit := range nodes {
				if exit == entry {
					continue
				}
				for hops := 2; hops <= nodes; hops++ {
					for missing := 0; missing <= nodes; missing++ {
						allowed := min(missing, nodes-hops)
						want := client.MirrorTaken
						switch {
						case !served[entry]:
							want = client.MirrorLacksEntry
						case absent > allowed:
							want = client.MirrorLacksTooMany
						case !served[exit]:
							want = client.MirrorLacksExit
						}
						got, gotAbsent, gotAllowed := client.JudgeMirrorTo(served, entry, exit, hops, missing)
						if got != want || gotAbsent != absent || gotAllowed != allowed {
							t.Fatalf("mirror %v, entry %d, exit %d, %d hops, missing %d: %d with %d of %d, want %d with %d of %d",
								served, entry, exit, hops, missing, got, gotAbsent, gotAllowed, want, absent, allowed)
						}
						plain, _, _ := client.JudgeMirror(served, entry, hops, missing)
						if got != plain && (got != client.MirrorLacksExit || plain != client.MirrorTaken) {
							t.Fatalf("mirror %v, entry %d, exit %d: JudgeMirrorTo %d against JudgeMirror %d", served, entry, exit, got, plain)
						}
					}
				}
			}
		}
	}
}
