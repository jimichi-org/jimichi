package nodeview

import (
	"errors"
	"reflect"
	"testing"
)

func TestForeignTrustCoordinates(t *testing.T) {
	want := []struct {
		id, topology string
		missing      uint8
		foreign      []int
	}{
		{"trust-echo-k1-m0", "echo", 0, []int{0}},
		{"trust-echo-k1-m1", "echo", 1, []int{0}},
		{"trust-echo-k1-m2", "echo", 2, []int{0}},
		{"trust-echo-k2-m0", "echo", 0, []int{0, 1}},
		{"trust-echo-k2-m1", "echo", 1, []int{0, 1}},
		{"trust-echo-k2-m2", "echo", 2, []int{0, 1}},
		{"trust-peer-honest-k1-m0", "peer", 0, []int{0}},
		{"trust-peer-honest-k1-m1", "peer", 1, []int{0}},
		{"trust-peer-honest-k1-m2", "peer", 2, []int{0}},
		{"trust-peer-honest-k2-m0", "peer", 0, []int{0, 1}},
		{"trust-peer-honest-k2-m1", "peer", 1, []int{0, 1}},
		{"trust-peer-honest-k2-m2", "peer", 2, []int{0, 1}},
		{"trust-peer-foreign-k1-m0", "peer", 0, []int{4}},
		{"trust-peer-foreign-k1-m1", "peer", 1, []int{4}},
		{"trust-peer-foreign-k1-m2", "peer", 2, []int{4}},
		{"trust-peer-foreign-k2-m0", "peer", 0, []int{0, 4}},
		{"trust-peer-foreign-k2-m1", "peer", 1, []int{0, 4}},
		{"trust-peer-foreign-k2-m2", "peer", 2, []int{0, 4}},
	}
	got := foreignTrustCoordinates()
	if len(got) != 19 {
		t.Fatalf("coordinates: got %d, want 19", len(got))
	}
	seen := make(map[string]bool)
	for i, expected := range want {
		t.Run(expected.id, func(t *testing.T) {
			row := got[i]
			if seen[row.ID] || row.ID != expected.id {
				t.Fatalf("duplicate or unexpected ID: %q", row.ID)
			}
			seen[row.ID] = true
			if row.Topology != expected.topology || row.Trust != "foreign" || row.Population != "trust" || row.Placement != "drawn" || row.Setup != "serial" || row.Mode != "immediate" {
				t.Fatalf("coordinate metadata: %+v", row)
			}
			if row.N != 5 || row.H != 3 || row.Missing != expected.missing || !reflect.DeepEqual(row.Controlled, expected.foreign) || !reflect.DeepEqual(row.ForeignPositions, expected.foreign) {
				t.Fatalf("trust membership: %+v", row)
			}
			settings, mailbox := echoSettings(0), uint8(255)
			if expected.topology == "peer" {
				settings, mailbox = peerSettings(false, 0), 4
			}
			if row.Mailbox != mailbox || row.Settings != settings || row.Slots != 0 || row.Flows != 0 || row.Conversations != 0 || row.Training != 0 || row.Pilots != 0 || row.Main != 30 {
				t.Fatalf("structural registration: %+v", row)
			}
		})
	}
	membership := Coordinate{ID: "trust-unlisted", Topology: "echo", Trust: "trusted", Population: "membership", Missing: 2, Mailbox: 255, Placement: "unlisted", Setup: "serial", Mode: "immediate", N: 5, H: 3, Main: 30, Settings: echoSettings(0)}
	if seen[got[18].ID] || !reflect.DeepEqual(got[18], membership) {
		t.Fatalf("unlisted own-CA membership metadata: %+v", got[18])
	}
}

func TestStructuralTrustTasksComplete(t *testing.T) {
	coordinates := foreignTrustCoordinates()
	c := Config{Set: Compromise, Phase: Structural, Seed: 42}
	tasks := structuralTrustTasks(c, coordinates)
	if len(tasks) != 25 {
		t.Fatalf("cohorts: got %d, want 25", len(tasks))
	}
	if !reflect.DeepEqual(tasks, structuralTrustTasks(c, coordinates)) {
		t.Fatal("task schedule changed with the same configuration")
	}
	byID := make(map[string][]executionTask)
	total := 0
	for _, task := range tasks {
		byID[task.coordinate.ID] = append(byID[task.coordinate.ID], task)
		total += len(task.routes)
	}
	// six echo rows use 5*4*3 paths; twelve pinned rows use 4*3 paths
	if total != 504 || len(byID) != 19 {
		t.Fatalf("attempted slots %d, coordinates %d", total, len(byID))
	}
	for _, coordinate := range coordinates {
		t.Run(coordinate.ID, func(t *testing.T) {
			cohorts := byID[coordinate.ID]
			if coordinate.Population == "membership" {
				if len(cohorts) != 1 {
					t.Fatalf("membership tasks: got %d, want 1", len(cohorts))
				}
				want := executionTask{coordinate: coordinate, missing: 2, structural: true, membership: true}
				if !reflect.DeepEqual(cohorts[0], want) {
					t.Fatalf("membership is not a route or foreign-CA attempt: %+v", cohorts[0])
				}
				return
			}
			wantSizes := []int{32, 28}
			wantPaths, perEntry, foreignPaths := 60, 12, 36
			if len(coordinate.ForeignPositions) == 2 {
				foreignPaths = 54
			}
			if coordinate.Topology == "peer" {
				wantSizes, wantPaths, perEntry, foreignPaths = []int{12}, 12, 3, 6
				if len(coordinate.ForeignPositions) == 2 {
					foreignPaths = 10
				}
				for _, position := range coordinate.ForeignPositions {
					if position == 4 {
						foreignPaths = 12
					}
				}
			}
			if len(cohorts) != len(wantSizes) {
				t.Fatalf("cohort count: got %d, want %d", len(cohorts), len(wantSizes))
			}
			seen := make(map[[3]uint8]bool)
			var entries [5]int
			withForeign := 0
			for i, task := range cohorts {
				if len(task.routes) != wantSizes[i] || len(task.routes) > 32 || task.repeat != i || !task.structural || task.membership || task.missing != coordinate.Missing || !reflect.DeepEqual(task.foreign, coordinate.ForeignPositions) || !reflect.DeepEqual(task.coordinate, coordinate) {
					t.Fatalf("cohort %d metadata or size: %+v", i, task)
				}
				if coordinate.Topology == "peer" && len(task.routes)%2 != 0 {
					t.Fatal("peer side has no partner")
				}
				for _, path := range task.routes {
					if path[0] >= 5 || path[1] >= 5 || path[2] >= 5 || path[0] == path[1] || path[0] == path[2] || path[1] == path[2] || seen[path] {
						t.Fatalf("duplicate or invalid path: %v", path)
					}
					if coordinate.Topology == "peer" && path[2] != 4 {
						t.Fatalf("unpinned peer path: %v", path)
					}
					seen[path] = true
					entries[path[0]]++
					foreign := false
					for _, position := range coordinate.ForeignPositions {
						for _, node := range path {
							foreign = foreign || int(node) == position
						}
					}
					if foreign {
						withForeign++
					}
				}
			}
			// without one/two foreign nodes echo has 4*3*2 / 3*2*1 paths; honest pinned peer has 3*2 / 2*1
			if len(seen) != wantPaths || withForeign != foreignPaths {
				t.Fatalf("path coverage: %d paths, %d with foreign; want %d, %d", len(seen), withForeign, wantPaths, foreignPaths)
			}
			for entry, count := range entries {
				want := perEntry
				if coordinate.Topology == "peer" && entry == 4 {
					want = 0
				}
				if count != want {
					t.Fatalf("entry %d: got %d, want %d", entry, count, want)
				}
			}
		})
	}
}

func TestStructuralTrustTaskFilters(t *testing.T) {
	coordinates := foreignTrustCoordinates()
	coordinates = append(coordinates, Coordinate{ID: "E1", Topology: "echo", Population: "E1"})
	c := Config{Set: Compromise, Phase: Structural, Peer: true}
	tasks := structuralTrustTasks(c, coordinates)
	if len(tasks) != 12 {
		t.Fatalf("peer cohorts: got %d, want 12", len(tasks))
	}
	sides := 0
	for _, task := range tasks {
		if task.coordinate.Topology != "peer" || task.coordinate.Population != "trust" {
			t.Fatalf("unexpected peer coordinate: %+v", task.coordinate)
		}
		sides += len(task.routes)
	}
	if sides != 144 || sides/2 != 72 {
		t.Fatalf("got %d peer sides, want 144 sides/72 conversations", sides)
	}
	for _, c := range []Config{{Set: Collude, Phase: Structural}, {Set: Mailbox, Phase: Structural}, {Set: Compromise, Phase: Train}, {Set: Compromise, Phase: Pilot}, {Set: Compromise, Phase: Primary}} {
		if got := structuralTrustTasks(c, coordinates); len(got) != 0 {
			t.Fatalf("structural trust tasks in %s/%s", c.Set, c.Phase)
		}
	}
	if got := structuralTrustTasks(Config{Set: Compromise, Phase: Structural}, nil); len(got) != 0 {
		t.Fatal("empty registration produced tasks")
	}
}

func TestConditionedPeerRoutes(t *testing.T) {
	for _, sides := range []int{2, 12, 32} {
		for _, seed := range []int64{0, 1, 42, -1, 1<<63 - 1} {
			first, err := conditionedPeerRoutes(seed, "mailbox-first", sides)
			if err != nil {
				t.Fatal(err)
			}
			middle, err := conditionedPeerRoutes(seed, "mailbox-middle", sides)
			if err != nil {
				t.Fatal(err)
			}
			for placement, paths := range map[string][][3]uint8{"mailbox-first": first, "mailbox-middle": middle} {
				if len(paths) != sides {
					t.Fatalf("%s/%d/%d: got %d sides", placement, sides, seed, len(paths))
				}
				again, err := conditionedPeerRoutes(seed, placement, sides)
				if err != nil || !reflect.DeepEqual(paths, again) {
					t.Fatalf("%s/%d/%d: not reproducible", placement, sides, seed)
				}
				passing, bypass := 0, 0
				for side, path := range paths {
					if path[2] != 4 || path[0] >= 4 || path[1] >= 4 || path[0] == path[1] {
						t.Fatalf("%s/%d/%d side %d: invalid path %v", placement, sides, seed, side, path)
					}
					if path[0] != 0 && path[1] != 0 {
						bypass++
						continue
					}
					passing++
					if placement == "mailbox-first" && path[0] != 0 || placement == "mailbox-middle" && path[1] != 0 {
						t.Fatalf("%s: wrong controlled role %v", placement, path)
					}
				}
				if passing != sides/2 || bypass != sides/2 {
					t.Fatalf("%s/%d/%d: %d passing, %d unrelated", placement, sides, seed, passing, bypass)
				}
			}
			for side := range first {
				if (first[side][0] == 0) != (middle[side][1] == 0) {
					t.Fatal("paired role controls changed selected sides")
				}
			}
			if reflect.DeepEqual(first, middle) {
				t.Fatal("first and middle populations are identical")
			}
		}
	}
}

func TestConditionedPeerRoutesInvalid(t *testing.T) {
	for _, test := range []struct {
		placement string
		sides     int
	}{{"", 12}, {"mailbox", 12}, {"first", 12}, {"mailbox-first", -2}, {"mailbox-first", 0}, {"mailbox-first", 1}, {"mailbox-middle", 3}, {"mailbox-middle", 31}, {"mailbox-middle", 34}} {
		paths, err := conditionedPeerRoutes(42, test.placement, test.sides)
		if !errors.Is(err, ErrInvalid) || paths != nil {
			t.Fatalf("%q/%d: got %v, %v", test.placement, test.sides, paths, err)
		}
	}
}

func TestConditionedPeerRoutesPrivateSubset(t *testing.T) {
	var subsets [2]uint16
	for seed := range subsets {
		paths, err := conditionedPeerRoutes(int64(seed), "mailbox-first", 12)
		if err != nil {
			t.Fatal(err)
		}
		for side, path := range paths {
			if path[0] == 0 {
				subsets[seed] |= 1 << side
			}
		}
		if subsets[seed] == 0x3f {
			t.Fatalf("seed %d selected the positional first half", seed)
		}
	}
	if subsets[0] == subsets[1] {
		t.Fatal("different registered seeds selected the same passing subset")
	}
}
