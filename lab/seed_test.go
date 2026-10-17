package lab

import "testing"

// the overlap that motivated Derive: base+repeat+flow collides for repeat 0
// flow 1 and repeat 1 flow 0; derived seeds for 30 repeats of 10 flows in
// two streams must all differ
func TestDerivedSeedsDoNotCollide(t *testing.T) {
	seen := make(map[int64]string)
	for r := uint64(0); r < 30; r++ {
		run := Derive(1, r)
		for _, stream := range []uint64{streamPhases, streamGaps} {
			for f := uint64(0); f < 10; f++ {
				s := Derive(run, stream, f)
				if s < 0 {
					t.Fatalf("negative seed %d", s)
				}
				key := string(rune('a'+r)) + string(rune('a'+stream)) + string(rune('a'+f))
				if prev, dup := seen[s]; dup {
					t.Fatalf("seed %d repeats for %s and %s", s, prev, key)
				}
				seen[s] = key
			}
		}
	}
	if Derive(1, 0) != Derive(1, 0) {
		t.Fatal("Derive is not deterministic")
	}
}

// a change of Derive or of a stream number would move every published seed
func TestStreamsKeepTheirValues(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want uint64
	}{
		{"phases", streamPhases, 1}, {"gaps", streamGaps, 2}, {"paths", streamPaths, 3},
		{"training", StreamTraining, 4}, {"shift", StreamShift, 5}, {"permute", StreamPermute, 6},
	} {
		if c.got != c.want {
			t.Errorf("stream %s is %d, want %d", c.name, c.got, c.want)
		}
	}
	for _, c := range []struct {
		seed  int64
		parts []uint64
		want  int64
	}{
		{1, []uint64{0}, 2482289063980384216},
		{1, []uint64{4}, 1203625649006156877},
		{1, []uint64{4, 0}, 3821461619228793863},
		{3, []uint64{4, 0}, 7524001907707828211},
	} {
		if got := Derive(c.seed, c.parts...); got != c.want {
			t.Errorf("Derive(%d, %v) = %d, want %d", c.seed, c.parts, got, c.want)
		}
	}
}

// a training seed in two parts, Derive(base, StreamTraining, t), never takes
// the seed of a claim repeat or a stream of one: a base Derive(base,
// StreamTraining) would be the seed of repeat 4 itself. Per run its phases,
// permutation, ten gap and ten shift streams, 23 values; 110 runs per base
// seed give 2530 values, 7590 over the three
func TestTrainingAndNullSeedsNeverMeetTheSeries(t *testing.T) {
	pooled := map[int64]bool{}
	for base := int64(1); base <= 3; base++ {
		var runs []int64
		for r := uint64(0); r < 100; r++ {
			runs = append(runs, Derive(base, r))
		}
		for tr := uint64(0); tr < 10; tr++ {
			runs = append(runs, Derive(base, StreamTraining, tr))
		}
		seen := map[int64]bool{}
		for _, s := range runs {
			values := []int64{s, Derive(s, streamPhases), Derive(s, StreamPermute)}
			for f := uint64(0); f < 10; f++ {
				values = append(values, Derive(s, streamGaps, f), Derive(s, StreamShift, f))
			}
			for _, v := range values {
				seen[v] = true
				pooled[v] = true
			}
		}
		if len(seen) != 2530 {
			t.Errorf("base seed %d: %d distinct values of 2530", base, len(seen))
		}
	}
	if len(pooled) != 7590 {
		t.Errorf("%d distinct values over the three base seeds, want 7590", len(pooled))
	}
}
