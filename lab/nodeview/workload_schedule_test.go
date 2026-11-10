package nodeview

import (
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/lab"
)

func plannedPeerMessages(t *testing.T, master int64, side uint64) int {
	t.Helper()
	c := Config{Set: Mailbox, Phase: Structural, Seed: master}
	seed := nodeSeed(c, 0, 0, side, lab.StreamNodeGaps)
	count := 0
	for _, segment := range [][2]int64{{0, 10000000000}, {20000000000, 30000000000}} {
		rng := newGapRand(seed, segment[0])
		for next := segment[0]; next < segment[1]; {
			count++
			if count > 10000 {
				t.Fatal("bounded schedule reproduction did not terminate")
			}
			next += int64(rng.ExpFloat64() * float64(200*time.Millisecond))
		}
	}
	return count
}

func TestSourceCapFixturePlansOneRefusedAttempt(t *testing.T) {
	if plannedPeerMessages(t, 574, 0) != 129 || plannedPeerMessages(t, 574, 1) != 91 {
		t.Fatal("source-cap fixture no longer crosses the declared 128-message boundary exactly once")
	}
}

func TestTrustedAdmissionRandomScheduleExceedsSourceCap(t *testing.T) {
	maximum, over, firstHalfOver, total := 0, 0, 0, 0
	for side := range 32 {
		count := plannedPeerMessages(t, 117, uint64(side))
		maximum = max(maximum, count)
		total += count
		if count > 128 {
			over++
			if side < 16 {
				firstHalfOver++
			}
		}
	}
	if maximum != 129 || over != 1 || firstHalfOver != 0 || total != 3360 {
		t.Fatal("trusted admission no longer reproduces its distinct 16-side and 32-side source-cap boundary")
	}
}
