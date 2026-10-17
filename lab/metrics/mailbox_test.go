package metrics_test

import (
	"math"
	"testing"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

// circuits as (fetch, put); qa and qb are the queues of the two sides of a
// conversation, numbered by conversation
func TestJoinedConversationsKnownAnswer(t *testing.T) {
	three := []metrics.Queues{
		{"qa0", "qb0"}, {"qb0", ""}, {"qa1", "qb1"}, {"qb1", "qa1"}, {"qa2", "qb2"}, {"qb2", "qa2"},
	}
	pairs := []int{0, 0, 1, 1, 2, 2}
	silent := append([]metrics.Queues(nil), three...)
	silent[5] = metrics.Queues{}
	for _, c := range []struct {
		name         string
		circuits     []metrics.Queues
		conversation []int
		share        float64
		falsePairs   int
	}{
		// circuit 1 never puts, but circuit 0 puts into qb0, which 1 fetches;
		// (2, 3) and (4, 5) are tied both ways and no circuit puts into a queue
		// of another conversation: 3 of 3. Requiring both directions would
		// leave conversation 0 out, 2/3
		{"one direction", three, pairs, 1, 0},
		// circuit 5 made no request, and circuit 4 puts into qb2, which nobody
		// fetches: 2 of 3
		{"a circuit without requests", silent, pairs, 2.0 / 3, 0},
		// a rebuild of circuit 2 as 6: (3, 6) is tied, 6 puts into qb1 and 3
		// fetches it; (2, 6) share their fetch queue and are not tied: 3 of 3
		{"a rebuild", append(append([]metrics.Queues(nil), three...), metrics.Queues{Fetch: "qa1", Put: "qb1"}), append(append([]int(nil), pairs...), 1), 1, 0},
		// (0, 4) is tied because 4 puts into qa0, which 0 fetches: a false pair;
		// (4, 5) is true because 5 puts into qa2, which 4 fetches: 3 of 3
		{"a false pair", []metrics.Queues{
			{"qa0", "qb0"}, {"qb0", "qa0"}, {"qa1", "qb1"}, {"qb1", "qa1"}, {"qa2", "qa0"}, {"qb2", "qa2"},
		}, pairs, 1, 1},
	} {
		share, falsePairs := metrics.JoinedConversations(c.circuits, c.conversation, 3)
		if !near(share, c.share) || falsePairs != c.falsePairs {
			t.Errorf("%s: JoinedConversations = %v, %d, want %v and %d", c.name, share, falsePairs, c.share, c.falsePairs)
		}
	}
	for _, c := range []struct {
		name          string
		conversation  []int
		conversations int
	}{
		{"no conversations", pairs, 0},
		{"lengths differ", pairs[:5], 3},
		{"an index out of range", []int{0, 0, 1, 1, 3, 3}, 3},
		{"a negative index", []int{0, 0, 1, 1, 2, -1}, 3},
	} {
		if share, falsePairs := metrics.JoinedConversations(three, c.conversation, c.conversations); !math.IsNaN(share) || falsePairs != -1 {
			t.Errorf("%s: JoinedConversations = %v, %d, want NaN and -1", c.name, share, falsePairs)
		}
	}
}

// four requests, two per conversation, the first of each holding a message
func TestRequestScoresKnownAnswer(t *testing.T) {
	conversation := []int{0, 0, 1, 1}
	messages := []bool{true, false, true, false}
	for _, c := range []struct {
		name  string
		value []float64
		truth []bool
		auc   float64
	}{
		// a put exactly when a message rides it
		{"separated", []float64{1, 0, 1, 0}, messages, 1},
		// every request puts, all ties: q = 0, 0.5 + q/2
		{"every request puts", []float64{1, 1, 1, 1}, messages, 0.5},
		// a put without a message on request 1: each positive ties request 1
		// and beats request 3, (1/2 + 1) twice of 4 = 3/4 = 0.5 + q/2 with
		// q = 1/2
		{"a put without a message", []float64{1, 1, 1, 0}, messages, 0.75},
		// a window-full tick on request 2: the positive ties two negatives and
		// beats one, (1/2 + 1 + 1/2)/3 = 2/3 = 0.5 + q/2 with q = 1/3
		{"a window-full tick", []float64{1, 1, 0, 1}, []bool{true, false, false, false}, 2.0 / 3},
	} {
		scores := metrics.RequestScores(conversation, 2, c.value, c.truth)
		if got := metrics.AUC(scores); !near(got, c.auc) {
			t.Errorf("%s: AUC = %v, want %v", c.name, got, c.auc)
		}
	}
	scores := metrics.RequestScores(conversation, 2, []float64{1, 0, 1, 0}, messages)
	for i, s := range scores {
		if s.Entry != conversation[i] || s.Exit != i {
			t.Errorf("request %d scored as %+v, want entry %d and exit %d", i, s, conversation[i], i)
		}
	}
	// each conversation holds one positive and one negative, so every resample
	// separates them
	if ci := metrics.BootstrapAUC(scores, 2, 500, 1); ci.Point != 1 || ci.Low != 1 || ci.High != 1 {
		t.Errorf("BootstrapAUC over conversations = %+v, want [1, 1]", ci)
	}
	// no request holds a message: no AUC
	if got := metrics.AUC(metrics.RequestScores(conversation, 2, []float64{1, 0, 1, 0}, make([]bool, 4))); !math.IsNaN(got) {
		t.Errorf("AUC without a message = %v, want NaN", got)
	}
	for _, c := range []struct {
		name          string
		conversation  []int
		conversations int
		value         []float64
	}{
		{"lengths differ", conversation, 2, []float64{1, 0, 1}},
		{"a conversation out of range", []int{0, 0, 1, 2}, 2, []float64{1, 0, 1, 0}},
		{"a negative conversation", []int{0, 0, 1, -1}, 2, []float64{1, 0, 1, 0}},
		{"no conversations", conversation, 0, []float64{1, 0, 1, 0}},
		{"a NaN value", conversation, 2, []float64{1, math.NaN(), 1, 0}},
		{"an infinite value", conversation, 2, []float64{1, math.Inf(1), 1, 0}},
	} {
		if got := metrics.RequestScores(c.conversation, c.conversations, c.value, messages); got != nil {
			t.Errorf("%s: RequestScores = %+v, want nil", c.name, got)
		}
	}
}
