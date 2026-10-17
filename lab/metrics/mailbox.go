package metrics

import "math"

// the queue ids a mailbox saw a circuit fetch from and put into, "" for none
type Queues struct {
	Fetch, Put string
}

// one direction ties two circuits, since a put into the queue another circuit
// fetches from already shows the mailbox who talks to whom; requiring both
// understates it
func JoinedConversations(circuits []Queues, conversation []int, conversations int) (share float64, falsePairs int) {
	if conversations < 1 || len(conversation) != len(circuits) {
		return math.NaN(), -1
	}
	for _, c := range conversation {
		if c < 0 || c >= conversations {
			return math.NaN(), -1
		}
	}
	joined := make([]bool, conversations)
	for c := range circuits {
		for d := c + 1; d < len(circuits); d++ {
			if !tied(circuits[c], circuits[d]) {
				continue
			}
			if conversation[c] == conversation[d] {
				joined[conversation[c]] = true
			} else {
				falsePairs++
			}
		}
	}
	n := 0
	for _, j := range joined {
		if j {
			n++
		}
	}
	return float64(n) / float64(conversations), falsePairs
}

func tied(a, b Queues) bool {
	return a.Put != "" && a.Put == b.Fetch || b.Put != "" && b.Put == a.Fetch
}

// Entry is the conversation, so the bootstrap resamples the independent unit
func RequestScores(conversation []int, conversations int, value []float64, truth []bool) []Score {
	if conversations < 1 || len(value) != len(conversation) || len(truth) != len(conversation) {
		return nil
	}
	scores := make([]Score, len(value))
	for i, v := range value {
		c := conversation[i]
		if c < 0 || c >= conversations || math.IsNaN(v) || math.IsInf(v, 0) {
			return nil
		}
		scores[i] = Score{Entry: c, Exit: i, Value: v, True: truth[i]}
	}
	return scores
}
