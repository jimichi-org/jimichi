package nodeview

type queueCircuit struct{ circuit, put, fetch uint32 }

func queueInventory(observations []mailboxObservation, epoch, cutoff int64) (out []queueCircuit, resultErr error) {
	indices := make(map[uint32]int, min(maxConnections, len(observations)))
	defer clear(indices)
	defer func() {
		if resultErr != nil {
			clear(out)
			out = nil
		}
	}()
	out = make([]queueCircuit, 0, min(maxConnections, len(observations)))
	for _, o := range observations {
		if o.CallNS < epoch || o.CallNS >= cutoff || !o.Complete {
			continue
		}
		if o.Circuit == 0 || o.HasPut != (o.PutQueue != 0) {
			return out, fail(ReasonContract)
		}
		index, ok := indices[o.Circuit]
		if !ok {
			if len(out) == maxConnections {
				return out, fail(ReasonLimit)
			}
			index = len(out)
			indices[o.Circuit] = index
			out = append(out, queueCircuit{circuit: o.Circuit})
		}
		current := &out[index]
		if o.PutQueue != 0 {
			if current.put != 0 && current.put != o.PutQueue {
				return out, fail(ReasonContract)
			}
			current.put = o.PutQueue
		}
		if o.FetchQueue != 0 {
			if current.fetch != 0 && current.fetch != o.FetchQueue {
				return out, fail(ReasonContract)
			}
			current.fetch = o.FetchQueue
		}
	}
	return out, nil
}

type queuePair struct{ first, second int }

func queueCandidates(view []queueCircuit) []queuePair {
	out := make([]queuePair, 0, len(view)*(len(view)-1)/2)
	for first := range view {
		for second := first + 1; second < len(view); second++ {
			a, b := view[first], view[second]
			if a.put != 0 && a.put == b.fetch || b.put != 0 && b.put == a.fetch {
				out = append(out, queuePair{first, second})
			}
		}
	}
	return out
}

func evaluateQueues(node nodeView, view []queueCircuit, truth privateTruth, conversations int) (Number, uint64, error) {
	if len(view) == 0 {
		return Number{Reason: ReasonNoView}, 0, nil
	}
	if conversations < 1 || conversations > maxClients/2 {
		return Number{}, 0, fail(ReasonContract)
	}
	owners := make([]int, len(view))
	defer clear(owners)
	for i, v := range view {
		found := 0
		for _, s := range node.setups {
			if s.hop != v.circuit {
				continue
			}
			side, _, ok := setupOwner(truth, s.circuit, node.position)
			if !ok || int(side)/2 >= conversations {
				return Number{}, 0, fail(ReasonLabel)
			}
			owners[i] = int(side) / 2
			found++
		}
		if found != 1 {
			return Number{}, 0, fail(ReasonLabel)
		}
	}
	links := queueCandidates(view)
	defer clear(links)
	joined := make([]bool, conversations)
	defer clear(joined)
	var falsePairs uint64
	for _, edge := range links {
		if owners[edge.first] == owners[edge.second] {
			joined[owners[edge.first]] = true
		} else {
			falsePairs++
		}
	}
	count := 0
	for _, yes := range joined {
		if yes {
			count++
		}
	}
	return number(float64(count)/float64(conversations), ReasonNoView), falsePairs, nil
}
