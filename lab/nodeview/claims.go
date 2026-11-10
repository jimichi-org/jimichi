package nodeview

func observedClaim(node nodeView, s setupView, peer bool, clientToken int, portToRoster map[uint16]int) []int {
	width := 4
	if peer {
		width = 3
	}
	claim := make([]int, width)
	for i := range claim {
		claim[i] = -1
	}
	position := int(s.index) + 1
	if position < width {
		claim[position] = int(node.position)
	}
	if in, ok := connection(node, s.connection); ok && in.authenticated {
		if s.index == 0 && clientToken >= 0 {
			claim[0] = clientToken
		} else if s.index > 0 && in.peer != 255 && position-1 < width {
			claim[position-1] = int(in.peer)
		}
	}
	if next, ok := outgoing(node, s); ok && position+1 < width {
		if occupant, known := portToRoster[next.remotePort]; known {
			claim[position+1] = occupant
		}
	}
	return claim
}

type annotatedView struct {
	node, setup int
	side        uint16
	claim       []int
	onPath      bool
}
type evaluationInput struct {
	queueFalsePairs *uint64
	budget          *memoryBudget
	resultCharge    *resultCharge
	nkEndpoints     map[uint32]int
	rawDenied
	views          viewSet
	truth          privateTruth
	plans          []workloadPlan
	public         publicConfig
	portToRoster   map[uint16]int
	fragmentSource fragmentSourceIndex
	established    map[uint16]bool
}

func setupOwner(t privateTruth, circuit uint64, position uint8) (uint16, uint32, bool) {
	o, ok := ownerOf(t, circuit, position)
	return o.side, o.group, ok
}
