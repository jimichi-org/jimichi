package nodeview

import "sort"

func membershipSeen(m uint32Membership, key uint32) (bool, bool) {
	i := sort.Search(len(m), func(i int) bool { return m[i].key >= key })
	if i == len(m) || m[i].key != key {
		return false, false
	}
	return m[i].seen, true
}

func validateViewBindings(node nodeView, roster map[uint16]int) error {
	connections := make(map[uint32]connectionView, len(node.connections))
	defer clear(connections)
	tuples := make(map[uint32]bool, len(node.connections))
	defer clear(tuples)
	for _, c := range node.connections {
		if c.generation == 0 || c.localPort == 0 || c.remotePort == 0 {
			return fail(ReasonContract)
		}
		tuple := uint32(c.localPort)<<16 | uint32(c.remotePort)
		if tuples[tuple] {
			return fail(ReasonContract)
		}
		tuples[tuple] = true
		if _, exists := connections[c.generation]; exists {
			return fail(ReasonContract)
		}
		connections[c.generation] = c
	}
	lease, e := scratchReservation(node.budget, uint64(len(node.setups))*16)
	if e != nil {
		return e
	}
	defer lease()
	setups, e := makeUint32Membership(len(node.setups), func(i int) uint32 { return node.setups[i].generation }, node.budget)
	if e != nil {
		return e
	}
	defer setups.wipe()
	hops, e := makeUint32Membership(len(node.setups), func(i int) uint32 { return node.setups[i].hop }, node.budget)
	if e != nil {
		return e
	}
	defer hops.wipe()
	incoming, outgoingOwner := make(map[uint32]bool, len(node.connections)), make(map[uint32]bool, len(node.connections))
	defer clear(incoming)
	defer clear(outgoingOwner)
	for _, s := range node.setups {
		seenSetup, hasSetup := membershipSeen(setups, s.generation)
		seenHop, hasHop := membershipSeen(hops, s.hop)
		if s.generation == 0 || s.index >= 3 || !hasSetup || seenSetup || s.hop != 0 && (!hasHop || seenHop) {
			return fail(ReasonContract)
		}
		if _, bad := connections[s.generation]; bad {
			return fail(ReasonContract)
		}
		if _, bad := connections[s.hop]; s.hop != 0 && bad {
			return fail(ReasonContract)
		}
		setups.mark(s.generation)
		if s.hop != 0 {
			hops.mark(s.hop)
		}
		if s.connection != 0 {
			c, ok := connections[s.connection]
			position, present := roster[c.localPort]
			if !ok || c.initiator || !c.authenticated || !present || position != int(node.position) || incoming[s.connection] {
				return fail(ReasonContract)
			}
			incoming[s.connection] = true
		}
		if s.nextPort == 0 {
			if s.outConnection != 0 || s.index != 2 {
				return fail(ReasonContract)
			}
			continue
		}
		if s.index == 2 {
			return fail(ReasonContract)
		}
		if s.outConnection == 0 {
			continue
		}
		c, ok := connections[s.outConnection]
		peer, present := roster[c.remotePort]
		if !ok || s.connection == 0 || s.outConnection == s.connection || !c.initiator || !c.authenticated || c.remotePort != s.nextPort || c.peer >= 5 || !present || peer != int(c.peer) || outgoingOwner[s.outConnection] {
			return fail(ReasonContract)
		}
		outgoingOwner[s.outConnection] = true
	}
	return nil
}
