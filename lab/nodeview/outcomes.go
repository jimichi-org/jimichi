package nodeview

import (
	"bytes"
	"math"
	"sort"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func firstChainOutcomes(pred predictions, in evaluationInput, counts Counts, clean bool) (r RunResult, resultErr error) {
	peer := in.public.population == "peer"
	width := 4
	if peer {
		width = 3
	}
	lease, e := scratchReservation(in.budget, uint64(len(in.truth.fragments))*24+uint64(len(in.truth.messages))*32+uint64(len(in.truth.setups))*160+(2<<20))
	if e != nil {
		return r, e
	}
	defer lease()
	r = RunResult{RouteHistogram: make([]uint64, width+1)}
	defer func() {
		if resultErr != nil {
			clear(r.RouteHistogram)
			r.RouteHistogram = nil
		}
	}()
	if in.public.n != 5 || in.public.h != 3 || !peer && in.public.population != "echo" || len(in.plans) == 0 || len(in.plans) > maxClients || len(in.views.nodes) > 2 || len(in.public.controlled) < 1 || len(in.public.controlled) > 2 {
		return r, fail(ReasonContract)
	}
	if counts.Planned != uint64(len(in.plans)) || counts.Attempted > counts.Planned || counts.Established > counts.Attempted || counts.PreflightOK > counts.Established || counts.MessageBearing > counts.PreflightOK || counts.Refused > counts.Attempted || counts.SetupFailed > counts.Attempted {
		return r, fail(ReasonContract)
	}
	if counts.Refused > counts.Attempted-counts.Established || counts.SetupFailed > counts.Attempted-counts.Established-counts.Refused {
		return r, fail(ReasonContract)
	}
	plans := make(map[uint16]workloadPlan, len(in.plans))
	defer clear(plans)
	for _, p := range in.plans {
		if _, duplicate := plans[p.side]; duplicate || p.side >= maxClients {
			return r, fail(ReasonLabel)
		}
		var seen [5]bool
		for _, position := range p.route {
			if position >= 5 || seen[position] {
				return r, fail(ReasonLabel)
			}
			seen[position] = true
		}
		plans[p.side] = p
	}
	controlled := make(map[uint8]bool, 2)
	defer clear(controlled)
	for _, position := range in.public.controlled {
		if position < 0 || position >= 5 || controlled[uint8(position)] {
			return r, fail(ReasonContract)
		}
		controlled[uint8(position)] = true
	}
	preflight := uint64(0)
	for side, established := range in.established {
		if _, ok := plans[side]; !ok {
			return r, fail(ReasonLabel)
		}
		if established {
			preflight++
		}
	}
	if preflight != counts.PreflightOK {
		return r, fail(ReasonContract)
	}
	tokens := make(map[int]bool, maxClients)
	defer clear(tokens)
	for endpoint, token := range in.nkEndpoints {
		if endpoint>>16 == 0 || uint16(endpoint) == 0 || token < 5 || token >= 5+maxClients || tokens[token] {
			return r, fail(ReasonContract)
		}
		if _, planned := plans[uint16(token-5)]; !planned {
			return r, fail(ReasonContract)
		}
		tokens[token] = true
	}
	positions := make(map[int]bool, 5)
	defer clear(positions)
	for port, position := range in.portToRoster {
		if port == 0 || position < 0 || position >= 5 || positions[position] {
			return r, fail(ReasonContract)
		}
		positions[position] = true
	}
	owners, e := parseSetupOwnership(in.truth.setups, in.budget)
	if e != nil {
		return r, e
	}
	defer clear(owners)
	initial := make(map[uint16]uint8, maxClients)
	defer clear(initial)
	groupPositions, e := makeSetupGroupStates(owners, in.budget)
	if e != nil {
		return r, e
	}
	defer clear(groupPositions[:cap(groupPositions)])
	for _, entry := range owners {
		id, owner := entry.id, entry.owner
		p, ok := plans[owner.side]
		if !ok {
			return r, fail(ReasonLabel)
		}
		if !groupPositions.add(owner, id.roster) {
			return r, fail(ReasonLabel)
		}
		if owner.group == 1 && owner.complete {
			if p.route[owner.hop] != id.roster {
				return r, fail(ReasonLabel)
			}
			initial[owner.side] |= 1 << owner.hop
		}
	}
	viewCount := 0
	for _, node := range in.views.nodes {
		viewCount += len(node.setups)
	}
	all := make([]annotatedView, 0, viewCount)
	defer func() {
		for i := range all {
			clear(all[i].claim)
			all[i].claim = nil
		}
		clear(all)
	}()
	starts := make([]int, len(in.views.nodes))
	defer clear(starts)
	roles := make(map[uint16]uint8, maxClients)
	defer clear(roles)
	coverage := make(map[uint16]uint8, maxClients)
	defer clear(coverage)
	nodes := make(map[uint8]int, 2)
	defer clear(nodes)
	var hops [5]hopOwnerIndex
	defer func() {
		for _, values := range hops {
			clear(values[:cap(values)])
		}
		clear(hops[:])
	}()
	if e := in.budget.checkAllocation(uint64(len(owners))); e != nil {
		return r, e
	}
	seen := make([]bool, len(owners))
	defer clear(seen)
	for ni, node := range in.views.nodes {
		if _, duplicate := nodes[node.position]; duplicate || !controlled[node.position] {
			return r, fail(ReasonContract)
		}
		nodes[node.position] = ni
		starts[ni] = len(all)
		hops[node.position], e = makeHopOwnerIndex(node.setups, in.budget)
		if e != nil {
			return r, e
		}
		for si, s := range node.setups {
			id := setupIdentity{s.circuit, node.position}
			oi, ok := owners.find(id)
			if !ok {
				return r, fail(ReasonLabel)
			}
			owner := owners[oi].owner
			if seen[oi] || owner.hop != s.index {
				return r, fail(ReasonLabel)
			}
			seen[oi] = true
			if s.index >= 3 || s.stages&^31 != 0 {
				return r, fail(ReasonContract)
			}
			if s.hop != 0 {
				if !hops[node.position].activate(s.hop, oi) {
					return r, fail(ReasonContract)
				}
			}
			var claim []int
			first := owner.complete && owner.group == 1
			if first {
				if s.index == 0 && s.connection != 0 {
					incoming, present, e := outcomeConnection(node, s.connection)
					if e != nil {
						return r, e
					}
					if present && incoming.authenticated && !incoming.initiator && incoming.peer == 255 && incoming.selectorPort == 0 && incoming.localPort != 0 && incoming.remotePort != 0 {
						endpoint := uint32(incoming.localPort)<<16 | uint32(incoming.remotePort)
						if token, normalized := in.nkEndpoints[endpoint]; normalized && token != 5+int(owner.side) {
							return r, fail(ReasonContract)
						}
					}
				}
				observed, available, e := firstChainClaim(node, s, in)
				if e != nil {
					clear(observed)
					return r, e
				}
				claim = observed
				roles[owner.side] |= 1 << s.index
				r.Capture.Roles[s.index]++
				if available {
					coverage[owner.side] |= 1 << s.index
				}
			} else {
				claim = make([]int, width)
				for i := range claim {
					claim[i] = -1
				}
			}
			all = append(all, annotatedView{ni, si, owner.side, claim, first})
		}
	}
	links := make([]metrics.ViewEdge, 0, len(all))
	defer func() { clear(links) }()
	linkedFirst, linkedSecond := make(map[int]bool, maxConnections), make(map[int]bool, maxConnections)
	defer clear(linkedFirst)
	defer clear(linkedSecond)
	for _, method := range pred.methods {
		if method.method != "mixed" {
			continue
		}
		for _, edge := range method.matches {
			if len(in.views.nodes) != 2 || edge.First < 0 || edge.Second < 0 || edge.First >= len(in.views.nodes[0].setups) || edge.Second >= len(in.views.nodes[1].setups) || linkedFirst[edge.First] || linkedSecond[edge.Second] {
				return r, fail(ReasonContract)
			}
			linkedFirst[edge.First], linkedSecond[edge.Second] = true, true
			links = append(links, metrics.ViewEdge{First: starts[0] + edge.First, Second: starts[1] + edge.Second})
		}
	}
	r.ModelComplete = clean && counts.Planned > 0 && counts.Attempted == counts.Planned && counts.Established == counts.Planned && counts.PreflightOK == counts.Planned && counts.MessageBearing == counts.Planned
	for _, p := range in.plans {
		if roles[p.side] != 0 {
			r.Touched++
		}
		if roles[p.side]&5 == 5 {
			r.Ends++
		}
		available := in.established[p.side] && initial[p.side] == 7
		for hop, position := range p.route {
			if controlled[position] && coverage[p.side]&(1<<hop) == 0 {
				available = false
			}
		}
		if !available {
			r.ModelComplete = false
			continue
		}
		path := []int{5 + int(p.side), int(p.route[0]), int(p.route[1]), int(p.route[2])}
		path = path[:width]
		claims := make([]metrics.ViewClaim, len(all))
		for i, v := range all {
			claims[i] = metrics.ViewClaim{Positions: v.claim, OnPath: v.onPath && v.side == p.side}
		}
		n, share := metrics.RecoveredComponents(path, claims, links)
		clear(claims)
		clear(path)
		if n < 0 || math.IsNaN(share) {
			return r, fail(ReasonContract)
		}
		r.RouteHistogram[n]++
	}
	fragments := make([][]byte, 0, len(in.truth.fragments))
	defer func() { clear(fragments) }()
	for _, f := range in.truth.fragments {
		position, ok := in.fragmentSource.lookup(f.data)
		if !ok || f.hop == 0 || f.kind < 1 || f.kind > 3 || !outcomeArenaRef(in.truth.arena, f.data) {
			return r, fail(ReasonContract)
		}
		if int(position) >= len(hops) {
			return r, fail(ReasonLabel)
		}
		oi, ok := hops[position].lookup(f.hop)
		if !ok {
			return r, fail(ReasonLabel)
		}
		owner := owners[oi].owner
		if owner.complete && owner.group == 1 {
			fragments = append(fragments, in.truth.arena.bytes(f.data))
		}
	}
	messages := make([]actualMessage, 0, len(in.truth.messages))
	defer func() { clear(messages) }()
	for _, m := range in.truth.messages {
		if !m.sent {
			continue
		}
		if _, ok := plans[m.side]; !ok || m.body.size != 128 || !outcomeArenaRef(in.truth.arena, m.body) {
			return r, fail(ReasonLabel)
		}
		messages = append(messages, m)
	}
	sort.Slice(messages, func(i, j int) bool {
		return bytes.Compare(in.truth.arena.bytes(messages[i].body), in.truth.arena.bytes(messages[j].body)) < 0
	})
	bearing, found := make(map[uint16]bool, maxClients), make(map[uint16]bool, maxClients)
	defer clear(bearing)
	defer clear(found)
	for i, m := range messages {
		body := in.truth.arena.bytes(m.body)
		if i > 0 && bytes.Equal(body, in.truth.arena.bytes(messages[i-1].body)) {
			return r, fail(ReasonLabel)
		}
		share := metrics.ContentShare([][]byte{body}, fragments)
		if math.IsNaN(share) {
			return r, fail(ReasonLabel)
		}
		bearing[m.side] = true
		r.MeasuredMessages++
		if share == 1 {
			r.ContentMessages++
			found[m.side] = true
		}
	}
	if uint64(len(bearing)) != counts.MessageBearing {
		return r, fail(ReasonContract)
	}
	for side := range bearing {
		if !in.established[side] {
			return r, fail(ReasonLabel)
		}
	}
	r.ContentFound = uint64(len(found))
	return r, nil
}

func outcomeArenaRef(a *lockedArena, r arenaRef) bool {
	return a != nil && r.size > 0 && a.valid(r)
}

func firstChainClaim(node nodeView, s setupView, in evaluationInput) ([]int, bool, error) {
	peer := in.public.population == "peer"
	width := 4
	if peer {
		width = 3
	}
	unknown := make([]int, width)
	for i := range unknown {
		unknown[i] = -1
	}
	if s.hop == 0 || s.stages&(stageInput|stageLocal) != stageInput|stageLocal || s.connection == 0 {
		return unknown, false, nil
	}
	incoming, present, e := outcomeConnection(node, s.connection)
	if e != nil {
		return unknown, false, e
	}
	if !present {
		return unknown, false, nil
	}
	if !incoming.authenticated || incoming.initiator {
		return unknown, false, fail(ReasonContract)
	}
	clientToken := -1
	if s.index == 0 {
		if incoming.peer != 255 || incoming.selectorPort != 0 {
			return unknown, false, fail(ReasonContract)
		}
		if incoming.localPort == 0 || incoming.remotePort == 0 {
			return unknown, false, nil
		}
		endpoint := uint32(incoming.localPort)<<16 | uint32(incoming.remotePort)
		var present bool
		clientToken, present = in.nkEndpoints[endpoint]
		if !present {
			return unknown, false, fail(ReasonContract)
		}
	} else {
		if incoming.selectorPort == 0 {
			return unknown, false, nil
		}
		predecessor, present := in.portToRoster[incoming.selectorPort]
		if !present || incoming.peer >= 5 || predecessor != int(incoming.peer) {
			return unknown, false, fail(ReasonContract)
		}
	}
	if s.index < 2 {
		if s.nextPort == 0 || s.outConnection == 0 {
			return unknown, false, nil
		}
		next, present, e := outcomeConnection(node, s.outConnection)
		if e != nil {
			return unknown, false, e
		}
		if !present {
			return unknown, false, fail(ReasonContract)
		}
		if !next.authenticated || !next.initiator || next.peer >= 5 {
			return unknown, false, fail(ReasonContract)
		}
		if next.remotePort == 0 {
			return unknown, false, nil
		}
		successor, present := in.portToRoster[next.remotePort]
		if next.remotePort != s.nextPort || !present || successor != int(next.peer) {
			return unknown, false, fail(ReasonContract)
		}
	} else if s.nextPort != 0 || s.outConnection != 0 {
		return unknown, false, fail(ReasonContract)
	}
	claim := observedClaim(node, s, peer, clientToken, in.portToRoster)
	mask := uint8(0)
	for i, occupant := range claim {
		if occupant >= 0 {
			mask |= 1 << i
		}
	}
	required := [3]uint8{0b0111, 0b1110, 0b1100}
	if peer {
		required = [3]uint8{0b111, 0b110, 0b100}
	}
	if mask != required[s.index] {
		clear(claim)
		return unknown, false, fail(ReasonContract)
	}
	clear(unknown)
	return claim, true, nil
}

func outcomeConnection(node nodeView, generation uint32) (connectionView, bool, error) {
	var found connectionView
	count := 0
	for _, c := range node.connections {
		if c.generation == generation {
			found = c
			count++
		}
	}
	if count > 1 {
		return connectionView{}, false, fail(ReasonContract)
	}
	return found, count == 1, nil
}
