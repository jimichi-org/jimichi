package nodeview

func requiredInitialCapture(in evaluationInput) (bool, bool, error) {
	owners := in.truth.ownership
	if owners == nil {
		var err error
		owners, err = parseSetupOwnership(in.truth.setups, in.budget)
		if err != nil {
			return false, false, err
		}
		defer clear(owners)
	}
	var controlled [5]bool
	for _, position := range in.public.controlled {
		if position < 0 || position >= len(controlled) || controlled[position] {
			return false, false, fail(ReasonContract)
		}
		controlled[position] = true
	}
	var nodes [5]int
	for i := range nodes {
		nodes[i] = -1
	}
	for i, node := range in.views.nodes {
		if int(node.position) >= len(nodes) || !controlled[node.position] || nodes[node.position] >= 0 {
			return false, false, fail(ReasonContract)
		}
		nodes[node.position] = i
	}
	for position, selected := range controlled {
		if selected && nodes[position] < 0 {
			return false, false, nil
		}
	}
	setupComplete, localComplete := true, true
	for _, plan := range in.plans {
		if !in.established[plan.side] {
			continue
		}
		var initial uint8
		for _, entry := range owners {
			id, owner := entry.id, entry.owner
			if owner.side != plan.side || owner.group != 1 {
				continue
			}
			if !owner.complete || owner.hop >= 3 || plan.route[owner.hop] != id.roster {
				return false, false, fail(ReasonLabel)
			}
			initial |= 1 << owner.hop
		}
		if initial != 7 {
			return false, false, fail(ReasonLabel)
		}
		for hop, position := range plan.route {
			if int(position) >= len(controlled) {
				return false, false, fail(ReasonLabel)
			}
			if !controlled[position] {
				continue
			}
			if nodes[position] < 0 {
				setupComplete, localComplete = false, false
				continue
			}
			node := in.views.nodes[nodes[position]]
			found := false
			for _, setup := range node.setups {
				owner, present := owners.lookup(setupIdentity{setup.circuit, position})
				if !present || owner.side != plan.side || owner.group != 1 {
					continue
				}
				if found || !owner.complete || int(owner.hop) != hop || int(setup.index) != hop {
					return false, false, fail(ReasonLabel)
				}
				found = true
				if setup.opened <= 0 || setup.stages&stageInput == 0 {
					setupComplete = false
				}
				if setup.hop == 0 || setup.stages&stageLocal == 0 {
					localComplete = false
				}
			}
			if !found {
				setupComplete, localComplete = false, false
			}
		}
	}
	return setupComplete, localComplete, nil
}
