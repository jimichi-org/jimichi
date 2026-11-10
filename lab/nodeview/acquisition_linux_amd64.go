//go:build linux && amd64

package nodeview

func captureLinkingAcquisition(in evaluationInput, validated bool) linkingAcquisition {
	proof := linkingAcquisition{Requested: len(in.public.controlled) == 2}
	if !proof.Requested {
		return proof
	}
	if !validated {
		return proof
	}
	setupComplete, localComplete, coverageErr := requiredInitialCapture(in)
	if coverageErr != nil || !setupComplete {
		reason := ReasonIncomplete
		if coverageErr != nil {
			reason = reasonOf(coverageErr)
		}
		for mi := range 2 {
			for wi := range 5 {
				proof.Reasons[mi][wi] = reason
			}
		}
		return proof
	}
	proof.Setup = true
	for mi := range 2 {
		for wi := range 5 {
			proof.Windows[mi][wi] = localComplete || mi == 1
			if !proof.Windows[mi][wi] {
				proof.Reasons[mi][wi] = ReasonIncomplete
			}
		}
	}
	for _, node := range in.views.nodes {
		for _, setup := range node.setups {
			incoming, present := connection(node, setup.connection)
			valid := setup.opened > 0 && setup.stages&stageInput != 0 && present && !incoming.initiator && incoming.authenticated
			if !valid {
				proof.Setup = false
				for mi := range 2 {
					for wi := range 5 {
						proof.Windows[mi][wi] = false
						proof.Reasons[mi][wi] = ReasonProvenance
					}
				}
			}
		}
		for _, cell := range node.cells {
			if cell.dir != 0 {
				continue
			}
			for wi, window := range linkingGrid {
				if cell.localTime < in.public.epochNS || cell.inputTime >= in.public.epochNS+window && cell.inputTime > 0 {
					continue
				}
				if cell.hop != 0 && cell.kind == 1 && cell.stages&(stageInput|stageLocal) != stageInput|stageLocal {
					proof.Windows[0][wi] = false
					proof.Reasons[0][wi] = ReasonProvenance
				}
				if cell.hop == 0 && cell.stages&stageInput == 0 {
					proof.Windows[1][wi] = false
					proof.Reasons[1][wi] = ReasonProvenance
				}
			}
		}
	}
	return proof
}

func acquiredMethod(proof linkingAcquisition, method predictedMethod) (bool, Reason) {
	if method.method == "setup" {
		return proof.Setup, ReasonProvenance
	}
	mi := -1
	if method.method == "cells" {
		mi = 0
	}
	if method.method == "frames" {
		mi = 1
	}
	if mi < 0 {
		return true, ReasonNone
	}
	for wi, window := range linkingGrid {
		if method.windowNS == window {
			reason := proof.Reasons[mi][wi]
			if reason == ReasonNone {
				reason = ReasonIncomplete
			}
			return proof.Windows[mi][wi], reason
		}
	}
	return false, ReasonContract
}

func failMethodAcquisition(proof *linkingAcquisition, method predictedMethod, reason Reason) {
	if method.method == "setup" {
		proof.Setup = false
		return
	}
	mi := -1
	if method.method == "cells" {
		mi = 0
	}
	if method.method == "frames" {
		mi = 1
	}
	if mi < 0 {
		return
	}
	for wi, window := range linkingGrid {
		if method.windowNS == window {
			proof.Windows[mi][wi] = false
			proof.Reasons[mi][wi] = reason
		}
	}
}
