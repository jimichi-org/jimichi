package nodeview

func clearEvaluatedOwner(view *nodeView, truth *privateTruth, pred *predictions) uint64 {
	retained := predictionBackingBytes(*pred)
	clear(view.cells[:cap(view.cells)])
	releaseCapacity(view.cells, view.budget)
	view.cells = nil
	truth.wipeMetadata()
	pred.wipe()
	return retained
}
