package nodeview

func mergeTruth(dst *privateTruth, src privateTruth) error {
	if len(src.messages) > maxMessages-len(dst.messages) || len(src.seals) > maxTruthRecords-len(dst.seals) || len(src.setups) > maxContexts-len(dst.setups) || len(src.requests) > maxSelectedCells-len(dst.requests) || len(src.fragments) > maxSelectedCells-len(dst.fragments) {
		return fail(ReasonLimit)
	}
	var e error
	dst.setups, e = appendCapacity(dst.setups, len(src.setups), dst.budget)
	if e != nil {
		return e
	}
	dst.setups = append(dst.setups, src.setups...)
	dst.messages, e = appendCapacity(dst.messages, len(src.messages), dst.budget)
	if e != nil {
		return e
	}
	dst.messages = append(dst.messages, src.messages...)
	dst.seals, e = appendCapacity(dst.seals, len(src.seals), dst.budget)
	if e != nil {
		return e
	}
	dst.seals = append(dst.seals, src.seals...)
	dst.requests, e = appendCapacity(dst.requests, len(src.requests), dst.budget)
	if e != nil {
		return e
	}
	dst.requests = append(dst.requests, src.requests...)
	dst.fragments, e = appendCapacity(dst.fragments, len(src.fragments), dst.budget)
	if e != nil {
		return e
	}
	dst.fragments = append(dst.fragments, src.fragments...)
	return nil
}
