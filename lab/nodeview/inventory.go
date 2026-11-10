package nodeview

type cohortInventory struct{ messages, setups, seals, requests, fragments int }

func (i *cohortInventory) reserveTruth(kind uint8, n int) error {
	if n < 1 || n > 128 {
		return fail(ReasonIPC)
	}
	var count *int
	limit := 0
	origin := boundNone
	switch kind {
	case 1:
		count, limit = &i.messages, maxMessages
		origin = boundCohortMessages
	case 2:
		count, limit = &i.setups, maxContexts
		origin = boundCohortSetups
	case 3:
		count, limit = &i.seals, maxTruthRecords
		origin = boundCohortSeals
	case 4:
		count, limit = &i.requests, maxSelectedCells
		origin = boundCohortRequests
	case 5:
		count, limit = &i.fragments, maxSelectedCells
		origin = boundCohortFragments
	default:
		return fail(ReasonIPC)
	}
	if *count > limit || n > limit-*count {
		return recordBound(origin, *count, n, limit)
	}
	*count += n
	return nil
}
