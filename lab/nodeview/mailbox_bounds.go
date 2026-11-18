package nodeview

func boundedMailboxRows(node nodeView, period int64) ([]encodedMailboxRow, error) {
	if len(node.mailbox) > maxTruthRecords || len(node.mailbox) > 0 && node.position != 4 {
		return nil, fail(ReasonContract)
	}
	var circuits [maxConnections]uint32
	var queues [maxClients]uint32
	defer clear(circuits[:])
	defer clear(queues[:])
	ci, qi := 0, 0
	add := func(values []uint32, n *int, value uint32) bool {
		if value == 0 {
			return true
		}
		for _, prior := range values[:*n] {
			if prior == value {
				return true
			}
		}
		if *n == len(values) {
			return false
		}
		values[*n] = value
		*n++
		return true
	}
	for _, o := range node.mailbox {
		if o.Circuit == 0 || o.HasPut && o.RecordAlias == 0 || !add(circuits[:], &ci, o.Circuit) || !add(queues[:], &qi, o.PutQueue) || !add(queues[:], &qi, o.FetchQueue) {
			return nil, fail(ReasonContract)
		}
	}
	return extractMailboxRowsBudgeted(node.mailbox, period, node.budget)
}
