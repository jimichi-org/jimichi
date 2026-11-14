package nodeview

func registeredOrphan(c Config, row Coordinate) bool {
	return c.Set == Compromise && c.Phase == Structural && (row.ID == "trust-peer-honest-k1-m1" && row.Missing == 1 || row.ID == "trust-peer-honest-k1-m2" && row.Missing == 2) && row.Topology == "peer" && row.Mailbox == 4 && len(row.ForeignPositions) == 1 && row.ForeignPositions[0] == 0 && row.Settings == peerSettings(false, 0)
}
