package nodeview

func plannedTaskCount(c Config, p Plan) (int, error) {
	if c.Set == Compromise && c.Phase == Pilot {
		return 0, nil
	}
	if c.Set == Mailbox && c.Phase == Train {
		return 20, nil
	}
	total := 0
	add := func(n int) bool {
		if n < 0 || n > 163841-total {
			return false
		}
		total += n
		return true
	}
	if c.Set == Compromise {
		for _, row := range p.Configurations {
			if c.Phase == Primary && c.Suite.String() == "c25519" {
				if row.Population != "trust" && row.Population != "membership" && !add(row.Slots/32) {
					return 0, fail(ReasonLimit)
				}
				continue
			}
			if c.Peer && row.Topology != "peer" {
				continue
			}
			n := 1
			if row.Topology == "echo" && row.Population != "membership" {
				n = 2
			}
			if !add(n) {
				return 0, fail(ReasonLimit)
			}
		}
		return total, nil
	}
	for _, row := range p.Configurations {
		if row.Settings.ControlProfile != 0 {
			if c.Phase == Structural && !add(1) {
				return 0, fail(ReasonLimit)
			}
			continue
		}
		control := row.Population == "control" || row.Population == "incomplete" || row.Population == "defaults-control"
		if control && c.Phase != Structural && !(c.Set == Collude && c.Suite.String() == "gost" && c.Phase == Primary) {
			continue
		}
		n := 1
		if c.Phase == Pilot {
			n = 5
		} else if c.Phase == Primary {
			n = row.Main
		}
		if c.Suite.String() == "gost" && c.Phase == Primary {
			n = 1
			if c.Set == Mailbox {
				n = 5
			}
		}
		if control && c.Set == Collude && c.Suite.String() == "c25519" {
			n = 5
		}
		if !add(n) {
			return 0, fail(ReasonLimit)
		}
	}
	return total, nil
}
