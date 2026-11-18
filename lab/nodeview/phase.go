package nodeview

func validPhasePredecessor(c Config, p Plan) bool {
	if c.Set != p.Set || c.Suite.String() != p.Suite {
		return false
	}
	switch c.Phase {
	case Structural:
		return p.Phase == Structural && !p.TrainingReady && !p.PilotReady && !p.ModelReady
	case Train:
		return p.Phase == Structural && !p.TrainingReady && !p.PilotReady && !p.ModelReady && len(p.Samples) == 0 && len(p.FrozenModels) == 0 && len(p.Powers) == 0 && len(p.PowerSearch) == 0 && p.MainSeedCommitment == ""
	case Pilot:
		if c.Set == Compromise {
			return p.Phase == Structural && !p.ModelReady
		}
		if len(p.Powers) != 0 || len(p.PowerSearch) != 0 || p.PilotReady {
			return false
		}
		if c.Set == Mailbox {
			return p.Phase == Train && p.TrainingReady && len(p.FrozenModels) == 8
		}
		return p.Phase == Structural && !p.TrainingReady
	case Primary:
		if p.Suite == "gost" {
			if c.Set == Mailbox {
				return p.Phase == Train && p.TrainingReady && len(p.FrozenModels) == 8 && len(p.Powers) == 0
			}
			return p.Phase == Structural && !p.PilotReady && !p.ModelReady
		}
		if p.Phase != Pilot {
			return false
		}
		if c.Set == Compromise {
			return p.ModelReady
		}
		return p.PilotReady && p.TrainingReady && len(p.FrozenModels) == 8
	}
	return false
}
