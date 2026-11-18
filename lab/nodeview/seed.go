package nodeview

import "github.com/jimichi-org/jimichi/lab"

func phaseDomain(p Phase) uint64 {
	switch p {
	case Train:
		return lab.StreamNodeTraining
	case Pilot:
		return lab.StreamNodePilot
	case Primary:
		return lab.StreamNodeMain
	default:
		return lab.StreamNodeModel
	}
}
func nodeSeed(c Config, id, repeat, side uint64, domain uint64) int64 {
	phase := lab.Derive(c.Seed, phaseDomain(c.Phase), id, repeat, side)
	return lab.Derive(phase, domain, id, repeat, side)
}
func coordinateID(id string) uint64 {
	var x uint64 = 1469598103934665603
	for _, b := range []byte(id) {
		x ^= uint64(b)
		x *= 1099511628211
	}
	return x
}
