package nodeview

import (
	"time"

	"github.com/jimichi-org/jimichi/mailbox"
)

type boundaryAction uint8

const (
	boundaryNoAction boundaryAction = iota
	boundaryCloseBeforeEpoch
	boundaryPairAtTime
	boundaryCloseInitialAtTime
)

type boundaryProfile struct {
	name              string
	routes            [2][3]uint8
	sourceCount       int
	sourceOffsetsNS   [2]int64
	actions           [2]boundaryAction
	actionAtNS        int64
	pairedBeforeBegin bool
}

func boundaryProfileFor(id uint8) (boundaryProfile, bool) {
	p := boundaryProfile{routes: [2][3]uint8{{0, 1, 4}, {2, 3, 4}}, pairedBeforeBegin: true}
	switch id {
	case 1:
		p.name = "boundary-window-full"
		p.sourceCount = 1
		p.sourceOffsetsNS[0] = int64(time.Second)
	case 2:
		p.name = "boundary-put-full"
		p.sourceCount = 2
		p.sourceOffsetsNS = [2]int64{int64(time.Second), int64(10 * time.Second)}
	case 3:
		p.name = "boundary-no-messages"
	case 4:
		p.name = "boundary-one-requester"
		p.actions[1] = boundaryCloseBeforeEpoch
	case 5:
		p.name = "boundary-pre-session"
		p.actions = [2]boundaryAction{boundaryPairAtTime, boundaryPairAtTime}
		p.actionAtNS = int64(5 * time.Second)
		p.pairedBeforeBegin = false
	case 6:
		p.name = "boundary-stale"
	case 7:
		p.name = "boundary-rebuild"
		p.sourceCount = 2
		p.sourceOffsetsNS = [2]int64{int64(time.Second), int64(10 * time.Second)}
		p.actions[0] = boundaryCloseInitialAtTime
		p.actionAtNS = int64(5 * time.Second)
	default:
		return boundaryProfile{}, false
	}
	return p, true
}

func boundaryProfileSettings(id uint8) (Settings, bool) {
	if _, ok := boundaryProfileFor(id); !ok {
		return Settings{}, false
	}
	s := peerSettings(false, 0)
	s.ControlProfile = id
	s.RateNS = int64(50 * time.Millisecond)
	s.StaleFetches = 1800
	s.Workload = "registered-structural-control"
	s.DurationNS = int64(20 * time.Second)
	switch id {
	case 1:
		s.Window = 1
		s.RelayPeriodNS = int64(51 * time.Millisecond)
		s.CoverPuts = true
	case 2:
		s.CoverPuts = true
	}
	return s, true
}

func boundaryProfileStoreLimits(id uint8) (mailbox.Limits, bool) {
	if id > 7 {
		return mailbox.Limits{}, false
	}
	if id == 2 {
		return mailbox.Limits{TTL: 5 * time.Minute, Depth: 2, Queues: 2, Records: 4, Circuits: 32}, true
	}
	return mailbox.DefaultLimits(), true
}

// profile 6 selects by public Static-card order: 0 is the initiator, 1 is the responder
func boundaryProfileSideSettings(id uint8, side uint16) (Settings, bool) {
	if side > 1 {
		return Settings{}, false
	}
	s, ok := boundaryProfileSettings(id)
	if !ok {
		return Settings{}, false
	}
	if id == 2 && side == 1 {
		s.RateNS = int64(500 * time.Millisecond)
		s.CoverPuts = false
		s.StaleFetches = 180
	}
	if id == 6 {
		if side == 0 {
			s.KeepaliveNS = int64(10 * time.Second)
			s.StaleAfterNS = int64(30 * time.Second)
			s.StaleFetches = 600
		} else {
			s.StaleAfterNS = int64(2 * time.Second)
			s.StaleFetches = 40
		}
	}
	return s, true
}

func boundaryCoordinates() []Coordinate {
	out := make([]Coordinate, 0, 7)
	for id := uint8(1); id <= 7; id++ {
		profile, _ := boundaryProfileFor(id)
		settings, _ := boundaryProfileSettings(id)
		out = append(out, Coordinate{
			ID:            profile.name,
			Topology:      "peer",
			Trust:         "trusted",
			Population:    "boundary",
			Controlled:    []int{4},
			Missing:       2,
			Mailbox:       4,
			Placement:     "mailbox",
			Setup:         "serial",
			Mode:          "immediate",
			N:             5,
			H:             3,
			Conversations: 1,
			Settings:      settings,
		})
	}
	return out
}
