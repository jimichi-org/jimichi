package nodeview

import (
	"context"
	"regexp"
	"time"

	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

type Set string
type Phase string

const (
	Compromise Set   = "compromise"
	Collude    Set   = "collude"
	Mailbox    Set   = "mailbox"
	Structural Phase = "structural"
	Train      Phase = "train"
	Pilot      Phase = "pilot"
	Primary    Phase = "primary"
)

const (
	planSchema           = "jimichi-nodeview-plan-v1"
	reportSchema         = "jimichi-nodeview-v1"
	featureVersion       = "mailbox18-release-v2"
	maxClients           = 32
	maxConnections       = 128
	maxPendingFrames     = 512
	maxContexts          = 8192
	maxLifecycles        = 65536
	relayArenaBytes      = 32 << 20
	controllerArenaBytes = 128 << 20
	clientArenaBytes     = 1 << 20
	maxTruthRecords      = 32768
	maxMessages          = 32768
	maxSelectedCells     = 262144
	payloadBytes         = 128
	maxTrainingRows      = 131072
	maxIPCMessages       = 8192
	maxFrameBytes        = 65536
)

var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Config struct {
	sourceReplay     *sourceReplayScratch
	binarySHA        string
	retainedRawBytes uint64
	resultCharge     *resultCharge
	trainingBudget   *memoryBudget
	outputBudget     *memoryBudget
	hostCapacity     *hostCapacity
	resources        *resourceUsage
	publicTaskBytes  uint64
	Set              Set
	Phase            Phase
	Suite            jcrypto.Suite
	Seed             int64
	Revision         string
	PlanPath         string
	Peer             bool
}

func (c Config) validate() error {
	if c.Set != Compromise && c.Set != Collude && c.Set != Mailbox {
		return ErrInvalid
	}
	if c.Phase != Structural && c.Phase != Train && c.Phase != Pilot && c.Phase != Primary {
		return ErrInvalid
	}
	if c.Suite != jcrypto.SuiteC25519 && c.Suite != jcrypto.SuiteGOST {
		return ErrInvalid
	}
	if !revisionPattern.MatchString(c.Revision) {
		return ErrInvalid
	}
	if c.Peer && (c.Set != Compromise || c.Phase != Structural) {
		return ErrInvalid
	}
	if c.Phase == Train && c.Set != Mailbox {
		return ErrInvalid
	}
	if (c.Phase == Train || c.Phase == Pilot || c.Phase == Primary) && c.PlanPath == "" {
		return ErrInvalid
	}
	return nil
}

type Settings struct {
	ControlProfile   uint8  `json:"control_profile"`
	RateNS           int64  `json:"rate_ns"`
	RelayPeriodNS    int64  `json:"relay_period_ns"`
	ReplyTimeoutNS   int64  `json:"reply_timeout_ns"`
	KeepaliveNS      int64  `json:"keepalive_ns"`
	StaleAfterNS     int64  `json:"stale_after_ns"`
	RebuildForNS     int64  `json:"rebuild_for_ns"`
	Window           int    `json:"window"`
	MaxRefusals      int    `json:"max_refusals"`
	Outbox           int    `json:"outbox"`
	Hold             int    `json:"hold"`
	Inbox            int    `json:"inbox"`
	StaleFetches     int    `json:"stale_fetches"`
	SourceHandshakes int    `json:"max_handshakes_per_source"`
	SourceLinks      int    `json:"max_links_per_source"`
	SourceLinkRate   int    `json:"source_link_rate"`
	SourceSetupRate  int    `json:"source_setup_rate"`
	MaxHandshakes    int    `json:"max_handshakes"`
	MaxLinks         int    `json:"max_links"`
	Dispatch         int    `json:"dispatch"`
	CoverPuts        bool   `json:"cover_puts"`
	Workload         string `json:"workload"`
	DurationNS       int64  `json:"duration_ns"`
}

func echoSettings(level int) Settings {
	s := Settings{SourceHandshakes: -1, SourceLinks: -1, SourceLinkRate: -1, SourceSetupRate: -1, MaxHandshakes: 32, MaxLinks: 512, Dispatch: 16, Workload: "echo-exponential-v1", DurationNS: int64(20 * time.Second)}
	if level > 0 {
		s.RateNS = int64(35 * time.Millisecond)
	}
	if level > 1 {
		s.RelayPeriodNS = 33250000
	}
	return s
}

func peerSettings(cover bool, period int64) Settings {
	s := echoSettings(0)
	s.RateNS = 35000000
	s.RelayPeriodNS = period
	s.ReplyTimeoutNS = 7000000000
	s.KeepaliveNS = 1000000000
	s.StaleAfterNS = 90000000000
	s.RebuildForNS = 600000000000
	s.Window, s.MaxRefusals, s.Outbox, s.Hold, s.Inbox, s.StaleFetches = 16, 3, 256, 16, 256, 2571
	s.CoverPuts, s.Workload, s.DurationNS = cover, "active20-quiet10-v1", 30000000000
	return s
}

func (s Settings) validate(peer bool) error {
	if s.ControlProfile != 0 {
		want, ok := boundaryProfileSettings(s.ControlProfile)
		if !peer || !ok || s != want || time.Duration(s.RateNS) < conversation.MinRate(time.Duration(s.ReplyTimeoutNS)) {
			return ErrInvalid
		}
		return nil
	}
	if s.SourceHandshakes != -1 || s.SourceLinks != -1 || s.SourceLinkRate != -1 || s.SourceSetupRate != -1 || s.MaxHandshakes != 32 || s.MaxLinks != 512 || s.Dispatch != 16 {
		return ErrInvalid
	}
	if s.RelayPeriodNS != 0 && s.RelayPeriodNS != 33250000 {
		return ErrInvalid
	}
	if peer {
		if s != peerSettings(s.CoverPuts, s.RelayPeriodNS) && s != defaultsSettings(s.RelayPeriodNS) || time.Duration(s.RateNS) < conversation.MinRate(time.Duration(s.ReplyTimeoutNS)) {
			return ErrInvalid
		}
	} else if s != echoSettings(0) && s != echoSettings(1) && s != echoSettings(2) {
		return ErrInvalid
	}
	return nil
}

func defaultsSettings(period int64) Settings {
	s := peerSettings(false, period)
	s.KeepaliveNS = 30000000000
	s.Workload = "registered-structural-control"
	return s
}

func checkedProduct(a, b, limit int) (int, bool) {
	if a < 0 || b < 0 || a != 0 && b > limit/a {
		return 0, false
	}
	return a * b, true
}

func cohortCapacity(s Settings, sides int) error {
	if s.DurationNS <= 0 || s.DurationNS > int64(10*time.Minute) || s.RateNS < 0 {
		return ErrInvalid
	}
	if sides < 1 || sides > maxClients {
		return ErrInvalid
	}
	cells := 1024
	if s.RateNS > 0 {
		cells = int(s.DurationNS/s.RateNS) + 64
	}
	if _, ok := checkedProduct(cells, sides*2, maxLifecycles); !ok {
		return fail(ReasonLimit)
	}
	if _, ok := checkedProduct(cells, sides*6, maxSelectedCells); !ok {
		return fail(ReasonLimit)
	}
	if time.Duration(s.DurationNS)+30*time.Second+time.Duration(sides)*5*time.Second+30*time.Second+10*time.Second+12*time.Second > 10*time.Minute {
		return ErrInvalid
	}
	return nil
}

func Run(ctx context.Context, c Config) (Report, error) {
	if err := c.validate(); err != nil {
		return Report{}, err
	}
	return run(ctx, c)
}
