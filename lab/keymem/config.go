package keymem

import (
	"errors"
	"math/rand"
	"regexp"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

const (
	schema          = "keymem-cooperative-v1"
	view            = "go-exported-object-payloads-v1"
	privateArg      = "--keymem-child-v1"
	trialTimeout    = 60 * time.Second
	maxStreamBytes  = 128 << 20
	maxBinaryBytes  = 64 << 20
	maxConfigBytes  = 32768
	maxStatusBytes  = 1024
	maxStatusStream = 8192
)

var (
	errParseInvalid          = errors.New("parse_invalid")
	errCaptureIncomplete     = errors.New("capture_incomplete")
	errCaptureLimit          = errors.New("capture_limit")
	errControlFailed         = errors.New("control_failed")
	errAllocationFailed      = errors.New("allocation_failed")
	errProtectionUnavailable = errors.New("protection_unavailable")
	errControllerFailed      = errors.New("controller_failed")
	errProtocolInvalid       = errors.New("protocol_invalid")
	errOracleInvalid         = errors.New("oracle_invalid")
	errInvalidConfig         = errors.New("keymem: invalid_config")
	errFixtureCleanup        = errors.New("fixture_cleanup_failed")
	revisionPattern          = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type Config struct {
	Suite    jcrypto.Suite
	Repeats  int
	Seed     int64
	Revision string
}

func (c Config) validate() error {
	if (c.Suite != jcrypto.SuiteC25519 && c.Suite != jcrypto.SuiteGOST) || c.Repeats < 1 || c.Repeats > 100 || !revisionPattern.MatchString(c.Revision) {
		return errInvalidConfig
	}
	return nil
}

type plannedCell struct {
	ID         uint64 `json:"id"`
	Repeat     int    `json:"repeat"`
	Order      int    `json:"order"`
	Policy     string `json:"policy"`
	Checkpoint string `json:"checkpoint"`
}

func plan(c Config) []plannedCell {
	rng := rand.New(rand.NewSource(c.Seed))
	out := make([]plannedCell, 0, c.Repeats*6)
	for repeat := 0; repeat < c.Repeats; repeat++ {
		block := make([]plannedCell, 0, 6)
		for _, policy := range []string{"none", "all"} {
			for _, checkpoint := range []string{"active", "closed-now", "closed-1s"} {
				block = append(block, plannedCell{Repeat: repeat, Policy: policy, Checkpoint: checkpoint})
			}
		}
		rng.Shuffle(len(block), func(i, j int) { block[i], block[j] = block[j], block[i] })
		for _, cell := range block {
			cell.ID = uint64(len(out) + 1)
			cell.Order = len(out)
			out = append(out, cell)
		}
	}
	return out
}

func pointer[T any](v T) *T { return &v }
