package nodeview

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func TestConfigRejectsBeforeRuntime(t *testing.T) {
	base := Config{Set: Compromise, Phase: Structural, Suite: jcrypto.SuiteC25519, Revision: strings.Repeat("a", 40)}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Set = "unknown" },
		func(c *Config) { c.Phase = "unknown" },
		func(c *Config) { c.Suite = 99 },
		func(c *Config) { c.Revision = strings.Repeat("A", 40) },
		func(c *Config) { c.Revision = "unknown" },
		func(c *Config) { c.Phase = Primary },
		func(c *Config) { c.Phase = Pilot },
		func(c *Config) { c.Phase = Train },
		func(c *Config) { c.Set = Collude; c.Peer = true },
		func(c *Config) { c.Phase = Primary; c.PlanPath = "plan.json"; c.Peer = true },
	} {
		c := base
		mutate(&c)
		if _, err := Run(context.Background(), c); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid config entered runtime: %v", err)
		}
	}
}

func TestConfigAcceptedPhasesAndSuites(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, set := range []Set{Compromise, Collude, Mailbox} {
			for _, phase := range []Phase{Structural, Train, Pilot, Primary} {
				if phase == Train && set != Mailbox {
					continue
				}
				c := Config{Set: set, Phase: phase, Suite: s, Revision: strings.Repeat("a", 40), PlanPath: "plan.json"}
				if err := c.validate(); err != nil {
					t.Fatalf("%s/%s/%s: %v", s.String(), set, phase, err)
				}
			}
		}
	}
}

func TestTrainingRequiresFrozenPredecessorBeforeRuntime(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		c := Config{Set: Mailbox, Phase: Train, Suite: s, Revision: strings.Repeat("a", 40)}
		if report, err := Run(context.Background(), c); !errors.Is(err, ErrInvalid) || report.Schema != "" {
			t.Fatal("unregistered training entered runtime")
		}
		c.PlanPath = "structural.json"
		if err := c.validate(); err != nil {
			t.Fatal("honest training lineage was rejected before loading")
		}
	}
}

func TestRegisteredCohortsFitCapacity(t *testing.T) {
	settings := []Settings{echoSettings(0), echoSettings(1), echoSettings(2)}
	for _, period := range []int64{0, 33250000} {
		for _, cover := range []bool{false, true} {
			settings = append(settings, peerSettings(cover, period))
		}
	}
	for _, s := range settings {
		for _, sides := range []int{1, 20, 32} {
			if err := cohortCapacity(s, sides); err != nil {
				t.Fatalf("registered %s rate %d sides %d: %v", s.Workload, s.RateNS, sides, err)
			}
		}
	}
	for _, sides := range []int{0, 33, math.MaxInt} {
		if err := cohortCapacity(echoSettings(0), sides); err == nil {
			t.Fatalf("accepted %d sides", sides)
		}
	}
}

func TestCohortCapacityExactLifecycleBoundary(t *testing.T) {
	s := echoSettings(1)
	// 960 timed cells plus 64 reserved cells, two directions and 32 sides use 65536 lifecycles
	s.DurationNS = int64(33600 * time.Millisecond)
	if err := cohortCapacity(s, 32); err != nil {
		t.Fatalf("exact lifecycle cap rejected: %v", err)
	}
	s.DurationNS += int64(35 * time.Millisecond)
	if err := cohortCapacity(s, 32); err == nil {
		t.Fatal("next lifecycle batch accepted beyond cap")
	}
	s.DurationNS = math.MaxInt64
	if err := cohortCapacity(s, 32); err == nil {
		t.Fatal("unbounded duration accepted")
	}
}

func TestRegisteredReplyTimeoutPreservesProductionGuard(t *testing.T) {
	s := peerSettings(false, 0)
	if err := s.validate(true); err != nil {
		t.Fatalf("registered 35ms/7s rejected: %v", err)
	}
	s.ReplyTimeoutNS = int64(10 * time.Second)
	if err := s.validate(true); err == nil {
		t.Fatal("35ms/default10s accepted")
	}
	for i := range 4 {
		s = peerSettings(false, 0)
		switch i {
		case 0:
			s.SourceHandshakes = 0
		case 1:
			s.SourceLinks = 0
		case 2:
			s.SourceLinkRate = 0
		case 3:
			s.SourceSetupRate = 0
		}
		if err := s.validate(true); err == nil {
			t.Fatal("unregistered per-source throttle accepted")
		}
	}
}

func TestCheckedProductDoesNotOverflow(t *testing.T) {
	for _, tc := range []struct {
		a, b, limit, want int
		ok                bool
	}{
		{0, math.MaxInt, 65536, 0, true},
		{32, 2048, 65536, 65536, true},
		{32, 2049, 65536, 0, false},
		{math.MaxInt, 2, math.MaxInt, 0, false},
		{-1, 2, 65536, 0, false},
	} {
		got, ok := checkedProduct(tc.a, tc.b, tc.limit)
		if ok != tc.ok || ok && got != tc.want {
			t.Fatalf("%d*%d cap %d: %d,%v", tc.a, tc.b, tc.limit, got, ok)
		}
	}
}
