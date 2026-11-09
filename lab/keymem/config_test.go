package keymem

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

func validTestConfig() Config {
	return Config{Suite: jcrypto.SuiteC25519, Repeats: 1, Seed: 1, Revision: strings.Repeat("a", 40)}
}

func TestConfigValidation(t *testing.T) {
	for _, suite := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, repeats := range []int{1, 30, 100} {
			c := validTestConfig()
			c.Suite, c.Repeats = suite, repeats
			if err := c.validate(); err != nil {
				t.Fatal("supported configuration rejected")
			}
		}
	}
	for _, tt := range []struct {
		name string
		edit func(*Config)
	}{
		{"unknown-suite", func(c *Config) { c.Suite = 0 }},
		{"zero-repeats", func(c *Config) { c.Repeats = 0 }},
		{"negative-repeats", func(c *Config) { c.Repeats = -1 }},
		{"too-many-repeats", func(c *Config) { c.Repeats = 101 }},
		{"empty-revision", func(c *Config) { c.Revision = "" }},
		{"short-revision", func(c *Config) { c.Revision = strings.Repeat("a", 39) }},
		{"long-revision", func(c *Config) { c.Revision = strings.Repeat("a", 41) }},
		{"uppercase-revision", func(c *Config) { c.Revision = strings.Repeat("A", 40) }},
		{"nonhex-revision", func(c *Config) { c.Revision = strings.Repeat("g", 40) }},
		{"revision-newline", func(c *Config) { c.Revision += "\n" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := validTestConfig()
			tt.edit(&c)
			if !errors.Is(c.validate(), errInvalidConfig) {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestPlanFixedMatrix(t *testing.T) {
	c := validTestConfig()
	c.Repeats = 30
	cells := plan(c)
	// 2 policies times 3 checkpoints times 30 repeats gives 180 independent children per suite
	if len(cells) != 180 {
		t.Fatalf("planned %d children, want 180", len(cells))
	}
	for repeat := 0; repeat < c.Repeats; repeat++ {
		seen := map[string]bool{}
		for order, cell := range cells[repeat*6 : (repeat+1)*6] {
			absolute := repeat*6 + order
			if cell.ID != uint64(absolute+1) || cell.Order != absolute || cell.Repeat != repeat {
				t.Fatal("plan identifiers or order are inconsistent")
			}
			if cell.Policy != "none" && cell.Policy != "all" {
				t.Fatal("unapproved policy in plan")
			}
			if cell.Checkpoint != "active" && cell.Checkpoint != "closed-now" && cell.Checkpoint != "closed-1s" {
				t.Fatal("unapproved checkpoint in plan")
			}
			key := cell.Policy + "/" + cell.Checkpoint
			if seen[key] {
				t.Fatal("condition repeated within a block")
			}
			seen[key] = true
		}
		if len(seen) != 6 {
			t.Fatal("a repeat block omitted a condition")
		}
	}
	if !reflect.DeepEqual(cells, plan(c)) {
		t.Fatal("same seed changed planned order")
	}
	c.Suite = jcrypto.SuiteGOST
	if !reflect.DeepEqual(cells, plan(c)) {
		t.Fatal("suite changed the public scheduling stream")
	}
	c.Seed = 2
	if reflect.DeepEqual(cells, plan(c)) {
		t.Fatal("seed did not affect scheduling")
	}
	first, second := make([]string, 6), make([]string, 6)
	for i := range first {
		first[i] = cells[i].Policy + "/" + cells[i].Checkpoint
		second[i] = cells[i+6].Policy + "/" + cells[i+6].Checkpoint
	}
	if reflect.DeepEqual(first, second) {
		t.Fatal("seed-1 repeat blocks unexpectedly reused one shuffle")
	}
}

func TestNewTrialUnavailableOutcomes(t *testing.T) {
	row := newTrial(validTestConfig(), plannedCell{ID: 1, Policy: "none", Checkpoint: "active"})
	row.AnyMatch = pointer(true)
	for i := range row.Keys {
		row.Keys[i].Matches = pointer(uint64(i + 1))
	}
	row.terminal("capture_incomplete")
	if row.AnyMatch != nil || row.ErrorClass == nil || *row.ErrorClass != row.Status {
		t.Fatal("unavailable row retained a primary outcome")
	}
	for i, key := range row.Keys {
		if key.Class != "cell" || key.Hop != i || key.Matches != nil {
			t.Fatal("unavailable row retained a key outcome")
		}
	}
	row.terminal("evaluated")
	if row.ErrorClass != nil {
		t.Fatal("evaluated row retained an error class")
	}
}
