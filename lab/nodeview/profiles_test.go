package nodeview

import (
	"reflect"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/conversation"
	"github.com/jimichi-org/jimichi/mailbox"
)

func TestBoundaryProfileCatalog(t *testing.T) {
	want := []boundaryProfile{
		{name: "boundary-window-full", routes: [2][3]uint8{{0, 1, 4}, {2, 3, 4}}, sourceCount: 1, sourceOffsetsNS: [2]int64{1000000000, 0}, pairedBeforeBegin: true},
		{name: "boundary-put-full", routes: [2][3]uint8{{0, 1, 4}, {2, 3, 4}}, sourceCount: 2, sourceOffsetsNS: [2]int64{1000000000, 10000000000}, pairedBeforeBegin: true},
		{name: "boundary-no-messages", routes: [2][3]uint8{{0, 1, 4}, {2, 3, 4}}, pairedBeforeBegin: true},
		{name: "boundary-one-requester", routes: [2][3]uint8{{0, 1, 4}, {2, 3, 4}}, actions: [2]boundaryAction{boundaryNoAction, boundaryCloseBeforeEpoch}, pairedBeforeBegin: true},
		{name: "boundary-pre-session", routes: [2][3]uint8{{0, 1, 4}, {2, 3, 4}}, actions: [2]boundaryAction{boundaryPairAtTime, boundaryPairAtTime}, actionAtNS: 5000000000},
		{name: "boundary-stale", routes: [2][3]uint8{{0, 1, 4}, {2, 3, 4}}, pairedBeforeBegin: true},
		{name: "boundary-rebuild", routes: [2][3]uint8{{0, 1, 4}, {2, 3, 4}}, sourceCount: 2, sourceOffsetsNS: [2]int64{1000000000, 10000000000}, actions: [2]boundaryAction{boundaryCloseInitialAtTime, boundaryNoAction}, actionAtNS: 5000000000, pairedBeforeBegin: true},
	}
	coordinates := boundaryCoordinates()
	if len(coordinates) != 7 {
		t.Fatalf("boundary coordinates: got %d, want 7", len(coordinates))
	}
	seen := make(map[string]bool)
	sources, sides := 0, 0
	for i, expected := range want {
		id := uint8(i + 1)
		got, ok := boundaryProfileFor(id)
		if !ok || got != expected {
			t.Fatalf("profile %d: got %+v/%v, want %+v", id, got, ok, expected)
		}
		if seen[got.name] {
			t.Fatalf("duplicate profile name %q", got.name)
		}
		seen[got.name] = true
		settings, ok := boundaryProfileSettings(id)
		if !ok {
			t.Fatalf("profile %d has no settings", id)
		}
		wantCoordinate := Coordinate{ID: expected.name, Topology: "peer", Trust: "trusted", Population: "boundary", Controlled: []int{4}, Missing: 2, Mailbox: 4, Placement: "mailbox", Setup: "serial", Mode: "immediate", N: 5, H: 3, Conversations: 1, Settings: settings}
		if !reflect.DeepEqual(coordinates[i], wantCoordinate) {
			t.Fatalf("profile %d coordinate: %+v", id, coordinates[i])
		}
		sources += 2 * got.sourceCount
		sides += 2 * coordinates[i].Conversations
		for source, offset := range got.sourceOffsetsNS {
			if source < got.sourceCount {
				if offset <= 0 || offset >= settings.DurationNS {
					t.Fatalf("profile %d source %d outside observation: %d", id, source, offset)
				}
			} else if offset != 0 {
				t.Fatalf("profile %d has an undeclared source offset", id)
			}
		}
	}
	if sources != 10 || sides != 14 {
		t.Fatalf("per-suite source bodies %d, sides %d; want 10, 14", sources, sides)
	}
}

func TestBoundaryProfileSettings(t *testing.T) {
	base := Settings{
		RateNS: 50000000, ReplyTimeoutNS: 7000000000, KeepaliveNS: 1000000000,
		StaleAfterNS: 90000000000, RebuildForNS: 600000000000,
		Window: 16, MaxRefusals: 3, Outbox: 256, Hold: 16, Inbox: 256, StaleFetches: 1800,
		SourceHandshakes: -1, SourceLinks: -1, SourceLinkRate: -1, SourceSetupRate: -1,
		MaxHandshakes: 32, MaxLinks: 512, Dispatch: 16,
		Workload: "registered-structural-control", DurationNS: 20000000000,
	}
	for _, expected := range []struct {
		id     uint8
		period int64
		window int
		cover  bool
	}{{1, 51000000, 1, true}, {2, 0, 16, true}, {3, 0, 16, false}, {4, 0, 16, false}, {5, 0, 16, false}, {6, 0, 16, false}, {7, 0, 16, false}} {
		want := base
		want.ControlProfile = expected.id
		want.RelayPeriodNS, want.Window, want.CoverPuts = expected.period, expected.window, expected.cover
		got, ok := boundaryProfileSettings(expected.id)
		if !ok || got != want {
			t.Fatalf("wire profile %d: got %+v/%v, want %+v", expected.id, got, ok, want)
		}
	}
}

func TestBoundaryProfileSideSettings(t *testing.T) {
	if got := conversation.MinRate(7 * time.Second); got != 27450981*time.Nanosecond {
		t.Fatalf("minimum rate: got %v, want 27450981ns", got)
	}
	for _, expected := range []struct {
		id           uint8
		side         uint16
		rate         int64
		keepalive    int64
		staleAfter   int64
		staleFetches int
		cover        bool
	}{
		{1, 0, 50000000, 1000000000, 90000000000, 1800, true},
		{1, 1, 50000000, 1000000000, 90000000000, 1800, true},
		{2, 0, 50000000, 1000000000, 90000000000, 1800, true},
		{2, 1, 500000000, 1000000000, 90000000000, 180, false},
		{3, 0, 50000000, 1000000000, 90000000000, 1800, false},
		{3, 1, 50000000, 1000000000, 90000000000, 1800, false},
		{4, 0, 50000000, 1000000000, 90000000000, 1800, false},
		{4, 1, 50000000, 1000000000, 90000000000, 1800, false},
		{5, 0, 50000000, 1000000000, 90000000000, 1800, false},
		{5, 1, 50000000, 1000000000, 90000000000, 1800, false},
		{6, 0, 50000000, 10000000000, 30000000000, 600, false},
		{6, 1, 50000000, 1000000000, 2000000000, 40, false},
		{7, 0, 50000000, 1000000000, 90000000000, 1800, false},
		{7, 1, 50000000, 1000000000, 90000000000, 1800, false},
	} {
		want, _ := boundaryProfileSettings(expected.id)
		want.RateNS, want.KeepaliveNS, want.StaleAfterNS = expected.rate, expected.keepalive, expected.staleAfter
		want.StaleFetches, want.CoverPuts = expected.staleFetches, expected.cover
		got, ok := boundaryProfileSideSettings(expected.id, expected.side)
		if !ok || got != want {
			t.Fatalf("profile %d side/card-order %d: got %+v/%v, want %+v", expected.id, expected.side, got, ok, want)
		}
		// StaleFetches counts successful empty fetches, with thresholds 90s/50ms, 90s/500ms, 30s/50ms or 2s/50ms
		if got.StaleFetches != int(got.StaleAfterNS/got.RateNS) || got.KeepaliveNS >= got.StaleAfterNS || time.Duration(got.RateNS) < conversation.MinRate(time.Duration(got.ReplyTimeoutNS)) {
			t.Fatalf("profile %d side/card-order %d violates production timing guards", expected.id, expected.side)
		}
	}
}

func TestBoundaryProfileStoreLimits(t *testing.T) {
	for id := uint8(0); id <= 7; id++ {
		want := mailbox.Limits{TTL: 300 * time.Second, Depth: 16, Queues: 1024, Records: 16384, Circuits: 4096}
		if id == 2 {
			want = mailbox.Limits{TTL: 300 * time.Second, Depth: 2, Queues: 2, Records: 4, Circuits: 32}
		}
		got, ok := boundaryProfileStoreLimits(id)
		if !ok || got != want {
			t.Fatalf("profile %d Store limits: got %+v/%v, want %+v", id, got, ok, want)
		}
	}
}

func TestBoundaryProfilesRejectUnknownAndWrongSide(t *testing.T) {
	for value := 0; value <= 255; value++ {
		id := uint8(value)
		want := value >= 1 && value <= 7
		profile, ok := boundaryProfileFor(id)
		if ok != want || !ok && profile != (boundaryProfile{}) {
			t.Fatalf("profile enum %d: got %+v/%v", id, profile, ok)
		}
		settings, ok := boundaryProfileSettings(id)
		if ok != want || !ok && settings != (Settings{}) {
			t.Fatalf("settings enum %d: got %+v/%v", id, settings, ok)
		}
		for _, side := range []uint16{0, 1, 2, 65535} {
			settings, ok := boundaryProfileSideSettings(id, side)
			if ok != (want && side < 2) || !ok && settings != (Settings{}) {
				t.Fatalf("side enum %d/%d: got %+v/%v", id, side, settings, ok)
			}
		}
		limits, ok := boundaryProfileStoreLimits(id)
		if ok != (value <= 7) || !ok && limits != (mailbox.Limits{}) {
			t.Fatalf("Store enum %d: got %+v/%v", id, limits, ok)
		}
	}
}

func TestBoundaryProfilesLeaveNormalSettingsUnchanged(t *testing.T) {
	normal := []Settings{echoSettings(0), echoSettings(1), echoSettings(2), peerSettings(false, 0), peerSettings(true, 0), peerSettings(false, 33250000), peerSettings(true, 33250000), defaultsSettings(0), defaultsSettings(33250000)}
	before := append([]Settings(nil), normal...)
	for i, settings := range normal {
		if settings.ControlProfile != 0 {
			t.Fatalf("normal configuration %d has boundary profile %d", i, settings.ControlProfile)
		}
		if preset, ok := boundaryProfileSettings(settings.ControlProfile); ok || preset != (Settings{}) {
			t.Fatalf("normal configuration %d was replaced by a boundary preset", i)
		}
	}
	for id := uint8(1); id <= 7; id++ {
		boundaryProfileFor(id)
		boundaryProfileSettings(id)
		boundaryProfileStoreLimits(id)
		boundaryProfileSideSettings(id, 0)
		boundaryProfileSideSettings(id, 1)
	}
	if !reflect.DeepEqual(normal, before) {
		t.Fatal("boundary lookup mutated normal settings")
	}
	for _, set := range []Set{Compromise, Collude, Mailbox} {
		for _, coordinate := range canonicalCoordinates(set) {
			if coordinate.Population != "boundary" && coordinate.Settings.ControlProfile != 0 {
				t.Fatalf("unrelated coordinate %s has boundary profile", coordinate.ID)
			}
		}
	}
	if len(modelIDs()) != 13 || len(differenceIDs()) != 13 {
		t.Fatal("boundary lookup changed inference family sizes")
	}
}

func TestBoundaryProfilesReturnIndependentValues(t *testing.T) {
	profile, _ := boundaryProfileFor(2)
	wantProfile := profile
	profile.routes[0][0] = 99
	profile.sourceOffsetsNS[0] = 99
	profile.actions[0] = boundaryCloseInitialAtTime
	if got, _ := boundaryProfileFor(2); got != wantProfile {
		t.Fatal("descriptor mutation affected registry")
	}
	settings, _ := boundaryProfileSettings(2)
	wantSettings := settings
	settings.RateNS = 99
	if got, _ := boundaryProfileSettings(2); got != wantSettings {
		t.Fatal("settings mutation affected registry")
	}
	limits, _ := boundaryProfileStoreLimits(2)
	wantLimits := limits
	limits.Depth = 99
	if got, _ := boundaryProfileStoreLimits(2); got != wantLimits {
		t.Fatal("Store-limit mutation affected registry")
	}
	coordinates := boundaryCoordinates()
	wantCoordinate := boundaryCoordinates()[0]
	coordinates[0].Controlled[0] = 99
	coordinates[0].Settings.DurationNS = 99
	if got := boundaryCoordinates()[0]; !reflect.DeepEqual(got, wantCoordinate) {
		t.Fatal("coordinate mutation affected registry")
	}
}

func TestBoundaryProfileResourceKnownAnswers(t *testing.T) {
	var maxDrain int64
	for id := uint8(1); id <= 7; id++ {
		settings, _ := boundaryProfileSettings(id)
		drain := max(int64(300*time.Millisecond), 12*(settings.RateNS+settings.RelayPeriodNS))
		maxDrain = max(maxDrain, drain)
	}
	// canonical profile 1: 12*(50+51)ms = 1.212s; slow-side overrides do not change the controller's drain recipe
	if maxDrain != 1212000000 {
		t.Fatalf("maximum registered drain: got %d, want 1212000000ns", maxDrain)
	}
	driverNS := int64(30*time.Second+200*time.Millisecond+20*time.Second+10*time.Second) + maxDrain
	cohortNS := int64(30*time.Second+2*5*time.Second+30*time.Second+200*time.Millisecond+20*time.Second+10*time.Second+2*time.Second) + maxDrain
	if driverNS != 61412000000 || driverNS >= int64(62*time.Second) || cohortNS != 103412000000 || cohortNS >= int64(10*time.Minute) {
		t.Fatalf("driver/cohort bounds: %d/%d", driverNS, cohortNS)
	}
	// 62s/50ms plus one in-flight tick; each request and Seal retain at most 392 bytes, plus four source bodies
	attempts := int64(62*time.Second)/int64(50*time.Millisecond) + 1
	arena := 392*(attempts+attempts) + 4*128
	if attempts != 1241 || arena != 973456 || (1<<20)-arena != 75120 {
		t.Fatalf("attempt/arena bound: %d/%d", attempts, arena)
	}
	// 1241 = 9*128+89 records per kind; two kinds use 20 chunks, with 30-byte headers and 3-byte prefixes
	chunks := (attempts + 127) / 128
	frames := 2*chunks + 63*3 + 4
	wireBytes := attempts*(399+404) + 2*chunks*(30+3) + 63*3*45 + 4*165
	if chunks != 10 || attempts%128 != 89 || frames != 213 || wireBytes != 1006348 || (1<<20)-wireBytes != 42228 {
		t.Fatalf("FD6 bound: chunks %d, frames %d, bytes %d", chunks, frames, wireBytes)
	}
	if 128*399+33 != 51105 || 128*404+33 != 51745 {
		t.Fatal("full truth chunk exceeds its registered frame answer")
	}
	if 5*32+2+128 != 290 || 2*(2*attempts+2) != 4968 || 7*2*20 != 280 {
		t.Fatal("fixed arena/lifecycle/observation bounds changed")
	}
}
