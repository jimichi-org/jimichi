package lab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func TestMarkStateCutoffAccounting(t *testing.T) {
	s := newMarkState(time.Now(), 2)
	origin, cutoff := time.Second, 10*time.Second
	s.calls[0][0] = &MarkCall{Invoked: durationPtr(2 * time.Second), Returned: durationPtr(3 * time.Second), Echo: durationPtr(11 * time.Second)}
	s.calls[0][1] = &MarkCall{Invoked: durationPtr(4 * time.Second), Returned: durationPtr(12 * time.Second)}
	s.calls[0][2] = &MarkCall{Invoked: durationPtr(5 * time.Second), Returned: durationPtr(6 * time.Second), Echo: durationPtr(7 * time.Second)}
	s.calls[0][markProbe] = &MarkCall{Invoked: durationPtr(8 * time.Second), Returned: durationPtr(9 * time.Second), Echo: durationPtr(9 * time.Second)}
	s.closures[0] = durationPtr(cutoff)
	s.closures[1] = durationPtr(9 * time.Second)
	f := s.snapshot(origin, cutoff)
	if f[0].CallsStarted != 3 || f[0].NilReturns != 2 || f[0].Pending != 1 || f[0].Echoes != 1 || f[0].NilWithoutEcho != 1 || f[0].Closure != nil || !*f[0].Responsive || *f[1].Open {
		t.Fatal(f)
	}
	if len(f[0].Latency) != 1 || f[0].Latency[0] != 2*time.Second {
		t.Fatal(f[0].Latency)
	}
}

func TestMarkEnvironmentErrorIdentity(t *testing.T) {
	for _, err := range []error{secmem.ErrNotLocked, secmem.ErrNotMapped, fmt.Errorf("allocation: %w", secmem.ErrNotLocked), &markError{class: "handshake", err: secmem.ErrNotMapped}} {
		if MarkErrorClass(err) != "environment" {
			t.Fatal(err)
		}
	}
	if MarkErrorClass(&markError{class: "setup", err: errors.New("circuit refused")}) != "setup" {
		t.Fatal("circuit refusal became fatal")
	}
}
func TestMarkLiveBothSuites(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("bounded Linux integration")
	}
	for _, suite := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		for _, active := range []bool{true, false} {
			t.Run(suite.String()+map[bool]string{true: "-active", false: "-sham"}[active], func(t *testing.T) {
				cfg := Config{Flows: 6, Hops: 3, Duration: time.Second, SendEvery: 200 * time.Millisecond, Mode: client.ConstantRate, Rate: 50 * time.Millisecond, Payload: 128, Suite: suite, Mark: &MarkConfig{Enabled: active, Flow: 2, Code: []int8{1, -1}, Slot: 100 * time.Millisecond, Offset: 20 * time.Millisecond}}
				run, err := executeMarked(cfg, markPlan{ctx: context.Background(), readiness: 5 * time.Second, probe: 900 * time.Millisecond})
				if err != nil {
					t.Fatalf("%v entry=%d exit=%d mark=%+v", err, len(run.Entry), len(run.Exit), run.Mark)
				}
				if run.Mark.SetupStatus != "established" || run.Mark.CaptureStatus != "complete" || *run.Mark.CaptureEnd-*run.Mark.CaptureStart != cfg.Duration || len(run.Exit) != 6 {
					t.Fatal(run.Mark)
				}
				if active && run.Mark.Counters.Realization == "none" {
					t.Fatal("no delayed frame")
				}
				if !active && run.Mark.Counters.WaitStarted != 0 {
					t.Fatal(run.Mark.Counters)
				}
				for _, f := range run.Mark.Flows {
					if f.Preflight.Echo == nil || f.Probe.Invoked == nil || f.Open == nil || f.Responsive == nil {
						t.Fatal(f)
					}
				}
				for _, group := range [][]*Trace{run.Entry, run.Exit, run.EntryBack, run.ExitBack} {
					for _, trace := range group {
						for _, at := range trace.Events() {
							if at < run.Origin || at >= *run.Mark.CaptureEnd {
								t.Fatal("unfiltered event", at)
							}
						}
					}
				}
			})
		}
	}
}
func TestMarkSetupFailureRetained(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("bounded Linux integration")
	}
	cfg := Config{Flows: 6, Hops: 3, Duration: time.Second, SendEvery: time.Millisecond, Suite: jcrypto.SuiteC25519, Mark: &MarkConfig{Flow: 0, Code: []int8{1, -1}, Slot: time.Millisecond}}
	run, err := executeMarked(cfg, markPlan{ctx: context.Background(), readiness: time.Nanosecond, probe: time.Second / 2})
	if err == nil || run == nil || run.Mark == nil || run.Mark.SetupStatus != "failed" || run.Mark.ErrorClass == "" {
		t.Fatal(run, err)
	}
}

func TestMarkAllClosedKeepsHorizonAndProbe(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("bounded Linux integration")
	}
	cfg := Config{Flows: 6, Hops: 3, Duration: 250 * time.Millisecond, SendEvery: time.Second, Suite: jcrypto.SuiteC25519, Mark: &MarkConfig{Flow: 0, Code: []int8{1, -1}, Slot: time.Millisecond}}
	run, err := executeMarked(cfg, markPlan{ctx: context.Background(), readiness: 5 * time.Second, probe: 100 * time.Millisecond, onOrigin: func(closeOwned func()) { closeOwned() }})
	if err != nil {
		t.Fatal(err)
	}
	if *run.Mark.CaptureEnd-run.Origin != cfg.Duration {
		t.Fatal("horizon shortened")
	}
	for _, f := range run.Mark.Flows {
		if f.Open == nil || *f.Open || f.Responsive == nil || *f.Responsive || f.Closure == nil || f.Probe.Invoked == nil || *f.Probe.Invoked < run.Origin+100*time.Millisecond {
			t.Fatal(f)
		}
	}
}

func TestMarkPreflightDeadlineInterruptsSend(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("bounded Linux integration")
	}
	cfg := Config{Flows: 6, Hops: 3, Duration: 9 * time.Second, SendEvery: time.Second, Suite: jcrypto.SuiteC25519, Mark: &MarkConfig{Enabled: true, Flow: 0, Code: []int8{1, -1}, Slot: time.Second}}
	start := time.Now()
	run, err := executeMarked(cfg, markPlan{ctx: context.Background(), readiness: 200 * time.Millisecond, probe: time.Second, beforePreflight: func(c *markConn) { c.arm(time.Now()) }})
	if err == nil || run.Mark.SetupStatus != "failed" || run.Mark.ErrorClass != "readiness" {
		t.Fatal(run, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("blocked preflight not interrupted")
	}
}

func TestMarkCancellationUnknownSurvival(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("bounded Linux integration")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{Flows: 6, Hops: 3, Duration: time.Second, SendEvery: time.Millisecond, Suite: jcrypto.SuiteC25519, Mark: &MarkConfig{Flow: 0, Code: []int8{1, -1}, Slot: time.Millisecond}}
	run, err := executeMarked(cfg, markPlan{ctx: ctx, readiness: 5 * time.Second, probe: time.Second / 2, onOrigin: func(func()) { cancel() }})
	if err == nil || run.Mark.CaptureStatus != "incomplete" || run.Mark.Cutoff == nil || *run.Mark.Cutoff != run.Origin+cfg.Duration {
		t.Fatal(run, err)
	}
	for _, f := range run.Mark.Flows {
		if f.Open != nil || f.Responsive != nil {
			t.Fatal("cancelled survival known", f)
		}
	}
}

func TestMarkProbeInvokedWhileOrdinarySendBlocked(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("bounded Linux integration")
	}
	var wrapper *markConn
	cfg := Config{Flows: 6, Hops: 3, Duration: 250 * time.Millisecond, SendEvery: time.Millisecond, Suite: jcrypto.SuiteC25519, Mark: &MarkConfig{Enabled: true, Flow: 0, Code: []int8{1, -1}, Slot: time.Millisecond}}
	plan := markPlan{ctx: context.Background(), readiness: 5 * time.Second, probe: 100 * time.Millisecond, beforePreflight: func(c *markConn) { wrapper = c }, onOrigin: func(func()) { wrapper.mu.Lock(); wrapper.cfg.Slot = time.Second; wrapper.mu.Unlock() }}
	run, err := executeMarked(cfg, plan)
	if err != nil {
		t.Fatal(err)
	}
	f := run.Mark.Flows[0]
	if f.Pending == 0 || f.Probe.Invoked == nil || !f.Probe.PendingAtCutoff || f.Probe.Returned == nil || *f.Probe.Returned < *run.Mark.CaptureEnd {
		t.Fatal(f)
	}
	if run.Mark.Counters.WaitAborted != 1 {
		t.Fatal(run.Mark.Counters)
	}
}

func TestMarkPartialNodeStartEnvironmentFailureCleansUp(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("bounded Linux integration")
	}
	var first *node
	calls := 0
	plan := defaultMarkPlan()
	plan.startNode = func(p jcrypto.CryptoProvider, period time.Duration, observed bool, dial func(context.Context, string, string) (net.Conn, error)) (*node, error) {
		calls++
		if calls == 2 {
			return nil, fmt.Errorf("locked allocation: %w", secmem.ErrNotLocked)
		}
		n, err := startNode(p, period, observed, dial)
		first = n
		return n, err
	}
	cfg := Config{Flows: 6, Hops: 3, Duration: time.Second, SendEvery: time.Second, Suite: jcrypto.SuiteC25519, Mark: &MarkConfig{Flow: 0, Code: []int8{1, -1}, Slot: time.Millisecond}}
	run, err := executeMarked(cfg, plan)
	if err == nil || !errors.Is(err, secmem.ErrNotLocked) || MarkErrorClass(err) != "environment" || run.Mark.ErrorClass != "environment" || calls != 2 || first == nil {
		t.Fatal(err, calls, run.Mark)
	}
	select {
	case <-first.done:
	default:
		t.Fatal("listener worker remains")
	}
	if first.priv.Bytes() != nil || first.relay.Serving() {
		t.Fatal("node resources remain")
	}
	if _, err := first.ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("listener remains", err)
	}
}

func TestMarkPacedPaddingAndCountersRemainObserved(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("bounded Linux integration")
	}
	cfg := Config{Flows: 6, Hops: 3, Duration: time.Second, SendEvery: 200 * time.Millisecond, Mode: client.ConstantRate, Rate: 50 * time.Millisecond, RelayPeriod: 50 * time.Millisecond, Suite: jcrypto.SuiteC25519, Mark: &MarkConfig{Enabled: true, Flow: 0, Code: []int8{1, -1}, Slot: 100 * time.Millisecond, Offset: 20 * time.Millisecond}}
	run, err := executeMarked(cfg, markPlan{ctx: context.Background(), readiness: 5 * time.Second, probe: 900 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if run.Config.RelayPeriod != cfg.RelayPeriod || run.RelayPadding == 0 || run.Mark.CounterAt < *run.Mark.CaptureEnd {
		t.Fatal("missing paced counters", run.RelayPadding, run.Mark.CounterAt)
	}
	for _, group := range [][]*Trace{run.Entry, run.EntryBack, run.Exit, run.ExitBack} {
		frames := 0
		for _, trace := range group {
			frames += trace.Len()
		}
		if frames == 0 {
			t.Fatal("missing paced link observations")
		}
	}
	for _, f := range run.Mark.Flows {
		if f.CounterAt < *run.Mark.CaptureEnd {
			t.Fatal("missing client snapshot", f)
		}
	}
}

func TestMarkNilSendReturnsRetainClientQueueDrops(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("bounded Linux integration")
	}
	cfg := Config{Flows: 6, Hops: 3, Duration: 300 * time.Millisecond, SendEvery: 200 * time.Millisecond, Mode: client.ConstantRate, Rate: 50 * time.Millisecond, Payload: 128, Suite: jcrypto.SuiteC25519, Mark: &MarkConfig{Flow: 0, Code: []int8{1, -1}, Slot: time.Millisecond}}
	plan := markPlan{ctx: context.Background(), readiness: 5 * time.Second, probe: 200 * time.Millisecond, workload: func(ctx context.Context, flow int, c *client.Client, state *markState) {
		if flow != 0 {
			return
		}
		for seq := uint64(0); seq < 1024 && ctx.Err() == nil; seq++ {
			state.send(flow, seq, c, cfg.Payload)
		}
	}}
	run, err := executeMarked(cfg, plan)
	if err != nil {
		t.Fatal(err)
	}
	f := run.Mark.Flows[0]
	if f.CallsStarted <= 256 || f.NilReturns != f.CallsStarted || f.Errors != 0 || f.Dropped == 0 || f.NilWithoutEcho == 0 || f.Echoes >= f.NilReturns {
		t.Fatal(f)
	}
	if run.Dropped != f.Dropped || f.CounterAt < *run.Mark.CaptureEnd {
		t.Fatal(run.Dropped, f)
	}
}
