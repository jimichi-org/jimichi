package lab

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/link"
)

type MarkCall struct {
	Invoked          *time.Duration `json:"invoked"`
	Returned         *time.Duration `json:"returned"`
	ErrorClass       string         `json:"error_class"`
	Echo             *time.Duration `json:"echo"`
	PendingAtCutoff  bool           `json:"pending_at_cutoff"`
	EchoBeforeCutoff bool           `json:"echo_before_cutoff"`
}

type MarkFlow struct {
	Preflight      MarkCall        `json:"preflight"`
	Probe          MarkCall        `json:"probe"`
	CallsStarted   int             `json:"calls_started_before_cutoff"`
	NilReturns     int             `json:"nil_returns_before_cutoff"`
	Errors         int             `json:"errors_before_cutoff"`
	Pending        int             `json:"pending_at_cutoff"`
	Echoes         int             `json:"matched_echoes_before_cutoff"`
	NilWithoutEcho int             `json:"nil_returns_without_echo"`
	Dropped        uint64          `json:"drop_counter"`
	CounterAt      time.Duration   `json:"counter_snapshot_time"`
	Closure        *time.Duration  `json:"closure"`
	Open           *bool           `json:"open_at_cutoff"`
	Responsive     *bool           `json:"responsive_survival"`
	Latency        []time.Duration `json:"latency_samples"`
}

type MarkResult struct {
	SetupStatus       string         `json:"setup_status"`
	CaptureStatus     string         `json:"capture_status"`
	ErrorClass        string         `json:"normalized_error_class"`
	CaptureStart      *time.Duration `json:"capture_start"`
	CaptureEnd        *time.Duration `json:"capture_end"`
	Cutoff            *time.Duration `json:"planned_cutoff"`
	Counters          MarkCounters   `json:"realization_counters"`
	Flows             []MarkFlow     `json:"flows"`
	FirstClosure      *time.Duration `json:"first_closure"`
	CounterAt         time.Duration  `json:"diagnostic_counter_snapshot_time"`
	Setup             []MarkSetup    `json:"setup_timings"`
	SetupComplete     *time.Duration `json:"setup_complete"`
	PreflightStarted  *time.Duration `json:"preflight_started"`
	PreflightComplete *time.Duration `json:"preflight_complete"`
	ReadinessDeadline time.Duration  `json:"readiness_deadline"`
}

type MarkSetup struct {
	Started      *time.Duration `json:"started"`
	ClientReady  *time.Duration `json:"client_ready"`
	ExitLinkSeen *time.Duration `json:"exit_link_seen"`
	ExitFrame    *time.Duration `json:"exit_setup_frame"`
}

type markError struct {
	class string
	err   error
}

func (e *markError) Error() string { return "mark: " + e.class }
func (e *markError) Unwrap() error { return e.err }
func MarkErrorClass(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, secmem.ErrNotLocked) || errors.Is(err, secmem.ErrNotMapped) {
		return "environment"
	}
	var e *markError
	if errors.As(err, &e) {
		return e.class
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, net.ErrClosed) {
		return "closure"
	}
	if errors.Is(err, context.Canceled) {
		return "cancellation"
	}
	return "closure"
}

type markPlan struct {
	ctx              context.Context
	readiness, probe time.Duration
	onOrigin         func(func())
	beforePreflight  func(*markConn)
	startNode        func(jcrypto.CryptoProvider, time.Duration, bool, func(context.Context, string, string) (net.Conn, error)) (*node, error)
	workload         func(context.Context, int, *client.Client, *markState)
}

func defaultMarkPlan() markPlan {
	return markPlan{ctx: context.Background(), readiness: 5 * time.Second, probe: 12200 * time.Millisecond}
}
func durationPtr(d time.Duration) *time.Duration { return &d }

func executeMarked(cfg Config, plan markPlan) (run *Run, err error) {
	run = &Run{Config: cfg, Mark: &MarkResult{SetupStatus: "failed", CaptureStatus: "not_started"}}
	var state *markState
	var wrapper *markConn
	var start time.Time
	var failureAt time.Duration
	fail := func(class string, e error) (*Run, error) {
		if MarkErrorClass(e) == "environment" {
			class = "environment"
		}
		run.Mark.ErrorClass = class
		if !start.IsZero() {
			failureAt = time.Since(start)
		}
		return run, &markError{class, e}
	}
	cfg, err = validateMark(cfg)
	if err != nil {
		return fail("validation", err)
	}
	run.Config = cfg
	run.Mark.Flows = make([]MarkFlow, cfg.Flows)
	run.Mark.Setup = make([]MarkSetup, cfg.Flows)
	run.Mark.ReadinessDeadline = plan.readiness
	if plan.ctx == nil {
		plan.ctx = context.Background()
	}
	provider, err := suite.New(cfg.Suite)
	if err != nil {
		return fail("environment", err)
	}
	frame, err := link.FrameSize(provider)
	if err != nil {
		return fail("environment", err)
	}
	handshake, err := link.InitiatorHandshakeSize(provider)
	if err != nil {
		return fail("environment", err)
	}
	answer, err := link.ResponderHandshakeSize(provider)
	if err != nil {
		return fail("environment", err)
	}
	start = time.Now()
	tap := func(conn net.Conn, out, in *Trace) net.Conn {
		return &tappedConn{Conn: conn, out: &counter{trace: out, skip: handshake, frame: frame}, in: &counter{trace: in, skip: answer, frame: frame}}
	}
	var ownedMu sync.Mutex
	var owned []net.Conn
	closeOwned := func() {
		ownedMu.Lock()
		defer ownedMu.Unlock()
		for _, c := range owned {
			_ = c.Close()
		}
	}
	var nodes []*node
	var clients []*client.Client
	var collectors, senders sync.WaitGroup
	var watchers sync.WaitGroup
	finished := make(chan struct{})
	defer func() { close(finished); watchers.Wait() }()
	defer func() {
		closeOwned()
		for _, c := range clients {
			_ = c.Close()
		}
		senders.Wait()
		collectors.Wait()
		for _, n := range nodes {
			stopNode(n)
		}
		if run.Mark.SetupStatus != "established" {
			if state != nil {
				run.Mark.Flows = state.snapshot(0, failureAt)
				for i := range run.Mark.Flows {
					run.Mark.Flows[i].Open = nil
					run.Mark.Flows[i].Responsive = nil
				}
			}
			if wrapper != nil {
				run.Mark.Counters = wrapper.snapshot()
			}
		}
	}()
	watchers.Add(1)
	go func() {
		defer watchers.Done()
		select {
		case <-plan.ctx.Done():
			closeOwned()
		case <-finished:
		}
	}()
	var exitMu sync.Mutex
	exitDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		c, e := d.DialContext(ctx, network, addr)
		if e != nil {
			return nil, e
		}
		t, b := NewTrace(start), NewTrace(start)
		exitMu.Lock()
		run.Exit = append(run.Exit, t)
		run.ExitBack = append(run.ExitBack, b)
		exitMu.Unlock()
		return tap(c, t, b), nil
	}
	chain := make([]client.Node, cfg.Hops)
	startRelay := startNode
	if plan.startNode != nil {
		startRelay = plan.startNode
	}
	for i := cfg.Hops - 1; i >= 0; i-- {
		n, e := startRelay(provider, cfg.RelayPeriod, i == cfg.Hops-2, exitDial)
		if e != nil {
			return fail("environment", e)
		}
		nodes = append(nodes, n)
		chain[i] = client.Node{Addr: n.addr, StaticPub: n.pub}
	}
	setupCtx, setupCancel := context.WithCancel(plan.ctx)
	defer setupCancel()
	setupDone := make(chan struct{})
	var setupOnce sync.Once
	stopSetup := func() { setupOnce.Do(func() { close(setupDone) }) }
	watchers.Add(1)
	go func() {
		defer watchers.Done()
		select {
		case <-setupCtx.Done():
			select {
			case <-setupDone:
				return
			default:
				closeOwned()
			}
		case <-setupDone:
		}
	}()
	defer stopSetup()
	phases := rand.New(rand.NewSource(Derive(cfg.Seed, streamPhases)))
	schedule := max(cfg.Rate, cfg.CoverEvery)
	for i := 0; i < cfg.Flows; i++ {
		run.Mark.Setup[i].Started = durationPtr(time.Since(start))
		flowCtx, flowCancel := context.WithTimeout(setupCtx, plan.readiness)
		if schedule > 0 && !markSleep(flowCtx, time.Duration(phases.Int63n(int64(schedule)))) {
			flowCancel()
			return fail("readiness", flowCtx.Err())
		}
		a, b := NewTrace(start), NewTrace(start)
		run.Entry = append(run.Entry, a)
		run.EntryBack = append(run.EntryBack, b)
		dialFailed := false
		c, e := client.Dial(client.Config{Provider: provider, Chain: chain, Mode: cfg.Mode, Rate: cfg.Rate, CoverRate: cfg.CoverEvery, Jitter: cfg.Jitter, DialTimeout: plan.readiness, HandshakeTimeout: plan.readiness, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			raw, e := d.DialContext(flowCtx, network, addr)
			if e != nil {
				dialFailed = true
				return nil, e
			}
			var conn net.Conn = tap(raw, a, b)
			if i == cfg.Mark.Flow {
				wrapper = newMarkConn(conn, *cfg.Mark, handshake, frame, realMarkClock{})
				conn = wrapper
			}
			ownedMu.Lock()
			if setupCtx.Err() != nil {
				ownedMu.Unlock()
				_ = conn.Close()
				return nil, setupCtx.Err()
			}
			owned = append(owned, conn)
			ownedMu.Unlock()
			return conn, nil
		}})
		if e != nil {
			flowCancel()
			if dialFailed {
				return fail("dial", e)
			}
			return fail("handshake", e)
		}
		clients = append(clients, c)
		run.Mark.Setup[i].ClientReady = durationPtr(time.Since(start))
		if e := markWait(flowCtx, func() bool { exitMu.Lock(); defer exitMu.Unlock(); return len(run.Exit) == i+1 }); e != nil {
			flowCancel()
			return fail("readiness", e)
		}
		flowCancel()
		run.Mark.Setup[i].ExitLinkSeen = durationPtr(time.Since(start))
	}
	finalSetupCtx, finalSetupCancel := context.WithTimeout(setupCtx, plan.readiness)
	defer finalSetupCancel()
	if e := markWait(finalSetupCtx, func() bool {
		exitMu.Lock()
		defer exitMu.Unlock()
		for _, t := range run.Exit {
			if t.Len() == 0 {
				return false
			}
		}
		return len(run.Exit) == cfg.Flows
	}); e != nil {
		return fail("readiness", e)
	}
	stopSetup()
	setupCancel()
	run.Mark.SetupComplete = durationPtr(time.Since(start))
	exitMu.Lock()
	for i, t := range run.Exit {
		events := t.Events()
		if len(events) > 0 {
			run.Mark.Setup[i].ExitFrame = durationPtr(events[0])
		}
	}
	exitMu.Unlock()
	state = newMarkState(start, cfg.Flows)
	if plan.beforePreflight != nil {
		plan.beforePreflight(wrapper)
	}
	for i, c := range clients {
		collectors.Add(1)
		go func(flow int, c *client.Client) { defer collectors.Done(); state.collect(flow, c.Replies()) }(i, c)
	}
	preCtx, preCancel := context.WithTimeout(plan.ctx, plan.readiness)
	run.Mark.PreflightStarted = durationPtr(time.Since(start))
	defer preCancel()
	preDone := make(chan struct{})
	watchers.Add(1)
	go func() {
		defer watchers.Done()
		select {
		case <-preCtx.Done():
			select {
			case <-preDone:
				return
			default:
				closeOwned()
			}
		case <-preDone:
		}
	}()
	for i, c := range clients {
		senders.Add(1)
		go func(flow int, c *client.Client) {
			defer senders.Done()
			state.send(flow, markPreflight, c, cfg.Payload)
		}(i, c)
	}
	if e := markWait(preCtx, func() bool { return state.preflightReady() }); e != nil {
		close(preDone)
		return fail("readiness", e)
	}
	close(preDone)
	run.Mark.PreflightComplete = durationPtr(time.Since(start))
	origin := time.Since(start)
	state.mu.Lock()
	last := state.lastEvent
	state.mu.Unlock()
	for origin <= last {
		if !markSleep(plan.ctx, time.Millisecond) {
			return fail("cancellation", plan.ctx.Err())
		}
		origin = time.Since(start)
	}
	run.Origin = origin
	if origin > time.Duration(math.MaxInt64)-cfg.Duration {
		return fail("validation", errors.New("mark: capture duration overflow"))
	}
	cutoff := origin + cfg.Duration
	run.Mark.SetupStatus = "established"
	run.Mark.CaptureStatus = "complete"
	run.Mark.CaptureStart = durationPtr(origin)
	run.Mark.CaptureEnd = durationPtr(cutoff)
	run.Mark.Cutoff = durationPtr(cutoff)
	wrapper.arm(start.Add(origin))
	if plan.onOrigin != nil {
		plan.onOrigin(closeOwned)
	}
	workCtx, workCancel := context.WithDeadline(plan.ctx, start.Add(cutoff))
	defer workCancel()
	for i, c := range clients {
		senders.Add(1)
		go func(flow int, c *client.Client) {
			defer senders.Done()
			rng := rand.New(rand.NewSource(Derive(cfg.Seed, streamGaps, uint64(flow))))
			if plan.workload != nil {
				plan.workload(workCtx, flow, c, state)
				return
			}
			for seq := uint64(0); seq < markProbe; seq++ {
				gap := time.Duration(rng.ExpFloat64() * float64(cfg.SendEvery))
				if !markSleep(workCtx, gap) {
					return
				}
				if !time.Now().Before(start.Add(cutoff)) {
					return
				}
				if !state.send(flow, seq, c, cfg.Payload) {
					return
				}
			}
		}(i, c)
		senders.Add(1)
		go func(flow int, c *client.Client) {
			defer senders.Done()
			if markSleep(workCtx, time.Until(start.Add(origin+plan.probe))) {
				state.send(flow, markProbe, c, cfg.Payload)
			}
		}(i, c)
	}
	<-workCtx.Done()
	if plan.ctx.Err() != nil {
		run.Mark.CaptureStatus = "incomplete"
		run.Mark.ErrorClass = "cancellation"
		cutoff = min(cutoff, time.Since(start))
		run.Mark.CaptureEnd = durationPtr(cutoff)
	}
	closeOwned()
	for _, c := range clients {
		_ = c.Close()
	}
	senders.Wait()
	collectors.Wait()
	run.Mark.Flows = state.snapshot(origin, cutoff)
	if run.Mark.CaptureStatus != "complete" {
		for i := range run.Mark.Flows {
			run.Mark.Flows[i].Open = nil
			run.Mark.Flows[i].Responsive = nil
		}
	}
	run.Mark.Counters = wrapper.snapshot()
	for i, c := range clients {
		f := &run.Mark.Flows[i]
		f.Dropped = c.Dropped()
		f.CounterAt = time.Since(start)
		run.Dropped += f.Dropped
		run.Sent += f.NilReturns
		run.Unanswered += f.CallsStarted - f.Echoes
		run.Latency = append(run.Latency, f.Latency...)
		run.Closures = append(run.Closures, Closure{Closed: f.Closure != nil})
		if f.Closure != nil {
			run.Closures[i].At = *f.Closure
			if run.Mark.FirstClosure == nil || *f.Closure < *run.Mark.FirstClosure {
				run.Mark.FirstClosure = durationPtr(*f.Closure)
			}
		}
		if c.Broken() {
			run.BrokenFlows++
		}
	}
	for _, n := range nodes {
		n.relay.Close()
		_ = n.ln.Close()
		run.addRelay(n.relay.Stats().Snapshot())
	}
	run.Mark.CounterAt = time.Since(start)
	exitMu.Lock()
	run.Exit = append([]*Trace(nil), run.Exit...)
	run.ExitBack = append([]*Trace(nil), run.ExitBack...)
	exitMu.Unlock()
	for _, group := range [][]*Trace{run.Entry, run.EntryBack, run.Exit, run.ExitBack} {
		for _, t := range group {
			t.mu.Lock()
			events := t.events[:0]
			for _, e := range t.events {
				if e >= origin && e < cutoff {
					events = append(events, e)
				}
			}
			t.events = events
			t.mu.Unlock()
		}
	}
	for _, t := range run.Entry {
		run.Cells += t.Len()
	}
	if run.Mark.ErrorClass != "" {
		return fail(run.Mark.ErrorClass, plan.ctx.Err())
	}
	return run, nil
}

func markSleep(ctx context.Context, d time.Duration) bool {
	if d < 0 {
		d = 0
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}
func markWait(ctx context.Context, ready func() bool) error {
	for !ready() {
		if !markSleep(ctx, time.Millisecond) {
			return ctx.Err()
		}
	}
	return nil
}

const (
	markPreflight uint64 = math.MaxUint64
	markProbe     uint64 = math.MaxUint64 - 1
)

type markState struct {
	mu        sync.Mutex
	start     time.Time
	calls     []map[uint64]*MarkCall
	closures  []*time.Duration
	lastEvent time.Duration
}

func newMarkState(start time.Time, n int) *markState {
	s := &markState{start: start, calls: make([]map[uint64]*MarkCall, n), closures: make([]*time.Duration, n)}
	for i := range s.calls {
		s.calls[i] = make(map[uint64]*MarkCall)
	}
	return s
}
func (s *markState) send(flow int, seq uint64, c *client.Client, size int) bool {
	b := make([]byte, max(size, flowField+seqField))
	binary.BigEndian.PutUint16(b, uint16(flow))
	binary.BigEndian.PutUint64(b[flowField:], seq)
	at := time.Since(s.start)
	record := &MarkCall{Invoked: durationPtr(at)}
	s.mu.Lock()
	s.calls[flow][seq] = record
	s.mu.Unlock()
	err := c.Send(b)
	returned := time.Since(s.start)
	s.mu.Lock()
	record.Returned = durationPtr(returned)
	record.ErrorClass = MarkErrorClass(err)
	s.mu.Unlock()
	return err == nil
}
func (s *markState) collect(flow int, replies <-chan []byte) {
	for b := range replies {
		at := time.Since(s.start)
		if len(b) < flowField+seqField {
			continue
		}
		seq := binary.BigEndian.Uint64(b[flowField:])
		s.mu.Lock()
		if c := s.calls[flow][seq]; c != nil && c.Echo == nil {
			c.Echo = durationPtr(at)
		}
		s.lastEvent = max(s.lastEvent, at)
		s.mu.Unlock()
	}
	at := time.Since(s.start)
	s.mu.Lock()
	s.closures[flow] = durationPtr(at)
	s.lastEvent = max(s.lastEvent, at)
	s.mu.Unlock()
}
func (s *markState) preflightReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.calls {
		c := m[markPreflight]
		if c == nil || c.Echo == nil || c.Returned == nil || c.ErrorClass != "" {
			return false
		}
	}
	return true
}
func (s *markState) snapshot(origin, cutoff time.Duration) []MarkFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]MarkFlow, len(s.calls))
	for i, m := range s.calls {
		f := &out[i]
		closed := s.closures[i]
		if closed != nil && *closed < cutoff {
			f.Closure = durationPtr(*closed)
		}
		open := f.Closure == nil
		f.Open = &open
		for seq, c := range m {
			v := *c
			v.PendingAtCutoff = v.Invoked != nil && *v.Invoked < cutoff && (v.Returned == nil || *v.Returned >= cutoff)
			v.EchoBeforeCutoff = v.Echo != nil && *v.Echo < cutoff
			if v.Echo != nil && *v.Echo >= cutoff {
				v.Echo = nil
			}
			switch seq {
			case markPreflight:
				f.Preflight = v
			case markProbe:
				f.Probe = v
			default:
				if v.Invoked == nil || *v.Invoked < origin || *v.Invoked >= cutoff {
					continue
				}
				f.CallsStarted++
				if v.PendingAtCutoff {
					f.Pending++
				}
				if v.Returned != nil && *v.Returned < cutoff {
					if v.ErrorClass == "" {
						f.NilReturns++
						if !v.EchoBeforeCutoff {
							f.NilWithoutEcho++
						}
					} else {
						f.Errors++
					}
				}
				if v.EchoBeforeCutoff {
					f.Echoes++
					f.Latency = append(f.Latency, *v.Echo-*v.Invoked)
				}
			}
		}
		responsive := open && f.Probe.EchoBeforeCutoff
		f.Responsive = &responsive
	}
	return out
}
