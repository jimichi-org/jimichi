package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"slices"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/lab"
	"github.com/jimichi-org/jimichi/lab/metrics"
	"github.com/jimichi-org/jimichi/lab/perf"
)

// one row per run of the perf set; the part decides which of the embedded
// groups it carries, and an undefined value is null, never zero
type perfRow struct {
	Part           string   `json:"part"`
	Warmup         bool     `json:"warmup"`
	Repeat         int      `json:"repeat"`
	OrderIndex     int      `json:"order_index"`
	BaseSeed       int64    `json:"base_seed"`
	Seed           int64    `json:"seed"`
	Suite          string   `json:"suite"`
	KeyMemLevel    string   `json:"keymem_level"`
	KeyMemPolicy   string   `json:"keymem_policy"`
	LocalRelays    int      `json:"local_relays"`
	KeysLocked     *bool    `json:"keys_locked"`
	MemlockBudget  *uint64  `json:"memlock_budget"`
	Rev            string   `json:"rev"`
	GOOS           string   `json:"goos"`
	GOARCH         string   `json:"goarch"`
	GoVersion      string   `json:"go_version"`
	NumCPU         int      `json:"num_cpu"`
	GOMAXPROCS     int      `json:"gomaxprocs"`
	CPUModel       string   `json:"cpu_model"`
	Kernel         string   `json:"kernel"`
	Governors      []string `json:"governors"`
	Virtualized    *bool    `json:"virtualized"`
	NoiseScope     *string  `json:"noise_scope"`
	LoadBefore     string   `json:"loadavg_before"`
	LoadAfter      string   `json:"loadavg_after"`
	ForeignCores   *float64 `json:"foreign_cores"`
	HostUserS      *float64 `json:"host_user_s"`
	HostSystemS    *float64 `json:"host_system_s"`
	HostIrqS       *float64 `json:"host_irq_s"`
	HostSoftirqS   *float64 `json:"host_softirq_s"`
	HostStealS     *float64 `json:"host_steal_s"`
	NoiseChecked   bool     `json:"noise_checked"`
	Noisy          bool     `json:"noisy"`
	SeriesEligible bool     `json:"series_eligible"`

	Messages            int    `json:"messages"`
	Unanswered          int    `json:"unanswered"`
	RelayDroppedCells   uint64 `json:"relay_dropped_cells"`
	RelayBrokenCircuits uint64 `json:"relay_broken_circuits"`
	BrokenFlows         int    `json:"broken_flows"`
	FlowClosed          []bool `json:"flow_closed"`
	RelayTimedOut       uint64 `json:"relay_timed_out"`
	RelayExpired        uint64 `json:"relay_expired"`
	RelayRefused        uint64 `json:"relay_refused"`

	Hops         *int `json:"hops,omitempty"`
	Flows        *int `json:"flows,omitempty"`
	Inflight     *int `json:"inflight,omitempty"`
	PayloadBytes int  `json:"payload_bytes"`

	*perfLatency
	*perfChain
	*perfNode
	*perfGoodput
}

type perfLatency struct {
	SendMeanGap    string   `json:"send_mean_gap"`
	Duration       string   `json:"duration"`
	LatencySamples int      `json:"latency_samples"`
	P50            *float64 `json:"latency_p50_us"`
	P95            *float64 `json:"latency_p95_us"`
	P99            *float64 `json:"latency_p99_us"`
}

type perfChain struct {
	WarmupS     float64  `json:"warmup_s"`
	WindowS     *float64 `json:"window_s"`
	Echoes      int      `json:"echoes_in_window"`
	Throughput  *float64 `json:"throughput_msgs_per_s"`
	ProcessCPUS *float64 `json:"process_cpu_s"`
	ProcessUtil *float64 `json:"process_utilisation"`
}

type perfNode struct {
	Cores          int      `json:"cores"`
	PerCore        int      `json:"circuits_per_core"`
	Circuits       int      `json:"circuits"`
	NodeCPUs       []int    `json:"node_cpus"`
	NodeSiblings   []int    `json:"node_siblings"`
	LoadCPUs       []int    `json:"load_cpus"`
	TopologyKnown  bool     `json:"topology_known"`
	L3Group        string   `json:"l3_group"`
	AffinityOK     bool     `json:"affinity_ok"`
	NodeLocked     bool     `json:"node_locked"`
	NodeDumpable   *int     `json:"node_dumpable"`
	NodeGOMAXPROCS int      `json:"node_gomaxprocs"`
	NodeWindowS    *float64 `json:"node_window_s"`
	SnapSkewUs     *float64 `json:"snap_skew_us"`
	NodeDelivered  uint64   `json:"node_delivered"`
	NodeRate       *float64 `json:"node_cells_per_s"`
	NodeCPUS       *float64 `json:"node_cpu_s"`
	NodeUtil       *float64 `json:"node_utilisation"`
	NodeBusyUtil   *float64 `json:"node_busy_utilisation"`
	ParentUtil     *float64 `json:"parent_utilisation"`
	CorePerCell    *float64 `json:"node_core_ns_per_cell"`
	Step           int      `json:"step"`
	Bound          string   `json:"bound"`
}

type perfGoodput struct {
	Mean *float64 `json:"goodput_mean_bps"`
	Min  *float64 `json:"goodput_min_bps"`
}

func intp(v int) *int { return &v }

// a run whose circuit closed, or where a relay limit acted, lost something the
// configuration did not; a noisy run shared its CPUs, and a series run whose
// host load was never read may have; a warmup run is only a warmup; a node run
// off its CPUs measured another machine
func (r perfRow) broken() bool {
	return r.RelayBrokenCircuits > 0 || r.BrokenFlows > 0 || slices.Contains(r.FlowClosed, true)
}

func (r perfRow) limited() bool {
	return r.RelayTimedOut > 0 || r.RelayExpired > 0 || r.RelayRefused > 0
}

func (r perfRow) unpinned() bool { return r.perfNode != nil && !r.AffinityOK }

func (r perfRow) unchecked() bool { return r.SeriesEligible && !r.NoiseChecked }

func (r perfRow) clean() bool {
	return !r.Warmup && !r.broken() && !r.limited() && !r.Noisy && !r.unchecked() && !r.unpinned()
}

type perfEnv struct {
	CPUModel       string   `json:"cpu_model"`
	Kernel         string   `json:"kernel"`
	NumCPU         int      `json:"num_cpu"`
	AllowedCPUs    []int    `json:"allowed_cpus"`
	NodeCPUs       []int    `json:"node_cpus"`
	NodeSiblings   []int    `json:"node_siblings"`
	LoadCPUs       []int    `json:"load_cpus"`
	TopologyKnown  bool     `json:"topology_known"`
	Virtualized    *bool    `json:"virtualized"`
	NoiseScope     *string  `json:"noise_scope"`
	Governors      []string `json:"governors"`
	GoVersion      string   `json:"go_version"`
	MemlockBudget  *uint64  `json:"memlock_budget"`
	GOOS           string   `json:"goos"`
	SeriesEligible bool     `json:"series_eligible"`
}

// a recorded series runs on linux alone: elsewhere there is neither mlock nor
// core affinity, and a run there is a smoke run
func seriesEligible(goos string) bool { return goos == "linux" }

func perfEnvironment(p perfPlan) perfEnv {
	e := perfEnv{CPUModel: cpuModel(), Kernel: kernelRelease(), NumCPU: runtime.NumCPU(), AllowedCPUs: perf.Allowed(),
		NodeCPUs: p.topo.Node, NodeSiblings: p.topo.Siblings, LoadCPUs: p.topo.Load, TopologyKnown: p.topo.Known,
		Governors: governors(), GoVersion: runtime.Version(), GOOS: runtime.GOOS, SeriesEligible: seriesEligible(runtime.GOOS)}
	if v, ok := perf.Virtualized(); ok {
		e.Virtualized = &v
		scope := "host"
		if v {
			scope = "guest"
		}
		e.NoiseScope = &scope
	}
	if b, err := secmem.MemlockBudget(); err == nil {
		e.MemlockBudget = &b
	}
	return e
}

// what one reading around the window holds: the parent's processor time and
// the CPU columns of the run are read just before and after the child's
// snapshot, and the middle of the two goes into the figures
type windowSnap struct {
	at      time.Time
	child   perf.Snapshot
	parent  time.Duration
	node    perf.CPUTimes
	scope   perf.CPUTimes
	hostOK  bool
	skew    time.Duration
	childOK bool
}

func takeSnap(child *perf.Child, nodeCPUs, scope []int) (windowSnap, error) {
	p0, _ := perf.ProcessCPU()
	n0, okN0 := perf.HostTimes(nodeCPUs)
	s0, okS0 := perf.HostTimes(scope)
	before := time.Now()
	var w windowSnap
	if child != nil {
		s, err := child.Snap()
		if err != nil {
			return w, err
		}
		w.child, w.childOK = s, true
	}
	after := time.Now()
	p1, _ := perf.ProcessCPU()
	n1, okN1 := perf.HostTimes(nodeCPUs)
	s1, okS1 := perf.HostTimes(scope)
	w.at = before.Add(after.Sub(before) / 2)
	w.parent = p0 + (p1-p0)/2
	w.node, w.scope = n0.Mid(n1), s0.Mid(s1)
	w.hostOK = okS0 && okS1 && (len(nodeCPUs) == 0 || okN0 && okN1)
	w.skew = after.Sub(before)
	return w, nil
}

// the two readings of a run, taken by their own goroutine: the first a warmup
// after the window opens, the second when the flows stop. The window callback
// only signals
type probe struct {
	opened, closed, quit chan struct{}
	done                 chan probeResult
}

type probeResult struct {
	first, last windowSnap
	err         error
}

func startProbe(warmup time.Duration, take func() (windowSnap, error)) *probe {
	p := &probe{opened: make(chan struct{}, 1), closed: make(chan struct{}, 1), quit: make(chan struct{}), done: make(chan probeResult, 1)}
	go func() {
		var res probeResult
		defer func() { p.done <- res }()
		select {
		case <-p.opened:
		case <-p.quit:
			res.err = errors.New("the window never opened")
			return
		}
		if warmup > 0 {
			t := time.NewTimer(warmup)
			select {
			case <-t.C:
			case <-p.closed:
				t.Stop()
				res.err = errors.New("the window closed within the warmup")
				return
			case <-p.quit:
				t.Stop()
				res.err = errors.New("the run ended within the warmup")
				return
			}
		}
		if res.first, res.err = take(); res.err != nil {
			return
		}
		select {
		case <-p.closed:
		case <-p.quit:
			res.err = errors.New("the run ended before its window closed")
			return
		}
		res.last, res.err = take()
	}()
	return p
}

func (p *probe) onWindow(open bool) {
	ch := p.closed
	if open {
		ch = p.opened
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (p *probe) wait() probeResult {
	close(p.quit)
	return <-p.done
}

func seconds(d time.Duration) *float64 { return opt(d.Seconds()) }

func runPerfCell(p perfPlan, env perfEnv, c perfCell, r int) (perfRow, error) {
	seed := lab.Derive(p.seed, uint64(r))
	row := perfRow{Part: c.part, Repeat: r, BaseSeed: p.seed, Seed: seed, Suite: c.suite.String(), KeyMemLevel: c.keymem,
		Rev: p.rev, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GoVersion: runtime.Version(), NumCPU: runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0), CPUModel: env.CPUModel, Kernel: env.Kernel, Governors: env.Governors,
		Virtualized: env.Virtualized, NoiseScope: env.NoiseScope, MemlockBudget: env.MemlockBudget, SeriesEligible: env.SeriesEligible}
	var keymem *secmem.Policy
	row.KeyMemPolicy = secmem.CurrentPolicy().String()
	if c.keymem != "heap" {
		pol, err := perf.KeyMemPolicy(c.keymem)
		if err != nil {
			return row, err
		}
		keymem, row.KeyMemPolicy = &pol, pol.String()
	}
	cfg := lab.Config{Hops: c.hops, Suite: c.suite, Seed: seed, Duration: p.duration}
	scope := env.AllowedCPUs
	var nodeCPUs []int
	var child *perf.Child
	warmup := p.warmup
	switch c.part {
	case "latency":
		cfg.Flows, cfg.SendEvery, cfg.KeyMem = p.flows, p.send, keymem
		warmup = 0
	case "chain":
		cfg.Flows, cfg.Window, cfg.FullPayload, cfg.KeyMem = c.flows, p.inflight, true, keymem
	case "node":
		nodeCPUs = p.topo.Node[:c.cores]
		scope = slices.Concat(p.topo.Node, p.topo.Siblings, p.topo.Load)
		restore, err := pinParent(p.topo.Load)
		if err != nil {
			return row, err
		}
		defer restore(p.allowed)
		row.GOMAXPROCS = runtime.GOMAXPROCS(0)
		ch, err := perf.Spawn(context.Background(), perf.ChildConfig{Suite: c.suite, KeyMem: c.keymem, CPUs: nodeCPUs})
		if err != nil {
			return row, err
		}
		child = ch
		defer child.Kill()
		exit := child.Node()
		// the generator never locks, so the levels of the node meet the same
		// load and the load does not depend on RLIMIT_MEMLOCK
		nolock, _ := perf.KeyMemPolicy("nolock")
		cfg.Flows, cfg.Window, cfg.FullPayload, cfg.Exit, cfg.KeyMem = c.circuits*c.cores, p.inflight, true, &exit, &nolock
	}
	pr := startProbe(warmup, func() (windowSnap, error) { return takeSnap(child, nodeCPUs, scope) })
	cfg.OnWindow = pr.onWindow

	row.LoadBefore = loadavg()
	run, err := lab.Execute(cfg)
	res := pr.wait()
	row.LoadAfter = loadavg()
	if err != nil {
		return row, err
	}
	if res.err != nil {
		return row, res.err
	}
	if len(run.Latency) == 0 {
		return row, errors.New("no echo came back")
	}
	row.Messages, row.Unanswered, row.BrokenFlows = run.Sent, run.Unanswered, run.BrokenFlows
	row.RelayDroppedCells, row.RelayBrokenCircuits = run.RelayDropped, run.RelayBroken
	row.RelayTimedOut, row.RelayExpired, row.RelayRefused = run.RelayTimedOut, run.RelayExpired, run.RelayRefused
	row.FlowClosed = make([]bool, len(run.Closures))
	for i, cl := range run.Closures {
		row.FlowClosed[i] = cl.Closed
	}
	row.LocalRelays, row.PayloadBytes = run.LocalRelays, run.Payload
	if run.LocalRelays > 0 {
		row.KeysLocked = &run.KeysLocked
	}

	first, last := res.first, res.last
	wall := last.at.Sub(first.at)
	own := last.parent - first.parent
	if child != nil {
		own += time.Duration(last.child.CPUNs - first.child.CPUNs)
	}
	if first.hostOK && last.hostOK {
		d := last.scope.Sub(first.scope)
		row.NoiseChecked = true
		row.HostUserS, row.HostSystemS = seconds(d.User+d.Nice), seconds(d.System)
		row.HostIrqS, row.HostSoftirqS, row.HostStealS = seconds(d.Irq), seconds(d.Softirq), seconds(d.Steal)
		fc := metrics.ForeignCores(d.Busy(), own, wall)
		row.ForeignCores = opt(fc)
		row.Noisy = fc > p.foreign
	}

	from, to := run.Origin+warmup, run.Origin+p.duration
	window := to - from
	switch c.part {
	case "latency":
		row.Hops, row.Flows = intp(c.hops), intp(p.flows)
		l := &perfLatency{SendMeanGap: p.send.String(), Duration: p.duration.String(), LatencySamples: len(run.Latency)}
		for q, dst := range map[float64]**float64{0.5: &l.P50, 0.95: &l.P95, 0.99: &l.P99} {
			if v, ok := metrics.TailPercentile(run.Latency, q); ok {
				*dst = opt(float64(v) / float64(time.Microsecond))
			}
		}
		row.perfLatency = l
	case "chain":
		row.Hops, row.Flows, row.Inflight = intp(3), intp(c.flows), intp(p.inflight)
		counts := metrics.CountsWithin(run.Completed, run.EchoFlow, c.flows, from, to)
		echoes := 0
		for _, n := range counts {
			echoes += n
		}
		ch := &perfChain{WarmupS: warmup.Seconds(), WindowS: seconds(window), Echoes: echoes,
			Throughput: opt(metrics.RateWithin(run.Completed, from, to))}
		if _, ok := perf.ProcessCPU(); ok {
			ch.ProcessCPUS = seconds(own)
			ch.ProcessUtil = opt(metrics.Utilisation(own, wall, runtime.GOMAXPROCS(0)))
		}
		row.perfChain = ch
		mean, low := metrics.Goodput(counts, run.Payload, window)
		row.perfGoodput = &perfGoodput{Mean: opt(mean), Min: opt(low)}
	case "node":
		row.Inflight = intp(p.inflight)
		final, err := child.Close()
		if err != nil {
			return row, fmt.Errorf("%w; child stderr: %s", err, child.Stderr())
		}
		k := final.Counters
		row.RelayDroppedCells, row.RelayBrokenCircuits = k.Dropped, k.Broken
		row.RelayTimedOut, row.RelayExpired = k.TimedOut, k.Expired
		row.RelayRefused = k.RefusedLinks + k.RefusedBusy + k.RefusedSource + k.RefusedRate + k.RefusedSetups
		t := time.Duration(last.child.MonoNs - first.child.MonoNs)
		childCPU := time.Duration(last.child.CPUNs - first.child.CPUNs)
		cells := last.child.Counters.Delivered - first.child.Counters.Delivered
		n := &perfNode{Cores: c.cores, PerCore: c.circuits, Circuits: c.circuits * c.cores,
			NodeCPUs: nodeCPUs, NodeSiblings: p.topo.Siblings, LoadCPUs: p.topo.Load, TopologyKnown: p.topo.Known, L3Group: p.topo.L3Group,
			NodeLocked: child.Ready().Locked, NodeDumpable: child.Ready().Dumpable, NodeGOMAXPROCS: last.child.GOMAXPROCS, NodeWindowS: seconds(t),
			SnapSkewUs: opt(float64(max(first.skew, last.skew)) / float64(time.Microsecond)), NodeDelivered: cells,
			Step: c.step}
		// the child must have run on its CPUs in every reading, and the parent on
		// the load CPUs to the end of the window
		n.AffinityOK = child.Ready().AffinityOK && first.child.AffinityOK && last.child.AffinityOK && final.AffinityOK && parentPinned(p.topo.Load)
		n.NodeRate = opt(metrics.CounterRate(first.child.Counters.Delivered, last.child.Counters.Delivered, t))
		n.NodeCPUS = seconds(childCPU)
		n.NodeUtil = opt(metrics.Utilisation(childCPU, t, c.cores))
		busy := math.NaN()
		if first.hostOK && last.hostOK {
			busy = metrics.Utilisation(last.node.Sub(first.node).Worked(), t, c.cores)
		}
		n.NodeBusyUtil = opt(busy)
		parent := metrics.Utilisation(last.parent-first.parent, t, len(p.topo.Load))
		n.ParentUtil = opt(parent)
		n.CorePerCell = opt(metrics.CostPerCell(childCPU, cells))
		n.Bound = metrics.Bound(busy, parent, perfBoundThreshold)
		row.perfNode = n
		counts := metrics.CountsWithin(run.Completed, run.EchoFlow, cfg.Flows, from, to)
		mean, low := metrics.Goodput(counts, run.Payload, window)
		row.perfGoodput = &perfGoodput{Mean: opt(mean), Min: opt(low)}
	}
	return row, nil
}

// the parent runs on the load CPUs while a node cell runs, with GOMAXPROCS set
// by hand so the runtime does not follow the mask on its own
func pinParent(load []int) (func([]int), error) {
	procs := runtime.GOMAXPROCS(0)
	if _, err := perf.Pin(load); err != nil {
		return nil, err
	}
	runtime.GOMAXPROCS(len(load))
	return func(allowed []int) {
		_, _ = perf.Pin(allowed)
		runtime.GOMAXPROCS(procs)
	}, nil
}

func parentPinned(load []int) bool { return perf.MasksOK(load) }
