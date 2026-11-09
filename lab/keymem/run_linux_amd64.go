//go:build linux && amd64

package keymem

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sync"

	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"golang.org/x/sys/unix"
)

func Run(ctx context.Context, c Config) (Report, error) {
	if e := c.validate(); e != nil {
		return Report{}, e
	}
	r := newReport(c)
	unavailable := func(class string) (Report, error) {
		for i := range r.Trials {
			r.Trials[i].terminal(class)
		}
		_ = r.finish()
		return r, errors.New(class)
	}
	if runtime.Version() != "go1.27.3" {
		return unavailable("unsupported_runtime")
	}
	if secmem.SetPolicy(secmem.Protected) != nil || secmem.HardenProcess() != nil {
		return unavailable("protection_unavailable")
	}
	protection, e := inspectProtection("all", true)
	if e != nil {
		return unavailable(childClass(e, "protection_unavailable"))
	}
	r.Manifest.Protection.Controller = &protection
	p, e := suite.New(c.Suite)
	if e != nil {
		return unavailable("controller_failed")
	}
	digest, e := ownDigest(p)
	if e != nil {
		return unavailable("controller_failed")
	}
	r.Manifest.BinaryDigest = &digest
	env, e := environment()
	if e != nil {
		return unavailable("controller_failed")
	}
	r.Manifest.Environment = env
	for i, cell := range r.Manifest.PlannedOrder {
		if ctx.Err() != nil {
			r.Trials[i].terminal("not_started")
			continue
		}
		tctx, cancel := context.WithTimeout(ctx, trialTimeout)
		row := newTrial(c, cell)
		f, e := newFixture(tctx, p)
		if e != nil {
			row.terminal(childClass(e, "fixture_failed"))
			if errors.Is(e, errFixtureCleanup) {
				row.CleanupError = pointer("fixture_cleanup_failed")
			}
			r.Trials[i] = row
			cancel()
			continue
		}
		var nonce [16]byte
		if randomFill(nonce[:]) != nil {
			row.terminal("controller_failed")
			if f.close() != nil {
				row.CleanupError = pointer("fixture_cleanup_failed")
			}
			r.Trials[i] = row
			cancel()
			continue
		}
		cfg := childConfig{Version: 1, Nonce: hex.EncodeToString(nonce[:]), Suite: c.Suite.String(), Policy: cell.Policy, Checkpoint: cell.Checkpoint, Anchor: f.ca.Anchor().String(), Relays: f.public}
		row = runTrial(tctx, row, cfg, digest)
		if f.close() != nil {
			if row.CleanupError == nil {
				row.CleanupError = pointer("fixture_cleanup_failed")
			}
			if row.Status == "evaluated" {
				row.terminal("cleanup_failed")
			}
		}
		if row.Status == "evaluated" && tctx.Err() != nil {
			if errors.Is(tctx.Err(), context.DeadlineExceeded) {
				row.terminal("capture_timeout")
			} else {
				row.terminal("controller_failed")
			}
		}
		cancel()
		r.Trials[i] = row
	}
	e = r.finish()
	if ctx.Err() != nil {
		return r, errControllerFailed
	}
	return r, e
}

func environment() (Environment, error) {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return Environment{}, errControllerFailed
	}
	kernel := make([]byte, 0, len(u.Release))
	for _, v := range u.Release {
		if v == 0 {
			break
		}
		kernel = append(kernel, byte(v))
	}
	if len(kernel) < 1 || len(kernel) > 256 {
		return Environment{}, errControllerFailed
	}
	for _, v := range kernel {
		if v < 32 || v > 126 {
			return Environment{}, errControllerFailed
		}
	}
	e := Environment{KernelRelease: string(kernel), NumCPU: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), GOGC: "runtime_default", GOMEMLIMIT: "runtime_default"}
	for _, name := range []string{"GOGC", "GOMEMLIMIT"} {
		if v, ok := os.LookupEnv(name); ok {
			valid := false
			if name == "GOGC" {
				valid = regexp.MustCompile(`^(off|[0-9]{1,10})$`).MatchString(v)
				e.GOGC = v
			} else {
				valid = regexp.MustCompile(`^(off|[0-9]{1,20}(B|KiB|MiB|GiB|TiB)?)$`).MatchString(v)
				e.GOMEMLIMIT = v
			}
			if !valid {
				return Environment{}, errControllerFailed
			}
		}
	}
	return e, nil
}

type parserEvidence struct {
	result parseResult
	err    error
}

type trialEvidence struct {
	status          statusResult
	oracle          oracleResult
	parser          parserEvidence
	parsed          bool
	exitCode        int
	deadline        bool
	cancelled       bool
	controller      bool
	commandComplete bool
	cleanup         *string
}

func resolve(e trialEvidence) string {
	terminal := e.status.EOF && e.status.Err == nil
	terminalMismatch := terminal && ((e.status.Failed != nil && e.exitCode == 0) || (e.status.Cleaned != nil && e.exitCode == 1))
	if e.status.Independent || terminalMismatch {
		return "protocol_invalid"
	}
	if e.oracle.Independent && errors.Is(e.oracle.Err, errOracleInvalid) {
		return "oracle_invalid"
	}
	if errors.Is(e.parser.err, errCaptureLimit) {
		return "capture_limit"
	}
	if errors.Is(e.parser.err, errParseInvalid) {
		return "parse_invalid"
	}
	if errors.Is(e.parser.err, errControlFailed) {
		return "control_failed"
	}
	if e.parsed && e.parser.result.Complete && (!e.parser.result.PositiveOK || !e.parser.result.NegativeOK) {
		return "control_failed"
	}
	if terminal && e.status.Failed != nil {
		if e.exitCode == 1 {
			return e.status.Failed.ErrorClass
		}
	}
	if e.exitCode == 2 && e.status.Configured == nil && e.status.Ready == nil && e.status.Cleaned == nil && e.status.Failed == nil {
		return "protocol_invalid"
	}
	if e.controller || e.cancelled {
		return "controller_failed"
	}
	if e.deadline {
		return "capture_timeout"
	}
	if e.exitCode != 0 || !terminal || e.status.Cleaned == nil {
		return "target_failed"
	}
	if e.oracle.Err != nil {
		if errors.Is(e.oracle.Err, errOracleInvalid) {
			return "oracle_invalid"
		}
		return e.oracle.Err.Error()
	}
	if !e.parsed || errors.Is(e.parser.err, errCaptureIncomplete) {
		return "capture_incomplete"
	}
	if e.parser.err != nil {
		return "controller_failed"
	}
	if !e.parser.result.Complete {
		return "capture_incomplete"
	}
	if e.status.Returned == nil || e.status.Ready == nil || e.status.Configured == nil {
		return "protocol_invalid"
	}
	if !e.commandComplete {
		return "controller_failed"
	}
	if e.cleanup != nil {
		return "cleanup_failed"
	}
	return "evaluated"
}

type trialInspection struct {
	pid                  int
	waitCalls            int
	processReaped        bool
	readersStarted       int
	readersJoined        int
	commandWritten       bool
	writerHeld           bool
	workloadReady        bool
	oracleReady          bool
	allDescriptorsClosed bool
}

func runTrial(ctx context.Context, row Trial, cfg childConfig, digest string) Trial {
	return runTrialWithCommandHold(ctx, row, cfg, digest, false, nil)
}

func runTrialWithCommandHold(ctx context.Context, row Trial, cfg childConfig, digest string, holdCommandEOF bool, inspection *trialInspection) Trial {
	var pipes [4][2]*os.File
	var heldCommand *os.File
	closeFile := func(f *os.File) bool {
		if f == nil {
			return true
		}
		e := f.Close()
		return e == nil || errors.Is(e, os.ErrClosed)
	}
	closeAll := func() {
		for _, pair := range pipes {
			for _, f := range pair {
				closeFile(f)
			}
		}
		closeFile(heldCommand)
	}
	for i := range pipes {
		r, w, e := os.Pipe()
		if e != nil {
			closeAll()
			row.terminal("controller_failed")
			return row
		}
		pipes[i] = [2]*os.File{r, w}
	}
	defer func() {
		closeAll()
		if inspection != nil {
			inspection.allDescriptorsClosed = true
			for _, pair := range pipes {
				for _, f := range pair {
					if f != nil && f.Fd() != ^uintptr(0) {
						inspection.allDescriptorsClosed = false
					}
				}
			}
			if heldCommand != nil && heldCommand.Fd() != ^uintptr(0) {
				inspection.allDescriptorsClosed = false
			}
		}
	}()
	null, e := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if e != nil {
		row.terminal("controller_failed")
		return row
	}
	defer null.Close()
	exe, e := os.Executable()
	if e != nil {
		row.terminal("controller_failed")
		return row
	}
	cmd := exec.Command(exe, privateArg)
	cmd.ExtraFiles = []*os.File{pipes[0][0], pipes[1][1], pipes[2][1], pipes[3][1]}
	cmd.Stdout = null
	cmd.Stderr = null
	if ctx.Err() != nil {
		row.terminal("not_started")
		return row
	}
	if e = cmd.Start(); e != nil {
		row.terminal("target_start_failed")
		return row
	}
	row.Started = true
	if inspection != nil {
		inspection.pid = cmd.Process.Pid
	}
	for _, f := range cmd.ExtraFiles {
		closeFile(f)
	}
	events := make(chan statusEvent, 2)
	statusCh := make(chan statusResult, 1)
	oracleCh := make(chan oracleResult, 1)
	parseCh := make(chan parserEvidence, 1)
	waitCh := make(chan int, 1)
	var workers sync.WaitGroup
	workers.Add(3)
	defer workers.Wait()
	if inspection != nil {
		inspection.readersStarted = 2
	}
	go func() { defer workers.Done(); statusCh <- readStatuses(pipes[3][0], cfg, digest, events) }()
	go func() { defer workers.Done(); oracleCh <- readOracle(pipes[1][0]) }()
	go func() {
		defer workers.Done()
		if inspection != nil {
			inspection.waitCalls++
		}
		e := cmd.Wait()
		if e == nil {
			waitCh <- 0
			return
		}
		var x *exec.ExitError
		if errors.As(e, &x) {
			waitCh <- x.ExitCode()
		} else {
			waitCh <- -1
		}
	}()
	ev := trialEvidence{exitCode: -1}
	oracleDone, statusDone, waitDone, parseDone := false, false, false, true
	var ready *readyData
	var aborted, authorized bool
	abort := func() {
		if aborted {
			return
		}
		aborted = true
		if !waitDone {
			if e := cmd.Process.Kill(); e != nil && !errors.Is(e, os.ErrProcessDone) && !errors.Is(e, unix.ESRCH) {
				ev.cleanup = pointer("process_cleanup_failed")
			}
		}
		for _, f := range []*os.File{pipes[0][1], pipes[1][0], pipes[2][0], pipes[3][0]} {
			if !closeFile(f) && ev.cleanup == nil {
				ev.cleanup = pointer("pipe_cleanup_failed")
			}
		}
		if !closeFile(heldCommand) && ev.cleanup == nil {
			ev.cleanup = pointer("pipe_cleanup_failed")
		}
	}
	if e = writeFrame(pipes[0][1], cfg, maxConfigBytes); e != nil {
		ev.controller = true
		abort()
	}
	ctxDone := ctx.Done()
	for !(oracleDone && statusDone && waitDone && parseDone) {
		if !aborted && !authorized && oracleDone && ev.oracle.Err == nil && ready != nil {
			authorized = true
			parseDone = false
			patterns := ev.oracle.Patterns
			markerAddress := ready.MarkerAddress
			workers.Add(1)
			if inspection != nil {
				inspection.readersStarted++
			}
			go func() {
				defer workers.Done()
				p, e := parseHeap(pipes[2][0], patterns, markerAddress)
				parseCh <- parserEvidence{p, e}
			}()
			if holdCommandEOF {
				fd, dupErr := unix.FcntlInt(pipes[0][1].Fd(), unix.F_DUPFD_CLOEXEC, 0)
				if dupErr != nil {
					ev.controller = true
					abort()
					continue
				}
				heldCommand = os.NewFile(uintptr(fd), "command-EOF-hold")
				if inspection != nil {
					inspection.writerHeld = true
				}
			}
			if e = writeCapture(pipes[0][1], cfg.Nonce); e != nil {
				closeFile(pipes[0][1])
				if errors.Is(e, errControllerFailed) {
					ev.controller = true
					abort()
				}
			} else {
				ev.commandComplete = true
				if inspection != nil {
					inspection.commandWritten = true
				}
			}
		}
		select {
		case event := <-events:
			if event.Fatal {
				abort()
			} else if event.Ready != nil {
				ready = event.Ready
				if inspection != nil {
					inspection.workloadReady = true
				}
			}
		case s := <-statusCh:
			if inspection != nil {
				inspection.readersJoined++
			}
			ev.status = s
			statusDone = true
			statusCh = nil
			if s.Ready != nil {
				ready = s.Ready
				if inspection != nil {
					inspection.workloadReady = true
				}
			}
			if s.Independent {
				abort()
			}
		case o := <-oracleCh:
			if inspection != nil {
				inspection.readersJoined++
			}
			ev.oracle = o
			if inspection != nil && o.Err == nil {
				inspection.oracleReady = true
			}
			oracleDone = true
			oracleCh = nil
			if o.Independent {
				if !errors.Is(o.Err, errOracleInvalid) {
					ev.controller = true
				}
				abort()
			}
		case p := <-parseCh:
			if inspection != nil {
				inspection.readersJoined++
			}
			ev.parser = p
			ev.parsed = true
			parseDone = true
			parseCh = nil
			if errors.Is(p.err, errCaptureLimit) || errors.Is(p.err, errParseInvalid) || errors.Is(p.err, errControlFailed) {
				abort()
			} else if p.err != nil && !errors.Is(p.err, errCaptureIncomplete) && !aborted {
				ev.controller = true
				abort()
			}
		case code := <-waitCh:
			if inspection != nil {
				inspection.processReaped = cmd.ProcessState != nil
			}
			ev.exitCode = code
			waitDone = true
			waitCh = nil
		case <-ctxDone:
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				ev.deadline = true
			} else {
				ev.cancelled = true
			}
			ctxDone = nil
			abort()
		}
	}
	workers.Wait()
	defer ev.oracle.release()
	if ev.status.Failed != nil && ev.status.EOF && ev.status.Err == nil && ev.exitCode == 1 && ev.status.Failed.CleanupError != nil && ev.cleanup == nil {
		ev.cleanup = pointer("child_cleanup_failed")
	}
	row.CleanupError = ev.cleanup
	if d := ev.status.Configured; d != nil {
		row.Runtime = &d.Runtime
		row.Protection = &d.Protection
		if cfg.Policy == "all" {
			row.PrimaryStorageExclusion = pointer("protected_primary_mmap")
		}
	}
	if d := ev.status.Ready; d != nil {
		row.EchoOK = &d.EchoOK
		row.SelectedCount = &d.SelectedCount
		row.AEADUses = &d.AEADUses
		row.ActiveLengths = &d.ActiveLengths
		row.Timing.EchoReadyNS = &d.EchoReadyNS
		row.NumGC.EchoReady = &d.NumGCEchoReady
	}
	if d := ev.status.Returned; d != nil {
		row.Timing = d.Timing
		row.NumGC = d.NumGC
		row.ReleasedLengths = d.ReleasedLengths
	}
	if d := ev.status.Cleaned; d != nil {
		row.ReleasedLengths = &d.ReleasedLengths
	}
	if d := ev.status.Failed; d != nil && ev.status.EOF && ev.status.Err == nil && ev.exitCode == 1 {
		if d.ReleasedLengths != nil {
			row.ReleasedLengths = d.ReleasedLengths
		}
	}
	if ev.parsed {
		p := ev.parser.result
		row.ParseComplete = &p.Complete
		row.StreamBytes = &p.StreamBytes
		row.ObjectRecords = &p.ObjectRecords
		row.ObjectBytes = &p.ObjectBytes
		row.UnscoredBlobBytes = &p.UnscoredBlobBytes
		if p.Complete {
			row.PositiveOK = &p.PositiveOK
			row.NegativeOK = &p.NegativeOK
		}
	}
	row.terminal(resolve(ev))
	if row.Status == "evaluated" {
		anyMatch := false
		for i, n := range ev.parser.result.Matches {
			row.Keys[i].Matches = pointer(n)
			anyMatch = anyMatch || n > 0
		}
		row.AnyMatch = &anyMatch
	}
	return row
}
