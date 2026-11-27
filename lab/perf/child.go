package perf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/lab"
)

const childArg = "--perf-node-child-v1"

// the policy of a level of block 6 by name; the levels differ only in Lock
func KeyMemPolicy(level string) (secmem.Policy, error) {
	switch level {
	case "all":
		return secmem.Protected, nil
	case "nolock":
		return secmem.Policy{OffHeap: true, DontDump: true, Zero: true}, nil
	}
	return secmem.Policy{}, fmt.Errorf("perf: keymem level %q", level)
}

// a binary that may be started as the child calls this first with its
// arguments; handled is true when it ran as the child, and code is its exit
// status: 0 done, 1 the relay or the pinning failed, 2 a protocol error
func MaybeRunChild(args []string) (handled bool, code int) {
	if len(args) == 0 || args[0] != childArg {
		return false, 0
	}
	if len(args) != 1 {
		return true, 2
	}
	return true, runChild(os.Stdin, os.Stdout)
}

func runChild(stdin io.Reader, stdout io.Writer) int {
	start := time.Now()
	in := bufio.NewScanner(stdin)
	if !in.Scan() {
		return 2
	}
	var cfg ChildConfig
	if err := json.Unmarshal(in.Bytes(), &cfg); err != nil {
		return 2
	}
	policy, err := KeyMemPolicy(cfg.KeyMem)
	if err != nil {
		return 2
	}
	// before any key: a policy acts on the buffers made after it
	if err := secmem.SetPolicy(policy); err != nil {
		return 2
	}
	dumpable, err := harden()
	if err != nil {
		fmt.Fprintf(os.Stderr, "perf child: harden: %v\n", err)
		return 1
	}
	affinity := false
	if len(cfg.CPUs) > 0 {
		ok, err := Pin(cfg.CPUs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "perf child: pin: %v\n", err)
			return 1
		}
		affinity = ok
		// set by hand, so the runtime does not move it after the mask
		runtime.GOMAXPROCS(len(cfg.CPUs))
	}
	p, err := suite.New(cfg.Suite)
	if err != nil {
		return 2
	}
	node, err := lab.StartNode(p, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "perf child: %v\n", err)
		return 1
	}
	defer node.Stop()
	snap := func() Snapshot {
		cpu, _ := ProcessCPU()
		ok := len(cfg.CPUs) > 0 && MasksOK(cfg.CPUs)
		return Snapshot{Counters: node.Counters(), CPUNs: int64(cpu), MonoNs: int64(time.Since(start)), AffinityOK: ok, GOMAXPROCS: runtime.GOMAXPROCS(0)}
	}
	addr := node.Client()
	ready := Ready{Addr: addr.Addr, Pub: addr.StaticPub, Locked: node.KeyLocked(), CPUs: cfg.CPUs, GOMAXPROCS: runtime.GOMAXPROCS(0), AffinityOK: affinity, Dumpable: dumpable}
	if b, err := secmem.MemlockBudget(); err == nil {
		ready.MemlockBudget = &b
	}
	if writeLine(stdout, ready) != nil {
		return 2
	}
	for in.Scan() {
		if in.Text() != cmdSnap {
			return 2
		}
		if writeLine(stdout, snap()) != nil {
			return 2
		}
	}
	if in.Err() != nil {
		return 2
	}
	node.Stop()
	if writeLine(stdout, snap()) != nil {
		return 2
	}
	return 0
}

// GOTRACEBACK, GODEBUG, GOGC and GOMEMLIMIT of the parent do not reach the
// measured node; windows needs SYSTEMROOT for its sockets
func childEnv() []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "GOTRACEBACK=none"}
	if runtime.GOOS == "windows" {
		env = append(env, "SYSTEMROOT="+os.Getenv("SYSTEMROOT"))
	}
	return env
}

// the parent's handle on a running child
type Child struct {
	cancel context.CancelFunc
	stdin  io.WriteCloser
	lines  chan []byte
	ready  Ready
	stderr *limitedBuffer
	waited chan error
	done   chan struct{}
	stop   sync.Once
	closed bool
}

type limitedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := stderrLimit - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// starts this binary as the child and waits for its relay; the child's stderr
// stays in memory, at most 64 KiB of it, and is shown only through Stderr
func Spawn(ctx context.Context, cfg ChildConfig) (*Child, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, exe, childArg)
	cmd.Dir = cfg.Dir
	cmd.Env = childEnv()
	stderr := &limitedBuffer{}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	c := &Child{cancel: cancel, stdin: stdin, lines: make(chan []byte, 4), stderr: stderr, waited: make(chan error, 1), done: make(chan struct{})}
	go func() {
		out := bufio.NewScanner(stdout)
		// lines nobody waits for are read and dropped, so Wait always runs
		for out.Scan() {
			select {
			case c.lines <- bytes.Clone(out.Bytes()):
			case <-c.done:
			}
		}
		close(c.lines)
		c.waited <- cmd.Wait()
	}()
	if err := writeLine(stdin, cfg); err != nil {
		c.Kill()
		return nil, err
	}
	if err := c.answer(&c.ready); err != nil {
		c.Kill()
		return nil, fmt.Errorf("%w; child stderr: %s", err, c.Stderr())
	}
	return c, nil
}

// ends the child at once, for a run that failed
func (c *Child) Kill() {
	c.closed = true
	c.stop.Do(func() { close(c.done) })
	c.cancel()
	_ = c.stdin.Close()
}

func (c *Child) answer(v any) error {
	timer := time.NewTimer(answerTimeout)
	defer timer.Stop()
	select {
	case line, ok := <-c.lines:
		if !ok {
			return errors.New("perf: the child ended")
		}
		return json.Unmarshal(line, v)
	case <-timer.C:
		c.Kill()
		return fmt.Errorf("perf: no answer from the child in %v", answerTimeout)
	}
}

func (c *Child) Ready() Ready { return c.ready }

func (c *Child) Node() client.Node { return client.Node{Addr: c.ready.Addr, StaticPub: c.ready.Pub} }

func (c *Child) Stderr() string { return c.stderr.String() }

func (c *Child) Snap() (Snapshot, error) {
	var s Snapshot
	if c.closed {
		return s, errors.New("perf: child closed")
	}
	if _, err := io.WriteString(c.stdin, cmdSnap+"\n"); err != nil {
		return s, err
	}
	return s, c.answer(&s)
}

// ends stdin, which stops the relay and releases its key, and takes the final
// snapshot; an exit status other than 0 is an error
func (c *Child) Close() (Snapshot, error) {
	var s Snapshot
	if c.closed {
		return s, errors.New("perf: child closed")
	}
	c.closed = true
	_ = c.stdin.Close()
	err := c.answer(&s)
	c.stop.Do(func() { close(c.done) })
	timer := time.NewTimer(answerTimeout)
	defer timer.Stop()
	select {
	case werr := <-c.waited:
		if err == nil && werr != nil {
			err = fmt.Errorf("perf: child: %w", werr)
		}
	case <-timer.C:
		if err == nil {
			err = fmt.Errorf("perf: the child did not exit in %v", answerTimeout)
		}
	}
	c.cancel()
	return s, err
}
