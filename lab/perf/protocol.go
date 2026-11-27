package perf

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/relay"
)

var (
	ErrNoAffinity       = errors.New("perf: cpu affinity needs linux")
	ErrCoresUnavailable = errors.New("perf: cores_unavailable")
)

// the child takes one line of it on stdin before anything else
type ChildConfig struct {
	Suite  jcrypto.Suite `json:"suite"`
	KeyMem string        `json:"keymem"` // "all" or "nolock"
	CPUs   []int         `json:"cpus"`
	// working directory of the child; empty keeps the parent's
	Dir string `json:"-"`
}

// the child's answer once its relay serves: only the public key and aggregates
// cross the pipe
type Ready struct {
	Addr          string  `json:"addr"`
	Pub           []byte  `json:"pub"`
	Locked        bool    `json:"locked"`
	MemlockBudget *uint64 `json:"memlock_budget"`
	CPUs          []int   `json:"cpus"`
	GOMAXPROCS    int     `json:"gomaxprocs"`
	AffinityOK    bool    `json:"affinity_ok"`
	// PR_GET_DUMPABLE after hardening; null off linux
	Dumpable *int `json:"dumpable"`
}

type Snapshot struct {
	Counters relay.Counters
	// processor time of the child by getrusage and its monotonic clock since it
	// started
	CPUNs      int64
	MonoNs     int64
	AffinityOK bool
	GOMAXPROCS int
}

type CPUTimes struct {
	User, Nice, System, Irq, Softirq, Steal time.Duration
}

// leaves out irq and softirq: they hold the loopback work of the run itself,
// which the kernel may not charge to any process, and noise counted from them
// would grow with the throughput
func (t CPUTimes) Busy() time.Duration { return t.User + t.Nice + t.System + t.Steal }

// what the CPUs worked, interrupts included and time taken by the hypervisor
// left out
func (t CPUTimes) Worked() time.Duration {
	return t.User + t.Nice + t.System + t.Irq + t.Softirq
}

func (t CPUTimes) Sub(u CPUTimes) CPUTimes {
	return CPUTimes{t.User - u.User, t.Nice - u.Nice, t.System - u.System, t.Irq - u.Irq, t.Softirq - u.Softirq, t.Steal - u.Steal}
}

func (t CPUTimes) Mid(u CPUTimes) CPUTimes {
	h := func(a, b time.Duration) time.Duration { return a + (b-a)/2 }
	return CPUTimes{h(t.User, u.User), h(t.Nice, u.Nice), h(t.System, u.System), h(t.Irq, u.Irq), h(t.Softirq, u.Softirq), h(t.Steal, u.Steal)}
}

type Topo struct {
	Node, Siblings, Load []int // siblings: SMT siblings of node CPUs, given to nobody
	Known                bool  // physical topology read and not under a hypervisor
	Virtualized          bool
	L3Group              string
}

const (
	cmdSnap = "snap"
	// every answer comes within this, or the parent kills the child
	answerTimeout = 10 * time.Second
	stderrLimit   = 64 << 10
)

func writeLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
