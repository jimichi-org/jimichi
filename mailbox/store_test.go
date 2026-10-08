package mailbox

import (
	"bytes"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type countingProvider struct {
	jcrypto.CryptoProvider
	hashes atomic.Int64
}

func (p *countingProvider) Hash(data ...[]byte) []byte {
	p.hashes.Add(1)
	return p.CryptoProvider.Hash(data...)
}

type fixture struct {
	t   *testing.T
	p   *countingProvider
	s   *Store
	clk *clock
}

func newFixture(t *testing.T, change func(*Limits)) *fixture {
	t.Helper()
	lim := DefaultLimits()
	if change != nil {
		change(&lim)
	}
	p := &countingProvider{CryptoProvider: providerOf(t, jcrypto.SuiteC25519)}
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	s, err := NewStore(p, lim, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return &fixture{t: t, p: p, s: s, clk: clk}
}

func capOf(b byte) [CapSize]byte {
	var f [CapSize]byte
	for i := range f {
		f[i] = b
	}
	return f
}

func randomCap(t *testing.T) [CapSize]byte {
	var f [CapSize]byte
	if _, err := rand.Read(f[:]); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) id(fetchCap [CapSize]byte) [IDSize]byte {
	f.t.Helper()
	id, err := QueueID(f.p, fetchCap[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func recordOf(b byte) [RecordSize]byte {
	var r [RecordSize]byte
	for i := range r {
		r[i] = b
	}
	return r
}

// one request through Deliver; the reply must pass every check a client makes
func (f *fixture) do(circuit uint64, req Request) Reply {
	f.t.Helper()
	out := f.s.Deliver(circuit, req.Bytes())
	r, err := ParseReply(out)
	if err != nil {
		f.t.Fatalf("reply does not parse: %v", err)
	}
	if err := r.Answers(&req); err != nil {
		f.t.Fatalf("reply %#02x does not answer the request: %v", r.Status, err)
	}
	return r
}

func (f *fixture) put(circuit uint64, to [IDSize]byte, rec byte) byte {
	f.t.Helper()
	return f.do(circuit, Request{Tag: 1, Put: to, Record: recordOf(rec)}).Status & PutMask
}

// the record the fetch returned, or 0 for none
func (f *fixture) fetch(circuit uint64, fetchCap [CapSize]byte) byte {
	f.t.Helper()
	r := f.do(circuit, Request{Tag: 2, Fetch: fetchCap})
	if r.Status&StatusRecord == 0 {
		return 0
	}
	if r.Record != recordOf(r.Record[0]) {
		f.t.Fatal("fetched record is not the one put")
	}
	return r.Record[0]
}

// the arrays the store holds for one queue, so a test can see them zeroed
func (f *fixture) arrays(id [IDSize]byte) []*[RecordSize]byte {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	var out []*[RecordSize]byte
	if q := f.s.queues[id]; q != nil {
		for _, r := range q.records {
			out = append(out, r.data)
		}
	}
	return out
}

func expectZero(t *testing.T, what string, arrays ...*[RecordSize]byte) {
	t.Helper()
	for i, a := range arrays {
		if *a != ([RecordSize]byte{}) {
			t.Fatalf("%s: array %d not zeroed", what, i)
		}
	}
}

func TestNewStoreRefusesBadLimits(t *testing.T) {
	p := providerOf(t, jcrypto.SuiteC25519)
	if _, err := NewStore(nil, DefaultLimits(), nil); err == nil {
		t.Fatal("a store without a provider")
	}
	for _, change := range []func(*Limits){
		func(l *Limits) { l.TTL = 0 },
		func(l *Limits) { l.Depth = 0 },
		func(l *Limits) { l.Queues = -1 },
		func(l *Limits) { l.Records = 0 },
		func(l *Limits) { l.Circuits = 0 },
	} {
		lim := DefaultLimits()
		change(&lim)
		if _, err := NewStore(p, lim, nil); err == nil {
			t.Fatalf("limits %+v accepted", lim)
		}
	}
}

func TestDefaultLimits(t *testing.T) {
	if l := DefaultLimits(); l != (Limits{TTL: 5 * time.Minute, Depth: 16, Queues: 1024, Records: 16384, Circuits: 4096}) {
		t.Fatalf("defaults %+v", l)
	}
}

func TestBadRequestGetsAFullReplyWithItsTag(t *testing.T) {
	f := newFixture(t, nil)
	valid := sampleRequest().Bytes()
	for _, c := range []struct {
		name string
		in   []byte
		tag  uint16
	}{
		{"empty", nil, 0},
		{"one byte", []byte{0x01}, 0},
		{"two bytes", []byte{0x01, 0x12}, 0},
		{"three bytes", []byte{0x01, 0x12, 0x34}, 0x1234},
		{"one byte short", valid[:RequestSize-1], 0x1234},
		{"one byte long", append(append([]byte{}, valid...), 0), 0x1234},
		{"version 2", append([]byte{0x02}, valid[1:]...), 0x1234},
	} {
		out := f.s.Deliver(9, append([]byte{}, c.in...))
		want := Reply{Tag: c.tag, Status: StatusBad}
		if !bytes.Equal(out, want.Bytes()) {
			t.Fatalf("%s: reply %x..., want 0x80 with tag %#04x", c.name, out[:min(4, len(out))], c.tag)
		}
	}
	if s := f.s.Stats(); s.Bad != 7 || s.Requests != 7 || s.Bindings != 0 || s.Queues != 0 {
		t.Fatalf("after bad requests: %+v", s)
	}
}

func TestPayloadIsZeroedAfterDeliver(t *testing.T) {
	f := newFixture(t, nil)
	good := sampleRequest().Bytes()
	f.s.Deliver(1, good)
	short := sampleRequest().Bytes()[:100]
	f.s.Deliver(2, short)
	for name, b := range map[string][]byte{"request": good, "bad request": short} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("%s payload not zeroed", name)
		}
	}
}

func TestQueueIsFIFO(t *testing.T) {
	f := newFixture(t, nil)
	a := capOf(0xaa)
	for _, rec := range []byte{1, 2, 3} {
		if st := f.put(1, f.id(a), rec); st != PutStored {
			t.Fatalf("put %d: %#02x", rec, st)
		}
	}
	for _, want := range []byte{1, 2, 3, 0} {
		if got := f.fetch(2, a); got != want {
			t.Fatalf("fetched %d, want %d", got, want)
		}
	}
	if s := f.s.Stats(); s.Puts != 3 || s.Fetches != 4 || s.Hits != 3 || s.Records != 0 || s.Queues != 1 {
		t.Fatalf("counters %+v", s)
	}
}

func TestPutAndFetchInOneRequest(t *testing.T) {
	f := newFixture(t, nil)
	a, b := capOf(0xaa), capOf(0xbb)
	f.put(1, f.id(a), 7)
	r := f.do(2, Request{Tag: 3, Fetch: a, Put: f.id(b), Record: recordOf(8)})
	if r.Status != PutStored|StatusRecord || r.Record[0] != 7 || r.Tag != 3 {
		t.Fatalf("reply %#02x with record %d", r.Status, r.Record[0])
	}
	if got := f.fetch(3, b); got != 8 {
		t.Fatalf("fetched %d from the other queue", got)
	}
}

func TestOnlyPutCreatesAQueue(t *testing.T) {
	f := newFixture(t, nil)
	for i := range 50 {
		if got := f.fetch(uint64(i), randomCap(t)); got != 0 {
			t.Fatal("a record out of nowhere")
		}
	}
	if s := f.s.Stats(); s.Queues != 0 || s.Fetches != 50 || s.Hits != 0 {
		t.Fatalf("fetches made queues: %+v", s)
	}
}

func TestCircuitIsBoundToOneQueueEachWay(t *testing.T) {
	f := newFixture(t, nil)
	a, b, c := capOf(0xaa), capOf(0xbb), capOf(0xcc)
	f.do(1, Request{Tag: 1, Fetch: a, Put: f.id(b), Record: recordOf(1)})

	for name, req := range map[string]Request{
		"other fetch":           {Tag: 5, Fetch: c},
		"other put":             {Tag: 6, Put: f.id(c), Record: recordOf(2)},
		"same fetch, other put": {Tag: 7, Fetch: a, Put: f.id(c), Record: recordOf(2)},
		"other fetch, same put": {Tag: 8, Fetch: c, Put: f.id(b), Record: recordOf(2)},
	} {
		before := f.s.Stats()
		out := f.s.Deliver(1, req.Bytes())
		want := Reply{Tag: req.Tag, Status: StatusBad}
		if !bytes.Equal(out, want.Bytes()) {
			t.Fatalf("%s: not refused as a whole", name)
		}
		after := f.s.Stats()
		if after.Puts != before.Puts || after.Fetches != before.Fetches || after.Queues != before.Queues || after.Bad != before.Bad+1 {
			t.Fatalf("%s: a refused request changed the store: %+v", name, after)
		}
	}

	if st := f.put(2, f.id(c), 3); st != PutStored {
		t.Fatalf("another circuit is not free: %#02x", st)
	}
	if got := f.fetch(2, c); got != 3 {
		t.Fatalf("another circuit fetched %d", got)
	}
	if r := f.do(1, Request{Tag: 9, Fetch: a, Put: f.id(b), Record: recordOf(4)}); r.Status&PutMask != PutStored {
		t.Fatalf("the bound queues no longer work: %#02x", r.Status)
	}
	if r := f.do(1, Request{Tag: 10}); r.Status != PutNone {
		t.Fatalf("an empty request on a bound circuit: %#02x", r.Status)
	}
}

func TestFetchedQueueOutlivesTheTTL(t *testing.T) {
	f := newFixture(t, nil)
	held, idle := capOf(0x11), capOf(0x22)
	f.put(1, f.id(held), 1)
	f.put(2, f.id(idle), 2)
	f.fetch(3, held)
	f.fetch(4, idle)
	for range 20 {
		f.clk.add(time.Minute)
		f.fetch(3, held)
		f.s.Sweep(f.clk.now())
	}
	f.s.mu.Lock()
	_, heldThere := f.s.queues[f.id(held)]
	_, idleThere := f.s.queues[f.id(idle)]
	f.s.mu.Unlock()
	if !heldThere || idleThere {
		t.Fatalf("after 20 minutes: fetched queue kept %v, idle queue kept %v", heldThere, idleThere)
	}
}

func TestEvictionTakesOnlyAnUnfetchedQueue(t *testing.T) {
	f := newFixture(t, func(l *Limits) { l.Queues = 2 })
	held, idle, third := capOf(0x11), capOf(0x22), capOf(0x33)
	f.put(1, f.id(held), 1)
	f.put(2, f.id(idle), 2)
	f.put(3, f.id(idle), 3)
	idleArrays := f.arrays(f.id(idle))

	f.clk.add(2 * time.Minute)
	f.fetch(4, held)
	if st := f.put(5, f.id(third), 9); st != PutRefused {
		t.Fatalf("both queues held, put of a new one: %#02x, want 11", st)
	}

	f.clk.add(4 * time.Minute)
	f.fetch(4, held)
	if st := f.put(5, f.id(third), 9); st != PutStored {
		t.Fatalf("put once the idle queue lapsed: %#02x, want 01", st)
	}
	expectZero(t, "evicted queue", idleArrays...)
	s := f.s.Stats()
	if s.Evicted != 1 || s.PutRefused != 1 || s.Queues != 2 || s.Records != 1 {
		t.Fatalf("counters %+v", s)
	}
	if got := f.fetch(7, third); got != 9 {
		t.Fatalf("the new queue holds %d", got)
	}
	if got := f.fetch(6, idle); got != 0 {
		t.Fatalf("evicted queue still answers: %d", got)
	}

	f.clk.add(time.Hour)
	f.fetch(4, held)
	f.fetch(7, third)
	for i := range 10 {
		if st := f.put(uint64(100+i), f.id(randomCap(t)), 5); st != PutRefused {
			t.Fatalf("a fetched queue was evicted: %#02x", st)
		}
	}
}

// strangers who each bind a circuit to a queue of their own fill the queue
// limit and get refusals; the pair keeps putting and fetching
func TestRandomPutsDoNotDisturbALivePair(t *testing.T) {
	f := newFixture(t, func(l *Limits) { l.Queues = 4 })
	a, b := capOf(0xaa), capOf(0xbb)
	f.do(1, Request{Tag: 1, Fetch: a, Put: f.id(b), Record: recordOf(1)})
	f.do(2, Request{Tag: 1, Fetch: b, Put: f.id(a), Record: recordOf(2)})
	refused := 0
	for i := range 200 {
		f.clk.add(200 * time.Millisecond)
		st := f.put(uint64(1000+i), f.id(randomCap(t)), 9)
		if st == PutRefused {
			refused++
		}
		ra := f.do(1, Request{Tag: 2, Fetch: a, Put: f.id(b), Record: recordOf(byte(i))})
		rb := f.do(2, Request{Tag: 2, Fetch: b, Put: f.id(a), Record: recordOf(byte(i))})
		if ra.Status&PutMask != PutStored || rb.Status&PutMask != PutStored ||
			ra.Status&StatusRecord == 0 || rb.Status&StatusRecord == 0 {
			t.Fatalf("tick %d: the pair got %#02x and %#02x", i, ra.Status, rb.Status)
		}
	}
	if refused < 190 {
		t.Fatalf("only %d of 200 strangers refused", refused)
	}
}

func TestPutLimits(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		f := newFixture(t, func(l *Limits) { l.Depth = 2 })
		a := capOf(0xaa)
		for i, want := range []byte{PutStored, PutStored, PutFull, PutFull} {
			if st := f.put(1, f.id(a), byte(i+1)); st != want {
				t.Fatalf("put %d: %#02x, want %#02x", i, st, want)
			}
		}
		f.fetch(2, a)
		if st := f.put(1, f.id(a), 9); st != PutStored {
			t.Fatalf("put after a fetch: %#02x", st)
		}
		if s := f.s.Stats(); s.PutFull != 2 || s.Puts != 3 {
			t.Fatalf("counters %+v", s)
		}
	})
	t.Run("records", func(t *testing.T) {
		f := newFixture(t, func(l *Limits) { l.Records = 3 })
		for i := range 3 {
			if st := f.put(uint64(i), f.id(capOf(byte(i+1))), 1); st != PutStored {
				t.Fatalf("put %d: %#02x", i, st)
			}
		}
		if st := f.put(9, f.id(capOf(0x09)), 1); st != PutFull {
			t.Fatalf("put over the record limit, new queue: %#02x, want 10", st)
		}
		if st := f.put(0, f.id(capOf(0x01)), 1); st != PutFull {
			t.Fatalf("put over the record limit, existing queue: %#02x, want 10", st)
		}
	})
}

func TestRecordsExpire(t *testing.T) {
	f := newFixture(t, func(l *Limits) { l.TTL = time.Minute })
	a := capOf(0xaa)
	f.put(1, f.id(a), 1)
	f.clk.add(30 * time.Second)
	f.put(1, f.id(a), 2)
	arrays := f.arrays(f.id(a))
	f.clk.add(30 * time.Second)
	if got := f.fetch(2, a); got != 2 {
		t.Fatalf("fetched %d, want the younger record", got)
	}
	expectZero(t, "expired and fetched", arrays...)

	f.put(1, f.id(a), 3)
	arrays = f.arrays(f.id(a))
	f.clk.add(time.Minute)
	f.s.Sweep(f.clk.now())
	expectZero(t, "expired at the sweep", arrays...)
	if s := f.s.Stats(); s.Expired != 2 || s.Records != 0 {
		t.Fatalf("counters %+v", s)
	}
}

func TestFetchedRecordIsZeroedInTheStore(t *testing.T) {
	f := newFixture(t, nil)
	a := capOf(0xaa)
	f.put(1, f.id(a), 0x5a)
	arrays := f.arrays(f.id(a))
	if got := f.fetch(2, a); got != 0x5a {
		t.Fatalf("fetched %d", got)
	}
	expectZero(t, "fetched", arrays...)
}

func TestBindingTableIsBounded(t *testing.T) {
	f := newFixture(t, func(l *Limits) { l.Circuits = 3 })
	for c := range uint64(5) {
		f.fetch(c, capOf(byte(c+1)))
		f.clk.add(time.Second)
	}
	if s := f.s.Stats(); s.Bindings != 3 {
		t.Fatalf("%d bindings, want 3", s.Bindings)
	}
	// circuit 0 lost its binding and binds again, to anything
	if got := f.fetch(0, capOf(0x77)); got != 0 {
		t.Fatal("record out of nowhere")
	}
	f.s.Sweep(f.clk.now().Add(5 * time.Minute))
	if s := f.s.Stats(); s.Bindings != 0 {
		t.Fatalf("%d bindings after the TTL, want 0", s.Bindings)
	}
}

func (f *fixture) refused(circuit uint64, req Request) bool {
	f.t.Helper()
	r, err := ParseReply(f.s.Deliver(circuit, req.Bytes()))
	if err != nil {
		f.t.Fatalf("reply does not parse: %v", err)
	}
	return r.Status == StatusBad
}

func TestBindingTableEvictsTheLeastRecentlySeen(t *testing.T) {
	f := newFixture(t, func(l *Limits) { l.Circuits = 3 })
	for c := range uint64(3) {
		f.fetch(c, capOf(byte(c+1)))
		f.clk.add(time.Second)
	}
	f.fetch(0, capOf(1))
	f.fetch(3, capOf(4))
	f.fetch(4, capOf(5))
	if !f.refused(0, Request{Tag: 3, Fetch: capOf(0x77)}) {
		t.Fatal("the circuit seen last lost its binding to a newer one")
	}
	for _, c := range []uint64{1, 2} {
		if f.refused(c, Request{Tag: 3, Fetch: capOf(0x77)}) {
			t.Fatalf("circuit %d seen least recently kept its binding", c)
		}
	}
}

func TestSweepKeepsABindingCreatedFirstButSeenRecently(t *testing.T) {
	f := newFixture(t, nil)
	for c := range uint64(3) {
		f.fetch(c, capOf(byte(c+1)))
		f.clk.add(time.Second)
	}
	f.clk.add(4 * time.Minute)
	f.fetch(0, capOf(1))
	f.s.Sweep(f.clk.now().Add(time.Minute + 10*time.Second))
	if s := f.s.Stats(); s.Bindings != 1 {
		t.Fatalf("%d bindings after the sweep, want only the one seen recently", s.Bindings)
	}
	if !f.refused(0, Request{Tag: 3, Fetch: capOf(0x77)}) {
		t.Fatal("the sweep took the binding seen recently")
	}
}

// a queue nobody fetched is past its hold, yet its younger record keeps it
func TestSweepKeepsAnUnfetchedQueueWithALiveRecord(t *testing.T) {
	f := newFixture(t, nil)
	a := capOf(0xaa)
	f.put(1, f.id(a), 1)
	f.clk.add(4 * time.Minute)
	f.put(1, f.id(a), 2)
	f.clk.add(time.Minute + time.Second)
	f.s.Sweep(f.clk.now())
	if s := f.s.Stats(); s.Queues != 1 || s.Records != 1 || s.Expired != 1 {
		t.Fatalf("after the sweep: %+v", s)
	}
	if got := f.fetch(2, a); got != 2 {
		t.Fatalf("fetched %d, want the younger record", got)
	}
}

func TestCloseZeroesEverything(t *testing.T) {
	f := newFixture(t, nil)
	a := capOf(0xaa)
	f.put(1, f.id(a), 1)
	f.put(1, f.id(a), 2)
	arrays := f.arrays(f.id(a))
	f.s.Close()
	expectZero(t, "closed", arrays...)
	if s := f.s.Stats(); s.Queues != 0 || s.Records != 0 || s.Bindings != 0 {
		t.Fatalf("after Close: %+v", s)
	}
	req := Request{Tag: 4, Fetch: a}
	if out := f.s.Deliver(1, req.Bytes()); !bytes.Equal(out, (&Reply{Tag: 4, Status: StatusBad}).Bytes()) {
		t.Fatal("a closed store answers")
	}
	f.s.Close()
}

func TestOneHashPerRequestInEveryState(t *testing.T) {
	f := newFixture(t, func(l *Limits) { l.Queues = 1; l.Depth = 1 })
	a, b := capOf(0xaa), capOf(0xbb)
	idA, idB := f.id(a), f.id(b)
	valid := (&Request{Tag: 1, Fetch: a}).Bytes()
	cases := []struct {
		name    string
		circuit uint64
		in      []byte
	}{
		{"empty", 1, nil},
		{"short", 1, valid[:10]},
		{"other version", 1, append([]byte{0x02}, valid[1:]...)},
		{"nothing asked", 1, (&Request{Tag: 1}).Bytes()},
		{"fetch of no queue", 1, valid},
		{"put creates", 2, (&Request{Tag: 1, Put: idA, Record: recordOf(1)}).Bytes()},
		{"put full", 2, (&Request{Tag: 1, Put: idA, Record: recordOf(1)}).Bytes()},
		{"put refused", 3, (&Request{Tag: 1, Put: idB, Record: recordOf(1)}).Bytes()},
		{"binding refused", 1, (&Request{Tag: 1, Fetch: b}).Bytes()},
		{"fetch hit", 1, valid},
		{"fetch empty", 1, valid},
	}
	for _, c := range cases {
		before := f.p.hashes.Load()
		f.s.Deliver(c.circuit, append([]byte{}, c.in...))
		if n := f.p.hashes.Load() - before; n != 1 {
			t.Fatalf("%s: %d hashes, want 1", c.name, n)
		}
	}
	f.s.Close()
	before := f.p.hashes.Load()
	f.s.Deliver(1, append([]byte{}, valid...))
	if n := f.p.hashes.Load() - before; n != 1 {
		t.Fatalf("closed store: %d hashes, want 1", n)
	}
}

func TestConcurrentDeliver(t *testing.T) {
	f := newFixture(t, nil)
	const n = 8
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			own, next := capOf(byte(i+1)), capOf(byte((i+1)%n+1))
			nextID, err := QueueID(f.p, next[:])
			if err != nil {
				t.Error(err)
				return
			}
			for range 200 {
				req := Request{Tag: 1, Fetch: own, Put: nextID, Record: recordOf(byte(i))}
				r, err := ParseReply(f.s.Deliver(uint64(i), req.Bytes()))
				if err == nil {
					err = r.Answers(&req)
				}
				if err != nil {
					t.Error(err)
					return
				}
				f.s.Stats()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			f.s.Sweep(f.clk.now())
		}
	}()
	wg.Wait()
	if s := f.s.Stats(); s.Requests != n*200 || s.Bad != 0 {
		t.Fatalf("counters %+v", s)
	}
}

func TestRunSweepsUntilStopped(t *testing.T) {
	f := newFixture(t, nil)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		f.s.Run(stop)
		close(done)
	}()
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
