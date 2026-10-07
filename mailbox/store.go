package mailbox

import (
	"container/list"
	"sync"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

const SweepEvery = 30 * time.Second

type Limits struct {
	// how long a record waits for its fetch, and how long a queue stays held
	// after its last fetch
	TTL      time.Duration
	Depth    int
	Queues   int
	Records  int
	Circuits int
}

func DefaultLimits() Limits {
	return Limits{TTL: 5 * time.Minute, Depth: 16, Queues: 1024, Records: 16384, Circuits: 4096}
}

// Queues, Records and Bindings are the current sizes, the rest count events;
// none of them names a queue or a circuit
type Counters struct {
	Requests   uint64
	Queues     uint64
	Records    uint64
	Bindings   uint64
	Puts       uint64
	PutFull    uint64
	PutRefused uint64
	Fetches    uint64
	Hits       uint64
	Expired    uint64
	Evicted    uint64
	Bad        uint64
}

type record struct {
	data *[RecordSize]byte
	at   time.Time
}

type queue struct {
	id      [IDSize]byte
	records []record
	// the last fetch, or the creation until the first one
	active time.Time
	elem   *list.Element
}

type binding struct {
	circuit    uint64
	fetch, put [IDSize]byte
	fetchBound bool
	putBound   bool
	seen       time.Time
	elem       *list.Element
}

type Store struct {
	p   jcrypto.CryptoProvider
	lim Limits
	now func() time.Time

	mu     sync.Mutex
	queues map[[IDSize]byte]*queue
	// least recently active first, so the one queue eviction may take is at the
	// front and a put never walks the queues
	byActive list.List
	bindings map[uint64]*binding
	bySeen   list.List
	records  int
	closed   bool
	c        Counters
}

func NewStore(p jcrypto.CryptoProvider, lim Limits, now func() time.Time) (*Store, error) {
	if p == nil || lim.TTL <= 0 || lim.Depth <= 0 || lim.Queues <= 0 || lim.Records <= 0 || lim.Circuits <= 0 {
		return nil, ErrLimits
	}
	if now == nil {
		now = time.Now
	}
	return &Store{
		p: p, lim: lim, now: now,
		queues:   make(map[[IDSize]byte]*queue),
		bindings: make(map[uint64]*binding),
	}, nil
}

// the shape of relay.Deliver: circuit is the identifier on the inbound link of
// the exit, unique among its live circuits. The payload is zeroed before the
// call returns and the reply is always ReplySize bytes
func (s *Store) Deliver(circuit uint64, payload []byte) []byte {
	// one hash on every request, whatever it holds, so the time to the reply
	// says nothing about the state of the store
	var fetchCap [CapSize]byte
	if len(payload) >= 3+CapSize {
		copy(fetchCap[:], payload[3:3+CapSize])
	}
	fetchID, hashErr := QueueID(s.p, fetchCap[:])
	clear(fetchCap[:])

	req, err := ParseRequest(payload)
	defer clearRequest(&req)
	if err != nil || hashErr != nil {
		out := badReply(payload)
		clear(payload)
		s.mu.Lock()
		s.c.Requests++
		s.c.Bad++
		s.mu.Unlock()
		return out
	}
	clear(payload)

	reply := s.handle(circuit, &req, fetchID)
	out := reply.Bytes()
	clear(reply.Record[:])
	return out
}

func clearRequest(r *Request) {
	clear(r.Fetch[:])
	clear(r.Record[:])
}

func (s *Store) handle(circuit uint64, req *Request, fetchID [IDSize]byte) Reply {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.c.Requests++
	fetches, puts := req.Fetches(), req.Puts()
	b := s.bindings[circuit]
	if s.closed || b != nil && (fetches && b.fetchBound && b.fetch != fetchID || puts && b.putBound && b.put != req.Put) {
		s.c.Bad++
		return Reply{Tag: req.Tag, Status: StatusBad}
	}

	now := s.now()
	if b == nil {
		b = s.bind(circuit)
	}
	if fetches && !b.fetchBound {
		b.fetch, b.fetchBound = fetchID, true
	}
	if puts && !b.putBound {
		b.put, b.putBound = req.Put, true
	}
	b.seen = now
	s.bySeen.MoveToBack(b.elem)

	reply := Reply{Tag: req.Tag}
	if puts {
		reply.Status |= s.put(req.Put, &req.Record, now)
	}
	if fetches && s.fetch(fetchID, &reply.Record, now) {
		reply.Status |= StatusRecord
	}
	return reply
}

// an evicted binding belongs to a circuit nobody has heard from for longest;
// an honest one binds again to the same queues on its next request
func (s *Store) bind(circuit uint64) *binding {
	if len(s.bindings) >= s.lim.Circuits {
		s.unbind(s.bySeen.Front().Value.(*binding))
	}
	b := &binding{circuit: circuit}
	b.elem = s.bySeen.PushBack(b)
	s.bindings[circuit] = b
	return b
}

func (s *Store) unbind(b *binding) {
	s.bySeen.Remove(b.elem)
	delete(s.bindings, b.circuit)
}

func (s *Store) put(id [IDSize]byte, rec *[RecordSize]byte, now time.Time) byte {
	q := s.queues[id]
	if q != nil && len(q.records) >= s.lim.Depth || s.records >= s.lim.Records {
		s.c.PutFull++
		return PutFull
	}
	if q == nil {
		if len(s.queues) >= s.lim.Queues {
			oldest := s.byActive.Front().Value.(*queue)
			if s.held(oldest, now) {
				s.c.PutRefused++
				return PutRefused
			}
			s.drop(oldest)
			s.c.Evicted++
		}
		q = &queue{id: id, active: now}
		q.elem = s.byActive.PushBack(q)
		s.queues[id] = q
	}
	data := new([RecordSize]byte)
	*data = *rec
	q.records = append(q.records, record{data: data, at: now})
	s.records++
	s.c.Puts++
	return PutStored
}

func (s *Store) fetch(id [IDSize]byte, out *[RecordSize]byte, now time.Time) bool {
	s.c.Fetches++
	q := s.queues[id]
	if q == nil {
		return false
	}
	q.active = now
	s.byActive.MoveToBack(q.elem)
	s.expireHead(q, now)
	if len(q.records) == 0 {
		return false
	}
	*out = *q.records[0].data
	s.removeHead(q)
	s.c.Hits++
	return true
}

func (s *Store) held(q *queue, now time.Time) bool {
	return now.Sub(q.active) < s.lim.TTL
}

func (s *Store) expired(r record, now time.Time) bool {
	return now.Sub(r.at) >= s.lim.TTL
}

func (s *Store) expireHead(q *queue, now time.Time) {
	for len(q.records) > 0 && s.expired(q.records[0], now) {
		s.removeHead(q)
		s.c.Expired++
	}
}

func (s *Store) removeHead(q *queue) {
	clear(q.records[0].data[:])
	n := copy(q.records, q.records[1:])
	q.records[n] = record{}
	q.records = q.records[:n]
	s.records--
}

func (s *Store) drop(q *queue) {
	for _, r := range q.records {
		clear(r.data[:])
	}
	s.records -= len(q.records)
	q.records = nil
	s.byActive.Remove(q.elem)
	delete(s.queues, q.id)
}

// removes the expired records, the empty queues nobody holds and the bindings
// not seen within the TTL
func (s *Store) Sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, q := range s.queues {
		s.expireHead(q, now)
		if len(q.records) == 0 && !s.held(q, now) {
			s.drop(q)
		}
	}
	for e := s.bySeen.Front(); e != nil; {
		b := e.Value.(*binding)
		if now.Sub(b.seen) < s.lim.TTL {
			break
		}
		e = e.Next()
		s.unbind(b)
	}
}

// sweeps every SweepEvery until stop is closed
func (s *Store) Run(stop <-chan struct{}) {
	t := time.NewTicker(SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.Sweep(s.now())
		}
	}
}

func (s *Store) Stats() Counters {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.c
	c.Queues = uint64(len(s.queues))
	c.Records = uint64(s.records)
	c.Bindings = uint64(len(s.bindings))
	return c
}

// zeroes every record; a request that comes later gets a bad reply
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, q := range s.queues {
		s.drop(q)
	}
	for _, b := range s.bindings {
		s.unbind(b)
	}
	s.closed = true
}
