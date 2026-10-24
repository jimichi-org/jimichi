package verify

import (
	"bytes"
	"slices"
	"time"

	"github.com/jimichi-org/jimichi/pki"
)

// epochs a record holds at most; with the admission rule and a pass period of
// a minute at most four pairwise consistent epochs can be live at once, so
// the guard is memory, not the rule
const MaxEpochs = 8

type statement struct {
	bundle []byte
	v      *pki.Verified
}

// what one epoch has shown: the statements that matter to the rules are the
// earliest and the latest published and the one that ends last
type epochSeen struct {
	first, last, longest *statement
}

func (e *epochSeen) each(visit func(*statement) bool) bool {
	seen := map[*statement]bool{}
	for _, s := range []*statement{e.first, e.last, e.longest} {
		if seen[s] {
			continue
		}
		seen[s] = true
		if !visit(s) {
			return false
		}
	}
	return true
}

// Record is what one node has shown of itself, bounded, and the pair that
// breaks a rule once one has. Public data: bundles the node signed
type Record struct {
	skew        time.Duration
	forgetAfter time.Duration
	// the first statement ever, kept so a change of identity, certificate or
	// link key shows after every epoch has been forgotten
	first   *statement
	epochs  map[uint32]*epochSeen
	held    uint32
	holding bool
	refused *pki.Conflict
}

// skew bounds how far ahead of now a statement may be published and still be
// recorded; forgetAfter is how long past its expiry an epoch is kept beyond
// skew, so a proof against it has time to reach every node
func NewRecord(skew, forgetAfter time.Duration) *Record {
	return &Record{skew: skew, forgetAfter: forgetAfter, epochs: make(map[uint32]*epochSeen)}
}

func (r *Record) Refused() *pki.Conflict { return r.refused }

// Hold names the epoch of the entry in service: neither Forget nor the guard
// on the number of epochs drops it
func (r *Record) Hold(epoch uint32) {
	r.held, r.holding = epoch, true
}

// Take adds a statement already checked with pki.VerifyStatement at the
// node's address and returns the conflict it makes with what is held,
// remembering it, or nil, and whether the statement was admitted: one
// published more than skew after now is not, since a set of consistent
// statements from the future could otherwise push the live epoch out of the
// record. Once refused, every Take returns the conflict
func (r *Record) Take(bundle []byte, v *pki.Verified, now time.Time) (*pki.Conflict, bool) {
	if r.refused != nil {
		return r.refused, false
	}
	if v.DescFrom.After(now.Add(r.skew)) {
		return nil, false
	}
	return r.admit(bundle, v), true
}

// TakeProof admits both bundles of a conflict VerifyConflict accepted,
// whatever their times, and returns the conflict the record holds afterwards
func (r *Record) TakeProof(c *pki.Conflict, a, b *pki.Verified) *pki.Conflict {
	if r.refused != nil {
		return r.refused
	}
	if found := r.admit(c.Proof.A, a); found != nil {
		return found
	}
	if found := r.admit(c.Proof.B, b); found != nil {
		return found
	}
	r.refused = c
	return r.refused
}

func (r *Record) admit(bundle []byte, v *pki.Verified) *pki.Conflict {
	s := &statement{bundle: bytes.Clone(bundle), v: v}
	var against *statement
	r.each(func(h *statement) bool {
		if pki.Compare(h.v, v) != 0 {
			against = h
			return false
		}
		return true
	})
	if against != nil {
		proof, err := pki.NewProof(against.bundle, bundle)
		if err != nil {
			// equal bytes never break a rule with themselves
			return nil
		}
		r.refused = &pki.Conflict{Addr: v.Addr, Rule: pki.Compare(against.v, v), Proof: *proof}
		return r.refused
	}
	r.store(s)
	return nil
}

// epochs in ascending order, so the pair a conflict names is the same at
// every node that holds the same statements
func (r *Record) each(visit func(*statement) bool) {
	if r.first != nil && !visit(r.first) {
		return
	}
	epochs := make([]uint32, 0, len(r.epochs))
	for epoch := range r.epochs {
		epochs = append(epochs, epoch)
	}
	slices.Sort(epochs)
	for _, epoch := range epochs {
		if !r.epochs[epoch].each(visit) {
			return
		}
	}
}

func (r *Record) store(s *statement) {
	if r.first == nil {
		r.first = s
	}
	e := r.epochs[s.v.Epoch]
	if e == nil {
		r.epochs[s.v.Epoch] = &epochSeen{first: s, last: s, longest: s}
		r.guard()
		return
	}
	if s.v.DescFrom.Before(e.first.v.DescFrom) {
		e.first = s
	}
	if s.v.DescFrom.After(e.last.v.DescFrom) {
		e.last = s
	}
	if s.v.DescUntil.After(e.longest.v.DescUntil) {
		e.longest = s
	}
}

// the smallest epoch other than the held one goes once a ninth arrives
func (r *Record) guard() {
	for len(r.epochs) > MaxEpochs {
		var smallest uint32
		found := false
		for epoch := range r.epochs {
			if r.holding && epoch == r.held {
				continue
			}
			if !found || epoch < smallest {
				smallest, found = epoch, true
			}
		}
		if !found {
			return
		}
		delete(r.epochs, smallest)
	}
}

// Forget drops the epochs whose longest statement expired skew plus
// forgetAfter ago or earlier: a descriptor expired for every clock opens no
// setup, and the allowance lets a proof against it reach every node first
func (r *Record) Forget(now time.Time) {
	for epoch, e := range r.epochs {
		if r.holding && epoch == r.held {
			continue
		}
		if !now.Before(e.longest.v.DescUntil.Add(r.skew + r.forgetAfter)) {
			delete(r.epochs, epoch)
		}
	}
}

// Epochs reports how many epochs the record holds
func (r *Record) Epochs() int { return len(r.epochs) }

// Newer reports whether b is a later statement of a node than a: a greater
// epoch, or the same epoch published later
func Newer(a, b *pki.Verified) bool {
	return b.Epoch > a.Epoch || b.Epoch == a.Epoch && b.DescFrom.After(a.DescFrom)
}
