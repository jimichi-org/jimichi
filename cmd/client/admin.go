package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/e2e"
)

// a card is under 200 bytes of text; nothing larger is read
const maxContactBody = 1 << 10

type pairing interface {
	Pair(e2e.Card) error
}

// the contact of a -peer client on its loopback admin port: GET /card hands
// out this client's card, PUT /contact pins the contact's. Another card after
// pinning stops the client for good: the conversation and every key go, and
// every request is answered 409 until the operator restarts the process, since
// a restart by the orchestrator would open a new window of trust on first use
type contact struct {
	p      jcrypto.CryptoProvider
	own    e2e.Card
	text   string
	conv   pairing
	logger *log.Logger
	now    func() time.Time
	// closed once the contact is pinned
	paired chan struct{}
	// closes the conversation and releases the identity and F
	halt func()

	stopped atomic.Bool

	mu       sync.Mutex
	pinned   []byte
	pinHash  []byte
	pinnedAt time.Time
}

func (c *contact) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /card", c.card)
	mux.HandleFunc("PUT /contact", c.pin)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.stopped.Load() {
			stoppedReply(w)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func stoppedReply(w http.ResponseWriter) {
	http.Error(w, "stopped: the contact card changed, the operator restarts the client", http.StatusConflict)
}

func (c *contact) halted() bool { return c.stopped.Load() }

func (c *contact) card(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, c.text+"\n")
}

// the checks run in this order: a body that is no canonical card changes
// nothing, a pinned contact takes only its own card again, and a first card
// must be another client of the same suite on the same mailbox whose key
// passes an agreement
func (c *contact) pin(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxContactBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "the body is larger than a card", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "the body did not arrive", http.StatusBadRequest)
		return
	}
	card, err := e2e.ParseCard(strings.TrimSuffix(string(raw), "\n"))
	if err != nil {
		http.Error(w, "not a contact card", http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	if c.stopped.Load() {
		c.mu.Unlock()
		stoppedReply(w)
		return
	}
	if c.pinned != nil {
		same := bytes.Equal(card.Bytes(), c.pinned)
		if !same {
			c.stopped.Store(true)
		}
		pinned := c.pinHash
		c.mu.Unlock()
		if same {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// the answer leaves before the conversation stops, which may wait for a
		// rebuild under way
		stoppedReply(w)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		c.halt()
		c.logger.Printf("contact card changed, refusing: pinned card_hash=%x", pinned)
		return
	}
	defer c.mu.Unlock()
	switch {
	case card.Suite != c.own.Suite:
		http.Error(w, "the card is of another suite", http.StatusBadRequest)
		return
	case card.Mailbox != c.own.Mailbox:
		http.Error(w, "the card names another mailbox", http.StatusBadRequest)
		return
	case bytes.Equal(card.Static, c.own.Static) || card.Queue == c.own.Queue:
		http.Error(w, "the card is this client's own", http.StatusBadRequest)
		return
	}
	hash, err := e2e.CardHash(c.p, card)
	if err != nil {
		http.Error(w, "not a contact card", http.StatusBadRequest)
		return
	}
	if err := c.conv.Pair(card); err != nil {
		if errors.Is(err, e2e.ErrCard) || errors.Is(err, e2e.ErrSelf) {
			http.Error(w, "the key of the card does not pass", http.StatusBadRequest)
			return
		}
		http.Error(w, "the conversation has ended", http.StatusServiceUnavailable)
		return
	}
	c.pinned, c.pinHash, c.pinnedAt = card.Bytes(), hash, c.now()
	role := e2e.RoleResponder
	if bytes.Compare(c.own.Static, card.Static) < 0 {
		role = e2e.RoleInitiator
	}
	c.logger.Printf("contact pinned card_hash=%x role=%s", hash, role)
	close(c.paired)
	w.WriteHeader(http.StatusNoContent)
}

// the line of every minute; a peer silent for longer than a minute gets a line
// of its own, since a contact restarted with a new identity needs the operator
func (c *contact) report(st conversation.Stats) {
	state := "unpaired"
	switch {
	case c.stopped.Load():
		state = "stopped"
	case st.Paired:
		state = st.State.String()
	}
	s := st.Session
	c.logger.Printf("e2e state=%s requests=%d puts=%d put_refused=%d window_full=%d hits=%d"+
		" sent=%d received=%d dummies_sent=%d dummies_received=%d copies=%d late=%d lost=%d window=%d bad=%d"+
		" bad_replies=%d handshakes=%d refused_handshakes=%d replayed_handshakes=%d stale=%d"+
		" rebuilds=%d refusals=%d outbox_dropped=%d held_dropped=%d inbox_dropped=%d unanswered=%d",
		state, st.Requests, st.Puts, st.PutRefused, st.WindowFull, st.Hits,
		s.Sent, s.Received, s.DummiesSent, s.DummiesReceived, s.Copies, s.Late, s.Lost, s.Window, s.Bad,
		st.BadReplies, s.Handshakes, s.RefusedHandshakes, s.ReplayedHandshakes, s.Stale,
		st.Rebuilds, st.Refusals, st.OutboxDropped, st.HeldDropped, st.InboxDropped, st.Unanswered)
	if c.stopped.Load() {
		return
	}
	c.mu.Lock()
	pinned, since := c.pinHash, c.pinnedAt
	c.mu.Unlock()
	if pinned == nil {
		return
	}
	if st.LastOpened.After(since) {
		since = st.LastOpened
	}
	if silent := c.now().Sub(since); silent > reportEvery {
		c.logger.Printf("e2e peer not reachable for %s, pinned card_hash=%x", silent.Round(time.Second), pinned)
	}
}
