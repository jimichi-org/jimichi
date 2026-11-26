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

const (
	stoppedText = "stopped: the contact card changed, the operator restarts the client"
	keyRefused  = "the key of the card does not pass"
)

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
	// with -vault no line names a card or a role, and writer holds the draft
	// until the container is written
	vault  bool
	writer *draftWriter

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
	http.Error(w, stoppedText, http.StatusConflict)
}

func (c *contact) halted() bool { return c.stopped.Load() }

func (c *contact) card(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, c.text+"\n")
}

// a body that is no canonical card changes nothing
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
	out := c.pinCard(card)
	if !out.stop {
		reply(w, out.status, out.text)
		return
	}
	// the answer leaves before the conversation stops, which may wait for a
	// rebuild under way
	stoppedReply(w)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	c.halt()
	if c.vault {
		c.logger.Print("contact card changed, refusing")
		return
	}
	c.logger.Printf("contact card changed, refusing: pinned card_hash=%x", out.pinned)
}

type pinOutcome struct {
	status int
	text   string
	// another card after pinning: the answer goes out, then the stop
	stop   bool
	pinned []byte
}

func reply(w http.ResponseWriter, status int, text string) {
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	http.Error(w, text, status)
}

// the checks run in this order: a pinned contact takes only its own card
// again, and a first card must be another client of the same suite on the
// same mailbox whose key passes an agreement. With a draft the container is
// written before the pairing, so the throwaway session of the write and the
// session of the conversation never hold pages at once
func (c *contact) pinCard(card e2e.Card) pinOutcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped.Load() {
		return pinOutcome{status: http.StatusConflict, text: stoppedText}
	}
	if c.pinned != nil {
		if !bytes.Equal(card.Bytes(), c.pinned) {
			c.stopped.Store(true)
			return pinOutcome{stop: true, pinned: c.pinHash}
		}
		if c.writer != nil {
			if status, text := c.writer.again(); status != 0 {
				return pinOutcome{status: status, text: text}
			}
		}
		return pinOutcome{status: http.StatusNoContent}
	}
	switch {
	case card.Suite != c.own.Suite:
		return pinOutcome{status: http.StatusBadRequest, text: "the card is of another suite"}
	case card.Mailbox != c.own.Mailbox:
		return pinOutcome{status: http.StatusBadRequest, text: "the card names another mailbox"}
	case bytes.Equal(card.Static, c.own.Static) || card.Queue == c.own.Queue:
		return pinOutcome{status: http.StatusBadRequest, text: "the card is this client's own"}
	}
	hash, err := e2e.CardHash(c.p, card)
	if err != nil {
		return pinOutcome{status: http.StatusBadRequest, text: "not a contact card"}
	}
	written := pinOutcome{status: http.StatusNoContent}
	if c.writer != nil {
		status, text, pin := c.writer.first(card)
		if !pin {
			return pinOutcome{status: status, text: text}
		}
		if status != 0 {
			written = pinOutcome{status: status, text: text}
		}
	}
	if err := c.conv.Pair(card); err != nil {
		if errors.Is(err, e2e.ErrCard) || errors.Is(err, e2e.ErrSelf) {
			return pinOutcome{status: http.StatusBadRequest, text: keyRefused}
		}
		return pinOutcome{status: http.StatusServiceUnavailable, text: "the conversation has ended"}
	}
	c.pinned, c.pinHash, c.pinnedAt = card.Bytes(), hash, c.now()
	if c.vault {
		c.logger.Print("contact pinned")
	} else {
		role := e2e.RoleResponder
		if bytes.Compare(c.own.Static, card.Static) < 0 {
			role = e2e.RoleInitiator
		}
		c.logger.Printf("contact pinned card_hash=%x role=%s", hash, role)
	}
	close(c.paired)
	return written
}

// since when the pinned contact has been silent, false before the pin
func (c *contact) silence(st conversation.Stats) (time.Duration, bool) {
	c.mu.Lock()
	pinned, since := c.pinHash, c.pinnedAt
	c.mu.Unlock()
	if pinned == nil {
		return 0, false
	}
	if st.LastOpened.After(since) {
		since = st.LastOpened
	}
	return c.now().Sub(since), true
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
