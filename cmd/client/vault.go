package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jimichi-org/jimichi/conversation"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/vault"
	"github.com/jimichi-org/jimichi/vault/profile"
)

const (
	// two blocks of a password and a card line fit with room to spare
	maxInitBody = 2 << 10
	// one password line and its CR LF
	maxUnlockBody = jcrypto.PasswordMax + 2
)

// the lines of the refusals are also the bodies of the answers: fixed
// classes, never the text of an error, since the vault errors name the path
const (
	lineNoVolume = "vault: no volume opens with this password"
	lineMailbox  = "vault: the volume does not fit this client: mailbox"
	lineContact  = "vault: the volume does not fit this client: contact"
	lineCorrupt  = "vault: the volume is corrupt"
	lineMemory   = "vault: not opened: memory"
	lineIO       = "vault: not opened: io"
	lineNotVault = "the vault file is not a vault"
	notWritten   = "vault: not written: "
)

// replaced in tests to fail as a drive fails
var writeDraft = (*vault.Draft).Write

type vaultState int

const (
	lockedNoFile vaultState = iota
	lockedFile
	// an init or an unlock in flight, up to the pin of the contact
	opening
	running
)

// a -peer client with -vault: locked until an init or an unlock opens a
// volume, then the client of the volume's identity
func runVaultPeer(set *peerSetup, f peerFlags, logger *log.Logger, stop <-chan os.Signal) int {
	if err := vault.Clean(f.vault); err != nil {
		logger.Print("the leftover of a vault creation could not be removed")
		return 1
	}
	exists, err := vaultFileExists(f.vault)
	if err != nil {
		logger.Print(err)
		return 1
	}
	va := newVaultAdmin(set.p, f, logger, exists)
	ln, err := net.Listen("tcp", f.admin)
	if err != nil {
		logger.Printf("admin: %v", err)
		return 1
	}
	srv := &http.Server{Handler: va.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
	defer srv.Close()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Printf("admin: %v", err)
		}
	}()
	logger.Printf("admin listening on %s", ln.Addr())
	logger.Print("vault locked")

	var req *handover
	select {
	case <-stop:
		logger.Print("shutting down")
		_ = srv.Close()
		va.drain()
		return 0
	case req = <-va.opened:
	}

	r := peerRoute(set, f, logger)
	first, err := r.first()
	if err != nil {
		logger.Printf("refusing to build the circuit: %s", peerCause(err))
		req.release()
		req.done <- openResult{http.StatusServiceUnavailable, "the circuit could not be built"}
		_ = srv.Close()
		va.drain()
		return 1
	}
	logger.Printf("circuit of %d hops among %d listed nodes to the mailbox, request period %v", f.hops, len(set.addrs), f.rate)
	l, err := va.attach(req, first, r.rebuild)
	if err != nil {
		logger.Printf("conversation: %v", err)
		_ = srv.Close()
		va.drain()
		return 1
	}
	code := serve(l.conv, l.ct, l.tk, logger, stop, false)
	_ = srv.Close()
	va.drain()
	l.release()
	return code
}

// a file that is there must be a container, or no password could open it
func vaultFileExists(path string) (bool, error) {
	st, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, errors.New("the vault file cannot be read")
	case !st.Mode().IsRegular() || st.Size() != vault.FileSize:
		return false, errors.New(lineNotVault)
	}
	return true, nil
}

// what an init or an unlock hands to the start of the conversation; the
// handover owns the profile and the draft until attach takes them
type handover struct {
	pr     *profile.Profile
	writer *draftWriter
	// the contact pinned once the conversation runs, and the answer of a
	// write that failed before the chain
	pin   *e2e.Card
	wrote openResult
	done  chan openResult
}

type openResult struct {
	status int
	text   string
}

func (o *handover) release() {
	o.pr.Close()
	if o.writer != nil {
		o.writer.close()
	}
}

// what a running client holds; release goes in the order of the
// conversation, the identity and F, the draft
type live struct {
	conv   *conversation.Conversation
	id     *e2e.Identity
	pr     *profile.Profile
	writer *draftWriter
	ct     *contact
	tk     *talk
}

func (l *live) release() {
	l.conv.Close()
	l.id.Close()
	l.pr.Close()
	if l.writer != nil {
		l.writer.close()
	}
}

type vaultAdmin struct {
	p      jcrypto.CryptoProvider
	f      peerFlags
	logger *log.Logger
	now    func() time.Time

	mu      sync.Mutex
	state   vaultState
	closing bool
	ops     sync.WaitGroup

	live      atomic.Pointer[live]
	opened    chan *handover
	quit      chan struct{}
	closeOnce sync.Once
}

func newVaultAdmin(p jcrypto.CryptoProvider, f peerFlags, logger *log.Logger, exists bool) *vaultAdmin {
	va := &vaultAdmin{p: p, f: f, logger: logger, now: time.Now, opened: make(chan *handover), quit: make(chan struct{})}
	if exists {
		va.state = lockedFile
	}
	return va
}

func (va *vaultAdmin) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /vault/init", va.initVault)
	mux.HandleFunc("PUT /vault/unlock", va.unlockVault)
	mux.HandleFunc("GET /card", va.whenRunning(func(l *live, w http.ResponseWriter, r *http.Request) { l.ct.card(w, r) }))
	mux.HandleFunc("PUT /contact", va.whenRunning(func(l *live, w http.ResponseWriter, r *http.Request) { l.ct.pin(w, r) }))
	mux.HandleFunc("GET /status", va.whenRunning(va.status))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !va.enter() {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		defer va.ops.Done()
		if l := va.live.Load(); l != nil && l.ct.halted() {
			stoppedReply(w)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// every request in flight is counted, so the keys it holds are released
// before the process returns
func (va *vaultAdmin) enter() bool {
	va.mu.Lock()
	defer va.mu.Unlock()
	if va.closing {
		return false
	}
	va.ops.Add(1)
	return true
}

func (va *vaultAdmin) drain() {
	va.mu.Lock()
	va.closing = true
	va.mu.Unlock()
	va.closeOnce.Do(func() { close(va.quit) })
	va.ops.Wait()
}

func (va *vaultAdmin) whenRunning(h func(*live, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l := va.live.Load()
		if l == nil {
			http.Error(w, "locked: no volume is open", http.StatusServiceUnavailable)
			return
		}
		h(l, w, r)
	}
}

// one init or unlock at a time, and only in the state it opens from
func (va *vaultAdmin) begin(w http.ResponseWriter, from vaultState) bool {
	va.mu.Lock()
	defer va.mu.Unlock()
	switch va.state {
	case opening:
		http.Error(w, "another init or unlock is under way", http.StatusTooManyRequests)
		return false
	case from:
		va.state = opening
		return true
	case running:
		http.Error(w, "a volume is open already", http.StatusConflict)
	case lockedNoFile:
		http.Error(w, "no container yet: PUT /vault/init creates one", http.StatusConflict)
	default:
		http.Error(w, "the container exists: PUT /vault/unlock opens it", http.StatusConflict)
	}
	return false
}

func (va *vaultAdmin) set(s vaultState) {
	va.mu.Lock()
	va.state = s
	va.mu.Unlock()
}

func (va *vaultAdmin) initVault(w http.ResponseWriter, r *http.Request) {
	if !va.begin(w, lockedNoFile) {
		return
	}
	status, text, req := va.prepare(r)
	if req == nil {
		va.set(lockedNoFile)
		reply(w, status, text)
		return
	}
	va.handOver(w, req, lockedNoFile)
}

func (va *vaultAdmin) unlockVault(w http.ResponseWriter, r *http.Request) {
	if !va.begin(w, lockedFile) {
		return
	}
	status, text, req := va.open(r)
	if req == nil {
		va.set(lockedFile)
		reply(w, status, text)
		return
	}
	va.handOver(w, req, lockedFile)
}

// the answer waits for the conversation, and for an unlock for its pin
func (va *vaultAdmin) handOver(w http.ResponseWriter, req *handover, back vaultState) {
	select {
	case va.opened <- req:
	case <-va.quit:
		req.release()
		va.set(back)
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	res := <-req.done
	reply(w, res.status, res.text)
}

func (va *vaultAdmin) refuse(status int, line string) (int, string, *handover) {
	va.logger.Print(line)
	return status, line, nil
}

// Prepare, then Take: the identity moves into the profile at once, and the
// draft keeps only the key and the content of the first volume
func (va *vaultAdmin) prepare(r *http.Request) (int, string, *handover) {
	body, status, text := readBody(r, maxInitBody)
	if body == nil {
		return status, text, nil
	}
	defer forget(body)
	blocks, text := parseInit(body, va.p.Suite(), va.f.mailbox)
	if blocks == nil {
		return http.StatusBadRequest, text, nil
	}
	volumes := make([]vault.Contents, 0, len(blocks))
	defer func() {
		for _, v := range volumes {
			v.Password.Release()
		}
	}()
	for _, b := range blocks {
		pw, err := secmem.NewFrom(b.password)
		if err != nil {
			return va.refuse(http.StatusInternalServerError, lineMemory)
		}
		volumes = append(volumes, vault.Contents{Password: pw, Fill: profile.New(va.p, va.f.mailbox, b.card)})
	}
	d, err := vault.Prepare(va.p, volumes...)
	for _, v := range volumes {
		v.Password.Release()
	}
	if err != nil {
		return va.initRefusal(err)
	}
	priv, pub, fetch := d.Identity().Take()
	if priv == nil || fetch == nil {
		if priv != nil {
			priv.Release()
		}
		if fetch != nil {
			fetch.Release()
		}
		d.Close()
		return va.refuse(http.StatusInternalServerError, lineIO)
	}
	pr := &profile.Profile{Pair: noise.NewKeyPair(va.p, priv, pub), Fetch: fetch}
	own, err := ownCard(va.p, pub, fetch, va.f.mailbox)
	if err != nil {
		pr.Close()
		d.Close()
		return va.refuse(http.StatusInternalServerError, lineIO)
	}
	pr.Card = own
	va.logger.Print("vault opened")

	w := &draftWriter{p: va.p, path: va.f.vault, own: own, logger: va.logger, draft: d}
	req := &handover{pr: pr, writer: w, done: make(chan openResult, 1)}
	if card := blocks[0].card; card != nil {
		// New checked this card in Prepare, so the container is written before
		// the chain: a client that exits there still has its contact
		w.filled = true
		req.pin = card
		if status, text := w.again(); status != 0 {
			req.wrote = openResult{status, text}
		}
	}
	return 0, "", req
}

func (va *vaultAdmin) initRefusal(err error) (int, string, *handover) {
	switch {
	case errors.Is(err, vault.ErrSamePassword):
		return http.StatusBadRequest, "two blocks under one password", nil
	case errors.Is(err, jcrypto.ErrBadPassword):
		return http.StatusBadRequest, badPassword, nil
	case errors.Is(err, e2e.ErrCard), errors.Is(err, e2e.ErrSelf):
		return http.StatusBadRequest, keyRefused, nil
	case memoryError(err):
		return va.refuse(http.StatusInternalServerError, lineMemory)
	}
	return va.refuse(http.StatusInternalServerError, lineIO)
}

// Open, Parse, Fit and the contact's key, all before any circuit: a volume
// this client cannot run leaves it locked with every key released
func (va *vaultAdmin) open(r *http.Request) (int, string, *handover) {
	body, status, text := readBody(r, maxUnlockBody)
	if body == nil {
		return status, text, nil
	}
	defer forget(body)
	lines, ok := splitLines(body)
	if !ok || len(lines) != 1 || !jcrypto.ValidPassword(lines[0]) {
		return http.StatusBadRequest, "want one line, the password of a volume: " + badPassword, nil
	}
	pw, err := secmem.NewFrom(lines[0])
	if err != nil {
		return va.refuse(http.StatusInternalServerError, lineMemory)
	}
	v, err := vault.Open(va.p, va.f.vault, pw)
	pw.Release()
	if err != nil {
		return va.refuse(unlockClass(err))
	}
	pr, err := profile.Parse(va.p, v)
	v.Close()
	if err != nil {
		return va.refuse(unlockClass(err))
	}
	if err := pr.Fit(va.f.mailbox); err != nil {
		pr.Close()
		return va.refuse(http.StatusConflict, lineMailbox)
	}
	if err := contactPasses(va.p, pr); err != nil {
		pr.Close()
		if errors.Is(err, e2e.ErrCard) || errors.Is(err, e2e.ErrSelf) {
			return va.refuse(http.StatusConflict, lineContact)
		}
		return va.refuse(unlockClass(err))
	}
	va.logger.Print("vault opened")
	contact := pr.Contact
	return 0, "", &handover{pr: pr, pin: &contact, done: make(chan openResult, 1)}
}

// the check of conv.Pair, run before the chain so that a refusal leaves the
// client locked
func contactPasses(p jcrypto.CryptoProvider, pr *profile.Profile) error {
	id, err := pr.Identity(p)
	if err != nil {
		return err
	}
	defer id.Close()
	s, err := e2e.NewSession(p, id, pr.Contact, e2e.Options{})
	if err != nil {
		return err
	}
	s.Close()
	return nil
}

func unlockClass(err error) (int, string) {
	switch {
	case errors.Is(err, vault.ErrNoVolume):
		return http.StatusForbidden, lineNoVolume
	case errors.Is(err, vault.ErrCorrupt), errors.Is(err, e2e.ErrCard):
		return http.StatusConflict, lineCorrupt
	case memoryError(err):
		return http.StatusInternalServerError, lineMemory
	}
	return http.StatusInternalServerError, lineIO
}

func memoryError(err error) bool {
	return errors.Is(err, secmem.ErrNotMapped) || errors.Is(err, secmem.ErrNotLocked)
}

// the conversation of an opened volume: the contact pins before the client
// takes any request of the running state
func (va *vaultAdmin) attach(req *handover, first conversation.Circuit, dial func() (conversation.Circuit, error)) (*live, error) {
	fail := func(err error) (*live, error) {
		_ = first.Close()
		req.release()
		req.done <- openResult{http.StatusServiceUnavailable, "the conversation did not start"}
		return nil, err
	}
	id, err := req.pr.Identity(va.p)
	if err != nil {
		return fail(err)
	}
	conv, err := startConversation(va.p, va.f, va.logger, id, req.pr.Fetch, first, dial)
	if err != nil {
		return fail(err)
	}
	own := id.Card()
	l := &live{conv: conv, id: id, pr: req.pr, writer: req.writer}
	l.ct = &contact{
		p: va.p, own: own, text: own.String(), conv: conv, logger: va.logger, now: va.now,
		paired: make(chan struct{}), halt: l.release, vault: true, writer: req.writer,
	}
	l.tk = newTalk(conv, va.f, va.logger, true)
	res := openResult{status: http.StatusNoContent}
	if req.pin != nil {
		out := l.ct.pinCard(*req.pin)
		switch {
		case out.status != http.StatusNoContent:
			res = openResult{out.status, out.text}
		case req.wrote.status != 0:
			res = req.wrote
		}
	}
	va.live.Store(l)
	va.set(running)
	req.done <- res
	return l, nil
}

type statusReply struct {
	State              string  `json:"state"`
	Requests           uint64  `json:"requests"`
	Puts               uint64  `json:"puts"`
	PutRefused         uint64  `json:"put_refused"`
	WindowFull         uint64  `json:"window_full"`
	Hits               uint64  `json:"hits"`
	Sent               uint64  `json:"sent"`
	Received           uint64  `json:"received"`
	DummiesSent        uint64  `json:"dummies_sent"`
	DummiesReceived    uint64  `json:"dummies_received"`
	Copies             uint64  `json:"copies"`
	Late               uint64  `json:"late"`
	Lost               uint64  `json:"lost"`
	Window             uint64  `json:"window"`
	Bad                uint64  `json:"bad"`
	BadReplies         uint64  `json:"bad_replies"`
	Handshakes         uint64  `json:"handshakes"`
	RefusedHandshakes  uint64  `json:"refused_handshakes"`
	ReplayedHandshakes uint64  `json:"replayed_handshakes"`
	Stale              uint64  `json:"stale"`
	Rebuilds           uint64  `json:"rebuilds"`
	Refusals           uint64  `json:"refusals"`
	OutboxDropped      uint64  `json:"outbox_dropped"`
	HeldDropped        uint64  `json:"held_dropped"`
	InboxDropped       uint64  `json:"inbox_dropped"`
	Unanswered         uint64  `json:"unanswered"`
	RoundTrips         uint64  `json:"round_trips"`
	LastRoundTripAt    string  `json:"last_round_trip_at,omitempty"`
	LastRoundTrip      string  `json:"last_round_trip,omitempty"`
	SilentFor          *uint64 `json:"silent_for,omitempty"`
}

// the counters of the minute line and the round trips, which with -vault
// reach no line of the log
func (va *vaultAdmin) status(l *live, w http.ResponseWriter, _ *http.Request) {
	st := l.conv.Stats()
	s := st.Session
	out := statusReply{
		State:    "unpaired",
		Requests: st.Requests, Puts: st.Puts, PutRefused: st.PutRefused, WindowFull: st.WindowFull, Hits: st.Hits,
		Sent: s.Sent, Received: s.Received, DummiesSent: s.DummiesSent, DummiesReceived: s.DummiesReceived,
		Copies: s.Copies, Late: s.Late, Lost: s.Lost, Window: s.Window, Bad: s.Bad,
		BadReplies: st.BadReplies, Handshakes: s.Handshakes, RefusedHandshakes: s.RefusedHandshakes,
		ReplayedHandshakes: s.ReplayedHandshakes, Stale: s.Stale,
		Rebuilds: st.Rebuilds, Refusals: st.Refusals, OutboxDropped: st.OutboxDropped, HeldDropped: st.HeldDropped,
		InboxDropped: st.InboxDropped, Unanswered: st.Unanswered,
		RoundTrips: l.tk.trips.Load(),
	}
	if st.Paired {
		out.State = st.State.String()
	}
	if out.RoundTrips > 0 {
		out.LastRoundTripAt = time.Unix(0, l.tk.lastAt.Load()).UTC().Format(time.RFC3339Nano)
		out.LastRoundTrip = time.Duration(l.tk.lastTook.Load()).String()
	}
	if silent, ok := l.ct.silence(st); ok {
		secs := uint64(max(silent, 0) / time.Second)
		out.SilentFor = &secs
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// the draft of a container created by init, until its only write
type draftWriter struct {
	p      jcrypto.CryptoProvider
	path   string
	own    e2e.Card
	logger *log.Logger

	mu    sync.Mutex
	draft *vault.Draft
	// the content holds a card, so a retry writes it as it is
	filled bool
}

// the write before the first pin: pin says whether the pin goes on, and a
// status other than 0 is the answer once it has
func (w *draftWriter) first(card e2e.Card) (status int, text string, pin bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.draft == nil || w.filled {
		return 0, "", true
	}
	inner := profile.WithContact(w.p, w.own, card)
	filled := false
	err := writeDraft(w.draft, w.path, func(id *vault.Identity, buf []byte) (int, error) {
		n, err := inner(id, buf)
		filled = err == nil
		return n, err
	})
	if !filled {
		if errors.Is(err, e2e.ErrCard) || errors.Is(err, e2e.ErrSelf) {
			return http.StatusBadRequest, keyRefused, false
		}
		status, text := w.failed(err)
		return status, text, false
	}
	w.filled = true
	if err != nil {
		status, text := w.failed(err)
		return status, text, true
	}
	w.written()
	return 0, "", true
}

// the same content again, after a write that failed
func (w *draftWriter) again() (int, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.draft == nil {
		return 0, ""
	}
	if err := writeDraft(w.draft, w.path, nil); err != nil {
		return w.failed(err)
	}
	w.written()
	return 0, ""
}

func (w *draftWriter) written() {
	w.draft.Close()
	w.draft = nil
	w.logger.Print("vault written")
}

// a failure after the link spent the draft; the file goes, as with jimichi
// vault init, so the pin holds for the process only and a restart finds no
// container
func (w *draftWriter) failed(err error) (int, string) {
	class := writeClass(err)
	if class == "sync" {
		_ = os.Remove(w.path)
		_ = vault.Clean(w.path)
		w.draft.Close()
		w.draft = nil
	}
	w.logger.Print(notWritten + class)
	return http.StatusInternalServerError, notWritten + class
}

func (w *draftWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.draft != nil {
		w.draft.Close()
		w.draft = nil
	}
}

func writeClass(err error) string {
	var link *os.LinkError
	switch {
	case errors.Is(err, vault.ErrWritten):
		return "sync"
	case memoryError(err):
		return "memory"
	case errors.Is(err, vault.ErrExists), errors.As(err, &link):
		return "link"
	}
	return "write"
}

// the formula of the own card in vault/profile, for an identity taken from a
// draft whose volume holds no contact yet
func ownCard(p jcrypto.CryptoProvider, pub []byte, fetch *secmem.Buffer, addr string) (e2e.Card, error) {
	queue, err := mailbox.QueueID(p, fetch.Bytes())
	if err != nil {
		return e2e.Card{}, err
	}
	c := e2e.Card{Suite: p.Suite(), Mailbox: addr, Queue: queue, Static: pub}
	return e2e.DecodeCard(c.Bytes())
}

var badPassword = fmt.Sprintf("1 to %d bytes without NUL and CR", jcrypto.PasswordMax)

type initBlock struct {
	password []byte
	card     *e2e.Card
}

// every formal check of a card comes before the first stretch; its key and
// whether it is the client's own need the identity, which only the stretch
// gives
func parseInit(body []byte, s jcrypto.Suite, addr string) ([]initBlock, string) {
	lines, ok := splitLines(body)
	if !ok || (len(lines) != 2 && len(lines) != 4) {
		return nil, "want one or two blocks, each a password line and a card line"
	}
	blocks := make([]initBlock, 0, 2)
	for i := 0; i < len(lines); i += 2 {
		n := i/2 + 1
		b := initBlock{password: lines[i]}
		if !jcrypto.ValidPassword(b.password) {
			return nil, fmt.Sprintf("block %d: the password: want %s", n, badPassword)
		}
		if len(lines[i+1]) == 0 {
			if n > 1 {
				return nil, "block 2: no card: a second volume holds its contact from the start"
			}
			blocks = append(blocks, b)
			continue
		}
		card, err := e2e.ParseCard(string(lines[i+1]))
		switch {
		case err != nil:
			return nil, fmt.Sprintf("block %d: not a contact card", n)
		case card.Suite != s:
			return nil, fmt.Sprintf("block %d: the card is of another suite", n)
		case card.Mailbox != addr:
			return nil, fmt.Sprintf("block %d: the card names another mailbox", n)
		}
		b.card = &card
		blocks = append(blocks, b)
	}
	if len(blocks) == 2 && blocks[0].card != nil {
		a, b := blocks[0].card, blocks[1].card
		if bytes.Equal(a.Static, b.Static) || a.Queue == b.Queue {
			return nil, "block 2: the key or the queue of the card of block 1: a contact belongs to one volume"
		}
	}
	return blocks, ""
}

// every line ends in LF or CR LF, the last one too
func splitLines(body []byte) ([][]byte, bool) {
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return nil, false
	}
	lines := bytes.Split(body[:len(body)-1], []byte{'\n'})
	for i, l := range lines {
		lines[i] = bytes.TrimSuffix(l, []byte{'\r'})
	}
	return lines, true
}

// into one buffer of a fixed size, so the passwords leave no copies in the
// arrays a growing read would drop
func readBody(r *http.Request, limit int) ([]byte, int, string) {
	buf := make([]byte, limit+1)
	n, err := io.ReadFull(r.Body, buf)
	switch {
	case err == nil:
		forget(buf)
		return nil, http.StatusRequestEntityTooLarge, fmt.Sprintf("the body is longer than %d bytes", limit)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return buf[:n], 0, ""
	}
	forget(buf)
	return nil, http.StatusBadRequest, "the body did not arrive"
}

// the body held passwords; under -keymem without zero it stays as it is, so
// the measure can be measured
func forget(b []byte) {
	if secmem.CurrentPolicy().Zero {
		clear(b[:cap(b)])
	}
}
