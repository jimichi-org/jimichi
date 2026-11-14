package nodeview

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/wire"
)

type providerIODelegate struct {
	jcrypto.CryptoProvider
	deriveCalls, newCalls int
	secret, key           *secmem.Buffer
	purpose               string
	context               jcrypto.Context
	size                  int
	aead                  *providerIOAEAD
}

func (p *providerIODelegate) DeriveKey(secret *secmem.Buffer, purpose string, context jcrypto.Context, size int) (*secmem.Buffer, error) {
	p.deriveCalls++
	p.secret, p.purpose, p.context, p.size = secret, purpose, context, size
	return p.CryptoProvider.DeriveKey(secret, purpose, context, size)
}

func (p *providerIODelegate) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	p.newCalls++
	p.key = key
	a, e := p.CryptoProvider.NewAEAD(key)
	if e != nil {
		return a, e
	}
	p.aead = &providerIOAEAD{AEAD: a}
	return p.aead, nil
}

type providerIOAEAD struct {
	jcrypto.AEAD
	openCalls, sealCalls, destroyCalls int
	dst, nonce, input, ad, output      []byte
	err                                error
}

func (a *providerIOAEAD) Seal(dst, nonce, plain, ad []byte) []byte {
	a.sealCalls++
	a.dst, a.nonce, a.input, a.ad = dst, nonce, plain, ad
	a.output = a.AEAD.Seal(dst, nonce, plain, ad)
	return a.output
}

func (a *providerIOAEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	a.openCalls++
	a.dst, a.nonce, a.input, a.ad = dst, nonce, ciphertext, ad
	a.output, a.err = a.AEAD.Open(dst, nonce, ciphertext, ad)
	return a.output, a.err
}

func (a *providerIOAEAD) Destroy() {
	a.destroyCalls++
	a.AEAD.Destroy()
}

func providerIOAlias(a, b []byte) bool {
	return len(a) == 0 && len(b) == 0 || len(a) > 0 && len(b) > 0 && &a[0] == &b[0]
}

func providerIONonce(size int, direction uint8, circuit, counter uint64) []byte {
	n := make([]byte, size)
	if size == 16 {
		binary.BigEndian.PutUint64(n[:8], counter|uint64(direction)<<62)
		binary.BigEndian.PutUint64(n[8:], circuit)
	} else {
		n[0] = direction
		binary.BigEndian.PutUint64(n[1:9], circuit)
		binary.BigEndian.PutUint64(n[9:17], counter)
	}
	return n
}

func TestProviderIORealSuitesDelegateExactBuffersAndErrors(t *testing.T) {
	for _, which := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(which.String(), func(t *testing.T) {
			base, e := suite.New(which)
			if e != nil {
				t.Fatal(e)
			}
			delegate := &providerIODelegate{CryptoProvider: base}
			observed := &observedProvider{CryptoProvider: delegate}
			secret, e := secmem.New(base.KeySize())
			if e != nil {
				t.Fatal(e)
			}
			defer secret.Release()
			context, e := jcrypto.NewContext(base, "provider/io", []byte("public test context"))
			if e != nil {
				t.Fatal(e)
			}
			key, e := observed.DeriveKey(secret, "setup", context, base.KeySize())
			if e != nil {
				t.Fatal(e)
			}
			defer key.Release()
			if delegate.deriveCalls != 1 || delegate.secret != secret || delegate.purpose != "setup" || delegate.context != context || delegate.size != base.KeySize() {
				t.Fatal("derivation changed arguments or count")
			}
			a, e := observed.NewAEAD(key)
			if e != nil || delegate.newCalls != 1 || delegate.key != key {
				t.Fatal("constructor changed borrowed buffer or count")
			}
			defer a.Destroy()
			if a.NonceSize() != delegate.aead.NonceSize() || a.Overhead() != delegate.aead.Overhead() {
				t.Fatal("primitive dimensions changed")
			}
			nonce := providerIONonce(a.NonceSize(), 0, 37, 19)
			plain, ad := []byte("real primitive alias witness"), []byte("public associated data")
			dst := make([]byte, 3, 128)
			copy(dst, []byte{1, 2, 3})
			ciphertext := a.Seal(dst, nonce, plain, ad)
			if delegate.aead.sealCalls != 1 || !providerIOAlias(ciphertext, dst) || !providerIOAlias(ciphertext, delegate.aead.output) || !providerIOAlias(delegate.aead.nonce, nonce) || !providerIOAlias(delegate.aead.input, plain) || !providerIOAlias(delegate.aead.ad, ad) || !bytes.Equal(ciphertext[:3], dst) {
				t.Fatal("seal changed alias, prefix, arguments or count")
			}
			body := ciphertext[3:]
			opened, e := a.Open(body[:0], nonce, body, ad)
			if e != nil || !bytes.Equal(opened, plain) || !providerIOAlias(opened, body) || !providerIOAlias(opened, delegate.aead.output) || delegate.aead.openCalls != 1 {
				t.Fatal("in-place open changed result, alias or count")
			}
			bad := a.Seal(nil, nonce, plain, ad)
			bad[len(bad)-1] ^= 1
			opened, e = a.Open(nil, nonce, bad, ad)
			if opened != nil || e != jcrypto.ErrOpen || e != delegate.aead.err || delegate.aead.openCalls != 2 {
				t.Fatal("failed real authentication was altered")
			}
			if key.Len() != base.KeySize() || secret.Len() != base.KeySize() {
				t.Fatal("wrapper released borrowed material")
			}
			a.Destroy()
			if delegate.aead.destroyCalls != 1 || key.Len() != base.KeySize() {
				t.Fatal("destroy changed ownership or delegation")
			}
			badKey, e := secmem.New(base.KeySize() - 1)
			if e != nil {
				t.Fatal(e)
			}
			defer badKey.Release()
			if failed, err := observed.NewAEAD(badKey); failed != nil || err != jcrypto.ErrBadKeySize || delegate.newCalls != 2 || delegate.key != badKey {
				t.Fatal("constructor error or borrowed key changed")
			}
			if failed, err := observed.DeriveKey(secret, "agree", context, base.KeySize()); failed != nil || err != jcrypto.ErrBadLabel || delegate.deriveCalls != 2 {
				t.Fatal("derivation error or count changed")
			}
		})
	}
}

func providerIOCollector(t *testing.T) *collector {
	t.Helper()
	buffer, e := secmem.New(32768)
	if e != nil {
		t.Fatal(e)
	}
	var clock atomic.Int64
	c := &collector{arena: &lockedArena{buffer: buffer}, keys: make(map[*secmem.Buffer]keyTag), bindings: make(map[uint64]uint32), transportIndex: make(map[transportKey][]int), contexts: make(map[[32]byte]*setupView), observerValid: true, now: func() int64 { return clock.Add(1) }}
	t.Cleanup(c.close)
	return c
}

func TestProviderIORealCipherShapeAndFailedOpen(t *testing.T) {
	for _, which := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(which.String(), func(t *testing.T) {
			base, e := suite.New(which)
			if e != nil {
				t.Fatal(e)
			}
			key, e := secmem.New(base.KeySize())
			if e != nil {
				t.Fatal(e)
			}
			defer key.Release()
			for _, mode := range []string{"handshake", "transport-seal", "transport-open", "failed-open", "invalid-cell"} {
				t.Run(mode, func(t *testing.T) {
					c := providerIOCollector(t)
					inner, e := base.NewAEAD(key)
					if e != nil {
						t.Fatal(e)
					}
					a := &observedAEAD{AEAD: inner, p: &observedProvider{collector: c}, generation: 7}
					defer a.Destroy()
					cell := wire.NewPadding()
					nonce := make([]byte, a.NonceSize())
					var ad []byte
					if mode == "handshake" {
						ad = make([]byte, 32)
					}
					if mode == "invalid-cell" {
						cell[0] = 0
					}
					if mode == "transport-open" || mode == "failed-open" {
						ciphertext := inner.Seal(nil, nonce, cell[:], nil)
						if mode == "failed-open" {
							ciphertext[len(ciphertext)-1] ^= 1
						}
						_, e = a.Open(ciphertext[:0], nonce, ciphertext, nil)
						if (mode == "failed-open") != (e == jcrypto.ErrOpen) {
							t.Fatal("authentication outcome changed")
						}
					} else {
						a.Seal(nil, nonce, cell[:], ad)
					}
					want := 0
					if mode == "transport-open" || mode == "transport-seal" {
						want = 1
					}
					if len(c.transports) != want || mode == "invalid-cell" && c.err != ReasonContract || mode != "invalid-cell" && c.err != ReasonNone {
						t.Fatal("handshake, failure or malformed cell was accepted as transport")
					}
					if c.summary.Calls != 1 {
						t.Fatal("observer counted an extra primitive invocation")
					}
				})
			}
		})
	}
}

func TestProviderIOProductionSetupHopAndExitBranches(t *testing.T) {
	for _, which := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(which.String(), func(t *testing.T) {
			base, e := suite.New(which)
			if e != nil {
				t.Fatal(e)
			}
			var chain [3]wire.SetupHop
			var private [3]*secmem.Buffer
			for i := range chain {
				private[i], chain[i].StaticPub, e = base.GenerateEphemeral()
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(private[i].Release)
				chain[i].Link = uint64(37 + i)
				if i < 2 {
					chain[i].NextAddr = loopback(uint16(1002 + i))
					chain[i].NextCircuit = uint64(38 + i)
				}
			}
			setup, e := wire.BuildSetup(base, chain[:])
			if e != nil {
				t.Fatal(e)
			}
			for _, key := range setup.CellKeys {
				t.Cleanup(key.Release)
			}
			client, e := wire.NewCircuit(base, setup.CellKeys, setup.Offsets, []uint64{37, 38, 39})
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			var observers [3]*collector
			var hops [3]*wire.Hop
			var cellKeys [3]*secmem.Buffer
			current := setup.Cell
			for i := range hops {
				c := providerIOCollector(t)
				c.publicKeySize = base.HandshakeInfo().PublicKeySize
				observers[i] = c
				p := &observedProvider{CryptoProvider: base, collector: c}
				layer, err := wire.OpenSetup(p, private[i], chain[i].StaticPub, nil, current)
				if err != nil {
					t.Fatal(err)
				}
				cellKeys[i] = layer.CellKey
				t.Cleanup(layer.CellKey.Release)
				hops[i], err = wire.NewHop(p, layer.CellKey, layer.Offsets, i)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(hops[i].Close)
				if len(c.view.setups) != 1 || c.view.setups[0].index != uint8(i) || c.view.setups[0].circuit != chain[i].Link || c.view.setups[0].hop == 0 || c.view.setups[0].stages != stageInput|stageLocal || len(c.keys) != 0 {
					t.Fatal("production setup or constructor metadata changed")
				}
				if i < 2 {
					current, err = wire.ForwardSetup(layer, i)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			for request, branch := range []string{"reply", "cover", "nil-reply"} {
				payload := []byte("actual production exit payload")
				var forwarded *wire.Cell
				if branch == "cover" {
					forwarded, e = client.SealCover(uint64(request))
				} else {
					forwarded, e = client.Seal(uint64(request), payload)
				}
				if e != nil {
					t.Fatal(e)
				}
				for i := 0; i < 2; i++ {
					forwarded, e = hops[i].Peel(forwarded)
					if e != nil {
						t.Fatal(e)
					}
					forwarded.SetCircuit(chain[i].NextCircuit)
				}
				opened, cover, err := hops[2].OpenLast(forwarded)
				if err != nil || cover != (branch == "cover") || !cover && !bytes.Equal(opened, payload) {
					t.Fatal("observed hop changed production payload or cover")
				}
				var reply *wire.Cell
				called := 0
				if !cover {
					deliver := observeDeliver(observers[2], base, func(circuit uint64, body []byte) []byte {
						called++
						if circuit != chain[2].Link || !providerIOAlias(body, opened) {
							t.Fatal("Deliver changed circuit or borrowed payload")
						}
						if branch == "nil-reply" {
							return nil
						}
						return body
					})
					out := deliver(chain[2].Link, opened)
					if out == nil {
						reply, e = hops[2].SealCoverReply(chain[2].Link, uint64(request))
					} else {
						reply, e = hops[2].SealReply(chain[2].Link, uint64(request), out)
					}
				} else {
					reply, e = hops[2].SealCoverReply(chain[2].Link, uint64(request))
				}
				if e != nil || called != boolInt(!cover) {
					t.Fatal("Deliver or reply delegation changed")
				}
				for i := 1; i >= 0; i-- {
					reply, e = hops[i].Wrap(reply, chain[i].Link)
					if e != nil {
						t.Fatal(e)
					}
				}
				out, replyCover, e := client.OpenExit(reply, wire.Backward)
				if e != nil || replyCover != (branch != "reply") || !replyCover && !bytes.Equal(out, payload) {
					t.Fatal("observed backward hop changed production reply")
				}
				forward := observers[2].view.cells[2*request]
				if forward.cover != cover || forward.noDeliver != cover || forward.delivered != !cover || forward.nilReply != (branch == "nil-reply") || !forward.paired {
					t.Fatal("exit branches were conflated")
				}
				clear(opened)
				clear(out)
			}
			for i, hop := range hops {
				hop.Close()
				c := observers[i]
				if len(c.view.cells) != 6 || len(c.view.releases) != 1 || c.view.releases[0].hop != c.view.setups[0].hop || cellKeys[i].Len() != base.KeySize() {
					t.Fatal("hop destroy lost stages or released a borrowed key")
				}
				want := ReasonNone
				if !cellKeys[i].Locked() {
					want = ReasonContract
				}
				if c.err != want {
					t.Fatal("production wrapper reported an unexpected contract failure")
				}
			}
		})
	}
}

type providerIOStep struct {
	data []byte
	err  error
}

type providerIOConn struct {
	reads         []providerIOStep
	writeCounts   []int
	writeErrors   []error
	readCalls     int
	writeCalls    int
	written       []byte
	readGate      <-chan struct{}
	readStarted   chan<- struct{}
	local, remote uint16
}

func (c *providerIOConn) Read(b []byte) (int, error) {
	c.readCalls++
	if c.readStarted != nil {
		c.readStarted <- struct{}{}
	}
	if c.readGate != nil {
		<-c.readGate
	}
	if len(c.reads) == 0 {
		return 0, io.EOF
	}
	s := c.reads[0]
	c.reads = c.reads[1:]
	if len(s.data) > len(b) {
		panic("test read buffer is too short")
	}
	return copy(b, s.data), s.err
}

func (c *providerIOConn) Write(b []byte) (int, error) {
	i := c.writeCalls
	c.writeCalls++
	n, e := len(b), error(nil)
	if i < len(c.writeCounts) {
		n = c.writeCounts[i]
	}
	if i < len(c.writeErrors) {
		e = c.writeErrors[i]
	}
	if n >= 0 && n <= len(b) {
		c.written = append(c.written, b[:n]...)
	}
	return n, e
}

func (c *providerIOConn) Close() error { return nil }
func (c *providerIOConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(c.local)}
}
func (c *providerIOConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(c.remote)}
}
func (c *providerIOConn) SetDeadline(time.Time) error      { return nil }
func (c *providerIOConn) SetReadDeadline(time.Time) error  { return nil }
func (c *providerIOConn) SetWriteDeadline(time.Time) error { return nil }

func providerIOBytes() []byte {
	b := make([]byte, 3*528)
	for i := range b {
		b[i] = byte(i/528*37 + i%528)
	}
	return b
}

func TestProviderIOConnEverySplitPreservesNErrorAndPartialTail(t *testing.T) {
	all := providerIOBytes()
	sentinel := errors.New("fixed io test error")
	for split := 0; split <= len(all); split++ {
		buffer, e := secmem.New(8192)
		if e != nil {
			t.Fatal(e)
		}
		var clock atomic.Int64
		c := &collector{arena: &lockedArena{buffer: buffer}, bindings: map[uint64]uint32{}, transportIndex: map[transportKey][]int{}, observerValid: true, now: func() int64 { return clock.Add(1) }}
		raw := &providerIOConn{local: 1001, remote: 1002, reads: []providerIOStep{{all[:split], sentinel}, {all[split:], io.EOF}}, writeCounts: []int{split, len(all) - split}, writeErrors: []error{sentinel, io.EOF}}
		o, e := observeConn(raw, c, true)
		if e != nil {
			t.Fatal(e)
		}
		b := make([]byte, len(all))
		n, e := o.Read(b)
		if n != split || e != sentinel || !bytes.Equal(b[:n], all[:split]) {
			t.Fatalf("read prefix changed at %d", split)
		}
		n, e = o.Read(b)
		if n != len(all)-split || e != io.EOF || !bytes.Equal(b[:n], all[split:]) {
			t.Fatalf("read suffix changed at %d", split)
		}
		n, e = o.Write(all)
		if n != split || e != sentinel {
			t.Fatalf("short write changed at %d", split)
		}
		n, e = o.Write(all[split:])
		if n != len(all)-split || e != io.EOF || !bytes.Equal(raw.written, all) {
			t.Fatalf("write suffix changed at %d", split)
		}
		if len(c.view.frames) != 4 || o.read.used != 0 || o.write.used != 0 || c.err != ReasonNone {
			t.Fatalf("frame total changed at %d", split)
		}
		for i, frame := range c.view.frames {
			if frame.direction != uint8(i/2) || !bytes.Equal(c.arena.bytes(frame.data), all[528*(1+i%2):528*(2+i%2)]) {
				t.Fatalf("captured bytes changed at %d", split)
			}
		}
		c.close()
	}
}

func TestProviderIOReadDoesNotHoldCollectorOrWriteLock(t *testing.T) {
	c := providerIOCollector(t)
	started, release := make(chan struct{}, 1), make(chan struct{})
	raw := &providerIOConn{local: 1001, remote: 1002, readStarted: started, readGate: release}
	o, e := observeConn(raw, c, true)
	if e != nil {
		t.Fatal(e)
	}
	readDone := make(chan struct{})
	go func() { _, _ = o.Read(make([]byte, 1)); close(readDone) }()
	<-started
	writeDone := make(chan error, 1)
	go func() { _, e := o.Write([]byte{1}); writeDone <- e }()
	select {
	case e := <-writeDone:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		close(release)
		<-readDone
		t.Fatal("blocked read held the collector or opposite-direction lock")
	}
	close(release)
	<-readDone
}

func TestProviderIOPartialAndFullNErrorKeepActualCompletion(t *testing.T) {
	for _, n := range []int{0, 1, 527, 528} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			c := providerIOCollector(t)
			sentinel := errors.New("fixed write failure")
			raw := &providerIOConn{local: 1001, remote: 1002, writeCounts: []int{528, n}, writeErrors: []error{nil, sentinel}}
			o, e := observeConn(raw, c, true)
			if e != nil {
				t.Fatal(e)
			}
			if got, e := o.Write(make([]byte, 528)); got != 528 || e != nil {
				t.Fatal("handshake delegation changed")
			}
			frame := bytes.Repeat([]byte{71}, 528)
			providerIOTransport(c, 11, false, frame, 41)
			if got, err := o.Write(frame); got != n || err != sentinel {
				t.Fatal("write return changed")
			}
			got := c.transports[0]
			if !got.attempted || !got.failed || got.partial != (n > 0 && n < 528) || got.matched != (n == 528) || got.connection != o.generation || len(c.view.frames) != boolInt(n == 528) || o.write.used != n%528 {
				t.Fatal("partial or n+error write invented or lost completed evidence")
			}
			if e := c.freeze(); e != nil {
				t.Fatal("ordinary terminal write failure became a provenance failure")
			}
		})
	}
}

func TestProviderIOCloseWipesPartialDirectionalBacking(t *testing.T) {
	for _, size := range []int{200, 528 + 200} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			c := providerIOCollector(t)
			partial := bytes.Repeat([]byte{83}, size)
			raw := &providerIOConn{local: 1001, remote: 1002, reads: []providerIOStep{{partial, io.EOF}}}
			o, e := observeConn(raw, c, true)
			if e != nil {
				t.Fatal(e)
			}
			if n, e := o.Read(make([]byte, size)); n != size || e != io.EOF {
				t.Fatal("partial read changed")
			}
			if n, e := o.Write(partial); n != size || e != nil {
				t.Fatal("partial write changed")
			}
			backing := [][]byte{o.read.flight[:], o.read.frame[:], o.write.flight[:], o.write.frame[:]}
			active := 0
			if size > 528 {
				active = 1
			}
			if bytes.Equal(backing[active], make([]byte, len(backing[active]))) || bytes.Equal(backing[active+2], make([]byte, len(backing[active+2]))) {
				t.Fatal("test did not retain actual partial bytes")
			}
			if o.Close() != nil || o.Close() != nil {
				t.Fatal("close delegation changed")
			}
			for _, b := range backing {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatal("close retained partial raw bytes")
				}
			}
			if c.arena.live != 0 || len(c.view.releases) != 1 {
				t.Fatal("directional backing was leaked or released twice")
			}
		})
	}
}

func providerIOTransport(c *collector, aead uint32, incoming bool, frame []byte, circuit uint64) {
	cell, _ := wire.NewCell(wire.Header{Kind: wire.KindPadding, Circuit: circuit}, make([]byte, wire.BodySize))
	c.transport(aead, incoming, frame, cell[:], 10)
}

func TestProviderIOProvenancePermutationsAndConflicts(t *testing.T) {
	permutations := [][4]int{}
	for a := 0; a < 4; a++ {
		for b := 0; b < 4; b++ {
			for d := 0; d < 4; d++ {
				for e := 0; e < 4; e++ {
					if a != b && a != d && a != e && b != d && b != e && d != e {
						permutations = append(permutations, [4]int{a, b, d, e})
					}
				}
			}
		}
	}
	for _, order := range permutations {
		c := providerIOCollector(t)
		frameA := bytes.Repeat([]byte{31}, 528)
		frameB := bytes.Clone(frameA)
		frameB[len(frameB)-1] ^= 1
		c.view.connections = []connectionView{{generation: 1}, {generation: 2}}
		one, two := &observedConn{c: c, generation: 1}, &observedConn{c: c, generation: 2}
		for _, event := range order {
			switch event {
			case 0:
				providerIOTransport(c, 11, true, frameA, 41)
			case 1:
				providerIOTransport(c, 22, true, frameB, 41)
			case 2:
				one.frame(frameA, 0, 9)
			case 3:
				two.frame(frameB, 0, 9)
			}
		}
		if c.err != ReasonNone || c.bindings[22] != 1 || c.bindings[44] != 2 || len(c.pendingFrames) != 0 || len(c.pendingTransports) != 0 || c.arena.live != 0 {
			t.Fatalf("exact association changed under order %v", order)
		}
	}
	for _, conflict := range []string{"equal-pending-sockets", "stale-aead-generation", "closed-tuple-reuse"} {
		t.Run(conflict, func(t *testing.T) {
			c := providerIOCollector(t)
			frame := bytes.Repeat([]byte{53}, 528)
			one := &observedConn{c: c, generation: 1}
			two := &observedConn{c: c, generation: 2}
			switch conflict {
			case "equal-pending-sockets":
				one.frame(frame, 0, 9)
				two.frame(frame, 0, 9)
				providerIOTransport(c, 11, true, frame, 41)
			case "stale-aead-generation":
				one.frame(frame, 0, 9)
				providerIOTransport(c, 11, true, frame, 41)
				two.frame(frame, 0, 10)
				providerIOTransport(c, 11, true, frame, 42)
			case "closed-tuple-reuse":
				raw := &providerIOConn{local: 1001, remote: 1002}
				o, e := observeConn(raw, c, true)
				if e != nil {
					t.Fatal(e)
				}
				_ = o.Close()
				if _, e = observeConn(raw, c, true); e == nil {
					t.Fatal("closed socket tuple was reused")
				}
			}
			if c.err != ReasonContract {
				t.Fatal("ambiguous or stale generation was guessed")
			}
		})
	}
}
