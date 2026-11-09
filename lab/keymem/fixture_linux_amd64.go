//go:build linux && amd64

package keymem

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

type fixture struct {
	ca         *pki.CA
	listeners  [3]net.Listener
	links      [3]*secmem.Buffer
	rings      [3]*relay.OnionRing
	identities [3]*pki.Identity
	relays     [3]*relay.Relay
	done       [3]chan error
	public     []relayPublic
}

func newFixture(ctx context.Context, p jcrypto.CryptoProvider) (f *fixture, err error) {
	f = &fixture{}
	defer func() {
		if err != nil {
			if f.close() != nil {
				err = errors.Join(err, errFixtureCleanup)
			}
		}
	}()
	for i := range f.listeners {
		var lc net.ListenConfig
		f.listeners[i], err = lc.Listen(ctx, "tcp4", "127.0.0.1:0")
		if err != nil {
			return f, err
		}
	}
	f.ca, err = pki.NewCA(p)
	if err != nil {
		return f, err
	}
	var addrs []string
	var bundles [][]byte
	var linkPubs [3][]byte
	for i := range f.listeners {
		if ctx.Err() != nil {
			return f, errControllerFailed
		}
		addr := f.listeners[i].Addr().String()
		name := "relay-" + strconv.Itoa(i+1)
		f.links[i], linkPubs[i], err = p.GenerateEphemeral()
		if err != nil {
			return f, err
		}
		if !f.links[i].Locked() {
			return f, errProtectionUnavailable
		}
		onion, onionPub, e := p.GenerateEphemeral()
		if e != nil {
			return f, e
		}
		if bytes.Equal(linkPubs[i], onionPub) {
			onion.Release()
			return f, errors.New("fixture_failed")
		}
		if !onion.Locked() {
			onion.Release()
			return f, errProtectionUnavailable
		}
		f.rings[i], err = relay.NewOnionRing(p, onion, onionPub, 0)
		if err != nil {
			onion.Release()
			return f, err
		}
		f.identities[i], err = pki.NewIdentity(p, name, addr)
		if err != nil {
			return f, err
		}
		if !f.identities[i].Locked() {
			return f, errProtectionUnavailable
		}
		var nonce [pki.NonceSize]byte
		if randomFill(nonce[:]) != nil {
			return f, errControllerFailed
		}
		raw, e := f.identities[i].Request(nonce)
		if e != nil {
			return f, e
		}
		req, e := pki.ParseRequest(raw)
		if e != nil {
			return f, e
		}
		if e = req.Check(p, nonce, name, addr); e != nil {
			return f, e
		}
		now := time.Now()
		cert, e := f.ca.Issue(req, now.Add(-pki.Skew), now.Add(2*time.Hour))
		if e != nil {
			return f, e
		}
		if e = f.identities[i].Install(cert.Marshal(), now); e != nil {
			return f, e
		}
		f.identities[i].SetKeys(linkPubs[i], onionPub, 0)
		if e = f.identities[i].Refresh(now, time.Hour); e != nil {
			return f, e
		}
		bundle, ok := f.identities[i].Bundle()
		if !ok {
			return f, errControllerFailed
		}
		addrs = append(addrs, addr)
		bundles = append(bundles, bundle)
		f.public = append(f.public, relayPublic{Address: addr, Bundle: base64.StdEncoding.EncodeToString(bundle)})
	}
	verified, e := pki.VerifyChain(p, pki.Policy{Anchor: f.ca.Anchor(), Skew: pki.Skew, MinLife: pki.MinDescriptorLife}, addrs, bundles, time.Now())
	if e != nil {
		return f, e
	}
	peers := make(map[string]relay.Peer, 3)
	for _, v := range verified {
		if len(v.Identity) == 0 {
			return f, errControllerFailed
		}
		peers[v.Addr] = relay.Peer{LinkPub: v.LinkPub, Identity: v.Identity}
	}
	lookup := func(addr string) (relay.Peer, bool) { peer, ok := peers[addr]; return peer, ok }
	for i, v := range verified {
		f.relays[i], err = relay.New(relay.Config{Provider: p, Addr: v.Addr, StaticPriv: f.links[i], StaticPub: linkPubs[i], Identity: v.Identity, Onion: f.rings[i], Peers: lookup, AllowAnonymous: false, Deliver: func(_ uint64, payload []byte) []byte { return payload }})
		if err != nil {
			return f, err
		}
		f.done[i] = make(chan error, 1)
		go func(r *relay.Relay, ln net.Listener, done chan<- error) { done <- r.Serve(ln) }(f.relays[i], f.listeners[i], f.done[i])
	}
	return f, nil
}

func (f *fixture) close() error {
	if f == nil {
		return nil
	}
	var failed bool
	for _, r := range f.relays {
		if r != nil {
			r.Close()
		}
	}
	for i, ln := range f.listeners {
		if ln != nil {
			if e := ln.Close(); e != nil && !errors.Is(e, net.ErrClosed) {
				failed = true
			}
			f.listeners[i] = nil
		}
	}
	for i, ch := range f.done {
		if ch != nil {
			if <-ch != nil {
				failed = true
			}
			f.done[i] = nil
		}
	}
	for i, r := range f.rings {
		if r != nil {
			r.Close()
			f.rings[i] = nil
		}
	}
	for i, id := range f.identities {
		if id != nil {
			id.Close()
			f.identities[i] = nil
		}
	}
	for i, k := range f.links {
		if k != nil {
			k.Release()
			f.links[i] = nil
		}
	}
	if f.ca != nil {
		f.ca.Close()
		f.ca = nil
	}
	if failed {
		return errFixtureCleanup
	}
	return nil
}
