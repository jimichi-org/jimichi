package main

import (
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/verify"
	"github.com/jimichi-org/jimichi/pki"
)

// a bundle of the node at addr under ca, signed at at for an hour
func enrolledBundle(t *testing.T, p jcrypto.CryptoProvider, ca *pki.CA, name, addr string, at time.Time) []byte {
	t.Helper()
	id, err := pki.NewIdentity(p, name, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	var nonce [pki.NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := id.Request(nonce)
	if err != nil {
		t.Fatal(err)
	}
	req, err := pki.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(req, at, at.Add(72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Install(cert.Marshal(), at); err != nil {
		t.Fatal(err)
	}
	keys := make([][]byte, 2)
	for i := range keys {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		priv.Release()
		keys[i] = pub
	}
	id.SetKeys(keys[0], keys[1], 0)
	if err := id.Refresh(at, time.Hour); err != nil {
		t.Fatal(err)
	}
	b, ok := id.Bundle()
	if !ok {
		t.Fatal("no bundle")
	}
	return b
}

func newCA(t *testing.T, p jcrypto.CryptoProvider) *pki.CA {
	t.Helper()
	ca, err := pki.NewCA(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Close)
	return ca
}

// the model made of bundles: every node is enrolled under the session CA and
// fetches the bundle of every other node from that node, except that a
// withholding node gives an honest one nothing or a bundle of a second CA, in
// turn. An honest entry serves the bundles it took, a rogue entry its own
// bundles for all but the nodes it leaves out and for those the same as a
// withholding node. What the nodes take with verify.Peer is extendsOf, and
// what a client holds of each mirror with verify.Mirror is mirrorsOf
func TestMirrorsAndExtendsOfTheModelAreWhatTheNodesVerify(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	session, second := newCA(t, p), newCA(t, p)
	trust := pki.Policy{Anchor: session.Anchor(), Skew: pki.Skew}
	kinds := map[bool]int{}
	for _, c := range []pathsConfig{
		{nodes: 4, rogue: 1},
		{nodes: 5, rogue: 2, leftOut: 1, withheld: 1},
		{nodes: 6, rogue: 3, leftOut: 2, withheld: 2},
		{nodes: 5, rogue: 2, leftOut: 3, withheld: 2},
	} {
		addrs := make([]string, c.nodes)
		own := make([][]byte, c.nodes)
		foreign := make([][]byte, c.nodes)
		for i := range addrs {
			name := fmt.Sprintf("relay-%d", i+1)
			addrs[i] = name + ".jimichi.svc.cluster.local:9000"
			own[i] = enrolledBundle(t, p, session, name, addrs[i], at)
			foreign[i] = enrolledBundle(t, p, second, name, addrs[i], at)
		}
		kept := func(x, y int) []byte {
			other := (x+y)%2 == 1
			kinds[other]++
			if other {
				return foreign[y]
			}
			return nil
		}

		extends := make([][]bool, c.nodes)
		mirrors := make([][]bool, c.nodes)
		for x := range extends {
			extends[x] = make([]bool, c.nodes)
			served := make([][]byte, c.nodes)
			for y := range served {
				honest := x >= c.rogue
				fetched := own[y]
				if honest && y < c.withheld {
					fetched = kept(x, y)
				}
				if fetched != nil {
					_, err := verify.Peer(p, pki.Policy{Anchor: session.Anchor(), Skew: pki.Skew}, addrs[y], fetched, at)
					extends[x][y] = err == nil
				}
				switch {
				case honest && extends[x][y]:
					served[y] = fetched
				case !honest && y < c.nodes-c.leftOut:
					served[y] = own[y]
				case !honest:
					served[y] = kept(x, y)
				}
			}
			v, err := verify.Mirror(p, true, trust, addrs, served, at)
			if err != nil {
				t.Fatal(err)
			}
			mirrors[x] = v.Usable()
		}
		if want := extendsOf(c); !reflect.DeepEqual(extends, want) {
			t.Errorf("%+v: the nodes take %v, extendsOf gives %v", c, extends, want)
		}
		if want := mirrorsOf(c); !reflect.DeepEqual(mirrors, want) {
			t.Errorf("%+v: the clients hold %v, mirrorsOf gives %v", c, mirrors, want)
		}
	}
	if kinds[false] == 0 || kinds[true] == 0 {
		t.Fatalf("%d bundles kept back and %d of the second CA: want both kinds", kinds[false], kinds[true])
	}
}
