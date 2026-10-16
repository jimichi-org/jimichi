package verify

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func provider(t *testing.T, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func addrOf(name string) string { return name + ".jimichi.svc.cluster.local:9000" }

type relayKeys struct {
	addr     string
	onion    []byte
	link     []byte
	identity []byte
}

// a node enrolled under ca the way jimichi enroll does it, serving a
// descriptor signed at t0 for an hour
func enrolled(t *testing.T, p jcrypto.CryptoProvider, ca *pki.CA, name string, notAfter time.Time) (relayKeys, []byte) {
	t.Helper()
	id, err := pki.NewIdentity(p, name, addrOf(name))
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
	cert, err := ca.Issue(req, t0, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Install(cert.Marshal(), t0); err != nil {
		t.Fatal(err)
	}
	k := relayKeys{addr: addrOf(name), onion: agreementKey(t, p), link: agreementKey(t, p), identity: id.Public()}
	id.SetKeys(k.link, k.onion, 0)
	if err := id.Refresh(t0, time.Hour); err != nil {
		t.Fatal(err)
	}
	b, ok := id.Bundle()
	if !ok {
		t.Fatal("no bundle")
	}
	return k, b
}

func agreementKey(t *testing.T, p jcrypto.CryptoProvider) []byte {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	return pub
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

// the bundle with one bit of its descriptor signature flipped
func altered(t *testing.T, bundle []byte) []byte {
	t.Helper()
	b, err := pki.ParseBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	b.Descriptor[len(b.Descriptor)-1] ^= 1
	return b.Marshal()
}

// a stream of the given 64-bit values, one per draw
func words(values ...uint64) *bytes.Reader {
	b := make([]byte, 0, 8*len(values))
	for _, v := range values {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	return bytes.NewReader(b)
}

// a draw among m nodes reads m+k for the k-th of them
func pick(m, k int) uint64 { return uint64(m + k) }

// n nodes enrolled under one CA and their bundles in the listed order
func enrolledNodes(t *testing.T, p jcrypto.CryptoProvider, ca *pki.CA, n int) ([]relayKeys, []string, [][]byte) {
	t.Helper()
	keys := make([]relayKeys, n)
	addrs := make([]string, n)
	bundles := make([][]byte, n)
	for i := range keys {
		keys[i], bundles[i] = enrolled(t, p, ca, fmt.Sprintf("relay-%d", i+1), t0.Add(72*time.Hour))
		addrs[i] = keys[i].addr
	}
	return keys, addrs, bundles
}
