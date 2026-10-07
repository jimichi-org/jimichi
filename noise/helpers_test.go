package noise_test

import (
	"bytes"
	"encoding/hex"
	"sync"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/noise"
)

// every test runs on a provider that fails it on a signing call, so no path
// of the handshake, refused and forged messages included, can sign or verify
func eachSuite(t *testing.T, run func(t *testing.T, p jcrypto.CryptoProvider)) {
	t.Helper()
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		p, err := suite.New(s)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(s.String(), func(t *testing.T) { run(t, noSigning{CryptoProvider: p, t: t}) })
	}
}

// keeps every secret the provider hands out, so a test can tell which ones
// are still held
type trackingProvider struct {
	jcrypto.CryptoProvider
	mu   sync.Mutex
	bufs []*secmem.Buffer
}

func (p *trackingProvider) keep(b *secmem.Buffer) *secmem.Buffer {
	if b != nil {
		p.mu.Lock()
		p.bufs = append(p.bufs, b)
		p.mu.Unlock()
	}
	return b
}

func (p *trackingProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	priv, pub, err := p.CryptoProvider.GenerateEphemeral()
	return p.keep(priv), pub, err
}

func (p *trackingProvider) Agree(priv *secmem.Buffer, pub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.Agree(priv, pub, ctx)
	return p.keep(b), err
}

func (p *trackingProvider) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.MixKey(chain, secret, ctx)
	return p.keep(b), err
}

func (p *trackingProvider) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	b, err := p.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	return p.keep(b), err
}

func (p *trackingProvider) live() (made, held int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.bufs {
		if b.Bytes() != nil {
			held++
		}
	}
	return len(p.bufs), held
}

// client identities are agreement keys only: any signing call fails the test
type noSigning struct {
	jcrypto.CryptoProvider
	t *testing.T
}

func (p noSigning) GenerateSigning() (*secmem.Buffer, []byte, error) {
	p.t.Error("GenerateSigning called")
	return p.CryptoProvider.GenerateSigning()
}

func (p noSigning) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	p.t.Error("Sign called")
	return p.CryptoProvider.Sign(priv, msg)
}

func (p noSigning) Verify(pub, msg, sig []byte) bool {
	p.t.Error("Verify called")
	return p.CryptoProvider.Verify(pub, msg, sig)
}

func staticKey(t *testing.T, p jcrypto.CryptoProvider) *noise.KeyPair {
	t.Helper()
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	kp := noise.NewKeyPair(p, priv, pub)
	t.Cleanup(kp.Close)
	return kp
}

// two statics and the KK states of both sides over them
func kkPair(t *testing.T, p jcrypto.CryptoProvider, prologue [][]byte) (*noise.HandshakeState, *noise.HandshakeState) {
	t.Helper()
	si, sr := staticKey(t, p), staticKey(t, p)
	return kkStates(t, p, si, sr, prologue, prologue)
}

func kkStates(t *testing.T, p jcrypto.CryptoProvider, si, sr noise.Static, prologueI, prologueR [][]byte) (*noise.HandshakeState, *noise.HandshakeState) {
	t.Helper()
	ini, err := noise.New(noise.Config{Provider: p, Pattern: noise.KK, Name: "test", Initiator: true,
		Prologue: prologueI, Local: si, RemoteStatic: sr.Public()})
	if err != nil {
		t.Fatalf("New(initiator): %v", err)
	}
	t.Cleanup(ini.Close)
	resp, err := noise.New(noise.Config{Provider: p, Pattern: noise.KK, Name: "test",
		Prologue: prologueR, Local: sr, RemoteStatic: si.Public()})
	if err != nil {
		t.Fatalf("New(responder): %v", err)
	}
	t.Cleanup(resp.Close)
	return ini, resp
}

func mustWrite(t *testing.T, hs *noise.HandshakeState, payload []byte) []byte {
	t.Helper()
	msg, err := hs.WriteMessage(payload)
	if err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	return msg
}

func mustRead(t *testing.T, hs *noise.HandshakeState, msg []byte) []byte {
	t.Helper()
	pt, err := hs.ReadMessage(msg)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	return pt
}

type split struct {
	i2r, r2i, sid []byte
}

func mustSplit(t *testing.T, hs *noise.HandshakeState) split {
	t.Helper()
	i2r, r2i, sid, err := hs.Split()
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	defer i2r.Release()
	defer r2i.Release()
	return split{bytes.Clone(i2r.Bytes()), bytes.Clone(r2i.Bytes()), sid}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func seq(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}
