package relay_test

import (
	"sync"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// every provider call that makes or uses a key outside an AEAD already held
type keyCountingProvider struct {
	jcrypto.CryptoProvider
	mu    sync.Mutex
	calls map[string]int
}

func (p *keyCountingProvider) count(name string) {
	p.mu.Lock()
	if p.calls == nil {
		p.calls = make(map[string]int)
	}
	p.calls[name]++
	p.mu.Unlock()
}

func (p *keyCountingProvider) snapshot() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]int, len(p.calls))
	for k, v := range p.calls {
		out[k] = v
	}
	return out
}

func (p *keyCountingProvider) NoiseDH(priv *secmem.Buffer, peerPub []byte) (*secmem.Buffer, error) {
	p.count("NoiseDH")
	return p.CryptoProvider.NoiseDH(priv, peerPub)
}

func (p *keyCountingProvider) NoiseKDF2(ck, input *secmem.Buffer) (*secmem.Buffer, *secmem.Buffer, error) {
	p.count("NoiseKDF2")
	return p.CryptoProvider.NoiseKDF2(ck, input)
}

func (p *keyCountingProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	p.count("GenerateEphemeral")
	return p.CryptoProvider.GenerateEphemeral()
}

func (p *keyCountingProvider) GenerateSigning() (*secmem.Buffer, []byte, error) {
	p.count("GenerateSigning")
	return p.CryptoProvider.GenerateSigning()
}

func (p *keyCountingProvider) Agree(priv *secmem.Buffer, peerPub []byte, ctx jcrypto.Context) (*secmem.Buffer, error) {
	p.count("Agree")
	return p.CryptoProvider.Agree(priv, peerPub, ctx)
}

func (p *keyCountingProvider) MixKey(chain, secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	p.count("MixKey")
	return p.CryptoProvider.MixKey(chain, secret, ctx)
}

func (p *keyCountingProvider) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	p.count("DeriveKey")
	return p.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
}

func (p *keyCountingProvider) DerivePair(secret *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, []byte, error) {
	p.count("DerivePair")
	return p.CryptoProvider.DerivePair(secret, ctx)
}

func (p *keyCountingProvider) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	p.count("PasswordKey")
	return p.CryptoProvider.PasswordKey(password, ctx)
}

func (p *keyCountingProvider) NewAEAD(key *secmem.Buffer) (jcrypto.AEAD, error) {
	p.count("NewAEAD")
	return p.CryptoProvider.NewAEAD(key)
}

func (p *keyCountingProvider) Sign(priv *secmem.Buffer, msg []byte) ([]byte, error) {
	p.count("Sign")
	return p.CryptoProvider.Sign(priv, msg)
}

// the mlock claim of block 6 rests on this: once a circuit is up, an echo
// through a live node, its links and the client makes and uses no key the
// circuit did not already hold. Known answer: 100 echoes add 0 to every count
func TestEchoPathCreatesNoKey(t *testing.T) {
	onEverySuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		w := &keyCountingProvider{CryptoProvider: p}
		exit := startNode(t, w, func(_ uint64, payload []byte) []byte { return payload })
		cl, err := client.Dial(client.Config{Provider: w, Chain: chainOf(exit)})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer cl.Close()
		echo := func() {
			t.Helper()
			if err := cl.Send([]byte("ping")); err != nil {
				t.Fatalf("Send: %v", err)
			}
			select {
			case <-cl.Replies():
			case <-time.After(3 * time.Second):
				t.Fatal("no echo came back")
			}
		}
		echo()
		before := w.snapshot()
		for range 100 {
			echo()
		}
		after := w.snapshot()
		for name, n := range after {
			if n != before[name] {
				t.Errorf("%s: %d calls during 100 echoes, want 0", name, n-before[name])
			}
		}
	})
}
