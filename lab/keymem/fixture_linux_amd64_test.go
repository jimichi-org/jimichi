//go:build linux && amd64

package keymem

import (
	"context"
	"errors"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

type failingFixtureProvider struct {
	jcrypto.CryptoProvider
	failAt int
	calls  int
	owned  []*secmem.Buffer
}

func (p *failingFixtureProvider) GenerateEphemeral() (*secmem.Buffer, []byte, error) {
	p.calls++
	if p.calls == p.failAt {
		return nil, nil, errAllocationFailed
	}
	priv, pub, e := p.CryptoProvider.GenerateEphemeral()
	if e == nil {
		p.owned = append(p.owned, priv)
	}
	return priv, pub, e
}

func (p *failingFixtureProvider) GenerateSigning() (*secmem.Buffer, []byte, error) {
	priv, pub, e := p.CryptoProvider.GenerateSigning()
	if e == nil {
		p.owned = append(p.owned, priv)
	}
	return priv, pub, e
}

func TestFixturePartialSetupReleasesEveryOwnedResource(t *testing.T) {
	if e := secmem.SetPolicy(secmem.Protected); e != nil {
		t.Fatal(e)
	}
	provider, e := suite.New(jcrypto.SuiteC25519)
	if e != nil {
		t.Fatal(e)
	}
	for n := 1; n <= 12; n++ {
		p := &failingFixtureProvider{CryptoProvider: provider, failAt: n}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		f, e := newFixture(ctx, p)
		cancel()
		if !errors.Is(e, errAllocationFailed) {
			if f != nil {
				f.close()
			}
			t.Fatal("missing injected allocation failure")
		}
		if f.close() != nil {
			t.Fatal("cleanup is not idempotent")
		}
		for _, key := range p.owned {
			if key.Len() != 0 {
				t.Fatal("partial fixture retained owned key")
			}
		}
		for i := range f.listeners {
			if f.listeners[i] != nil || f.done[i] != nil || f.links[i] != nil || f.rings[i] != nil || f.identities[i] != nil {
				t.Fatal("partial fixture retained resource")
			}
		}
		if f.ca != nil {
			t.Fatal("partial fixture retained CA")
		}
	}
}
