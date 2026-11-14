package nodeview

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

type delegationProvider struct {
	crypto.CryptoProvider
	a     *delegationAEAD
	calls int
}

func (p *delegationProvider) NewAEAD(*secmem.Buffer) (crypto.AEAD, error) { p.calls++; return p.a, nil }

type delegationAEAD struct {
	open, seal, destroy      int
	failure                  error
	nonce, ad, plain, cipher []byte
}

func (a *delegationAEAD) NonceSize() int { return 24 }
func (a *delegationAEAD) Overhead() int  { return 16 }
func (a *delegationAEAD) Open(dst, nonce, cipher, ad []byte) ([]byte, error) {
	a.open++
	a.nonce, a.ad, a.cipher = nonce, ad, cipher
	if a.failure != nil {
		return nil, a.failure
	}
	return append(dst, cipher...), nil
}
func (a *delegationAEAD) Seal(dst, nonce, plain, ad []byte) []byte {
	a.seal++
	a.nonce, a.ad, a.plain = nonce, ad, plain
	return append(dst, plain...)
}
func (a *delegationAEAD) Destroy() { a.destroy++ }

func TestProviderDelegatesOnceAndPreservesAliasing(t *testing.T) {
	base := &delegationProvider{a: &delegationAEAD{}}
	p := &observedProvider{CryptoProvider: base}
	a, e := p.NewAEAD(nil)
	if e != nil || base.calls != 1 {
		t.Fatal("constructor delegation")
	}
	nonce, ad := []byte{1, 2}, []byte{3, 4}
	backing := make([]byte, 3, 32)
	copy(backing, []byte{7, 8, 9})
	plain := []byte{10, 11}
	sealed := a.Seal(backing, nonce, plain, ad)
	if base.a.seal != 1 || !bytes.Equal(sealed, []byte{7, 8, 9, 10, 11}) || &sealed[0] != &backing[0] || &base.a.nonce[0] != &nonce[0] || &base.a.ad[0] != &ad[0] || &base.a.plain[0] != &plain[0] {
		t.Fatal("seal arguments, alias or result changed")
	}
	opened, e := a.Open(backing[:0], nonce, sealed, ad)
	if e != nil || base.a.open != 1 || &opened[0] != &backing[0] || &base.a.cipher[0] != &sealed[0] {
		t.Fatal("open arguments, alias or result changed")
	}
	sentinel := errors.New("private-primitive-failure")
	base.a.failure = sentinel
	out, e := a.Open(nil, nonce, plain, ad)
	if out != nil || e != sentinel || base.a.open != 2 {
		t.Fatal("open error changed")
	}
	a.Destroy()
	a.Destroy()
	if base.a.destroy != 2 {
		t.Fatal("destroy delegation changed")
	}
}

type delayedDelegation struct {
	delegationAEAD
	clock *int64
}

func (a *delayedDelegation) Open(dst, nonce, cipher, ad []byte) ([]byte, error) {
	*a.clock += 1000
	return a.delegationAEAD.Open(dst, nonce, cipher, ad)
}
func TestObserverCostExcludesDelegatedWork(t *testing.T) {
	b, e := secmem.New(1024)
	if e != nil {
		t.Fatal(e)
	}
	arena := &lockedArena{buffer: b}
	defer arena.close()
	clock := int64(0)
	c := &collector{arena: arena, observerValid: true, now: func() int64 { clock++; return clock }}
	base := &delayedDelegation{clock: &clock}
	a := observedAEAD{AEAD: base, p: &observedProvider{collector: c}}
	if _, e = a.Open(nil, []byte{1}, []byte{2, 3}, []byte{4}); e != nil {
		t.Fatal(e)
	}
	if base.open != 1 || c.summary.Calls != 1 || c.summary.CallbackNS != 2 {
		t.Fatal("delegate delay entered observer cost")
	}
}
