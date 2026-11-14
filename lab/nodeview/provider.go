package nodeview

import (
	"github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/wire"
)

type keyTag struct {
	purpose string
	context [32]byte
	locked  bool
}
type observedProvider struct {
	crypto.CryptoProvider
	collector *collector
	private   *privateCapture
}

func (p *observedProvider) DeriveKey(secret *secmem.Buffer, purpose string, ctx crypto.Context, size int) (*secmem.Buffer, error) {
	k, e := p.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
	c := p.collector
	start := int64(0)
	if c != nil {
		start = c.now()
	}
	if e == nil && k != nil && (purpose == "setup" || purpose == "cell" || purpose == "e2e/step/key") {
		tag := keyTag{purpose: purpose, locked: k.Locked()}
		copy(tag.context[:], ctx.Sum())
		if c != nil {
			c.mu.Lock()
			if len(c.keys)+len(c.view.setups) >= maxContexts {
				c.fail(ReasonLimit)
			} else if _, exists := c.keys[k]; exists {
				c.fail(ReasonContract)
			} else {
				c.keys[k] = tag
				c.inventory()
			}
			if !tag.locked {
				c.fail(ReasonContract)
			}
			c.mu.Unlock()
		}
		if p.private != nil {
			p.private.derived(k, tag)
		}
	}
	if c != nil {
		c.record(start, true)
	}
	return k, e
}

func (p *observedProvider) NewAEAD(k *secmem.Buffer) (crypto.AEAD, error) {
	a, e := p.CryptoProvider.NewAEAD(k)
	c := p.collector
	start := int64(0)
	if c != nil {
		start = c.now()
	}
	if e != nil || a == nil {
		if c != nil {
			c.record(start, true)
		}
		return a, e
	}
	var tag keyTag
	var generation uint32
	if c != nil {
		c.mu.Lock()
		tag = c.keys[k]
		delete(c.keys, k)
		generation = c.generation()
		if tag.purpose == "cell" {
			c.hopCreated(generation, tag)
		}
		c.recordLocked(start, true)
		c.mu.Unlock()
	}
	if p.private != nil {
		tag = p.private.consumed(k, tag)
	}
	return &observedAEAD{AEAD: a, p: p, tag: tag, generation: generation}, nil
}

type observedAEAD struct {
	crypto.AEAD
	p          *observedProvider
	tag        keyTag
	generation uint32
}

func (a *observedAEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	// an in-place primitive can overwrite the borrowed input before observation
	var input arenaRef
	c := a.p.collector
	if c != nil {
		start := c.now()
		c.mu.Lock()
		input = c.copy(ciphertext)
		c.recordLocked(start, false)
		c.mu.Unlock()
	}
	out, e := a.AEAD.Open(dst, nonce, ciphertext, ad)
	if c != nil {
		t := c.now()
		c.mu.Lock()
		if e == nil {
			plain := out
			if len(out) < len(dst) {
				c.fail(ReasonContract)
				plain = nil
			} else {
				plain = out[len(dst):]
			}
			switch a.tag.purpose {
			case "setup":
				c.setupOpened(a.generation, a.tag, nonce, c.arena.bytes(input), plain, ad, t)
			case "cell":
				c.hopOperation(a.generation, true, nonce, c.arena.bytes(input), plain, ad, t)
			case "":
				if len(ad) == 0 && len(plain) == wire.CellSize {
					c.transport(a.generation, true, c.arena.bytes(input), plain, t)
				}
			}
		}
		c.arena.erase(&input)
		c.recordLocked(t, true)
		c.mu.Unlock()
	}
	return out, e
}

func (a *observedAEAD) Seal(dst, nonce, plain, ad []byte) []byte {
	c := a.p.collector
	var input arenaRef
	if c != nil {
		start := c.now()
		c.mu.Lock()
		input = c.copy(plain)
		c.recordLocked(start, false)
		c.mu.Unlock()
	}
	if a.p.private != nil {
		a.p.private.beforeSeal(a.tag, nonce, plain, ad)
	}
	out := a.AEAD.Seal(dst, nonce, plain, ad)
	if c != nil {
		t := c.now()
		c.mu.Lock()
		ciphertext := out
		if len(out) < len(dst) {
			c.fail(ReasonContract)
			ciphertext = nil
		} else {
			ciphertext = out[len(dst):]
		}
		switch a.tag.purpose {
		case "cell":
			c.hopOperation(a.generation, false, nonce, c.arena.bytes(input), ciphertext, ad, t)
		case "":
			if len(ad) == 0 && input.size == wire.CellSize {
				c.transport(a.generation, false, ciphertext, c.arena.bytes(input), t)
			}
		}
		c.arena.erase(&input)
		c.recordLocked(t, true)
		c.mu.Unlock()
	}
	if a.p.private != nil {
		a.p.private.afterSeal(a.tag, nonce, out, ad)
	}
	return out
}

func (a *observedAEAD) Destroy() {
	a.AEAD.Destroy()
	if c := a.p.collector; c != nil {
		t := c.now()
		c.mu.Lock()
		c.released(a.generation, a.tag, t)
		c.recordLocked(t, true)
		c.mu.Unlock()
	}
}
