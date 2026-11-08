package gost

import (
	"bytes"
	"errors"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/noise"
	"testing"
)

func TestSecondSplitOutputAllocationRollback(t *testing.T) {
	for _, transport := range []bool{false, true} {
		p := New()
		key := func() *noise.KeyPair {
			b, pub, err := p.GenerateEphemeral()
			if err != nil {
				t.Fatal(err)
			}
			k := noise.NewKeyPair(p, b, pub)
			t.Cleanup(k.Close)
			return k
		}
		si, sr := key(), key()
		i, err := noise.NewNoise(noise.NoiseConfig{Provider: p, Pattern: noise.KK, Initiator: true, Local: si, RemoteStatic: sr.Public()})
		if err != nil {
			t.Fatal(err)
		}
		defer i.Close()
		r, err := noise.NewNoise(noise.NoiseConfig{Provider: p, Pattern: noise.KK, Local: sr, RemoteStatic: si.Public()})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		first, err := i.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadMessage(first); err != nil {
			t.Fatal(err)
		}
		second, err := r.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := i.ReadMessage(second); err != nil {
			t.Fatal(err)
		}
		sentinel := errors.New("second output allocation failure")
		var staged *secmem.Buffer
		calls := 0
		p.noiseAlloc = func(n int) (*secmem.Buffer, error) {
			calls++
			if calls == 2 {
				return nil, sentinel
			}
			b, err := secmem.New(n)
			staged = b
			return b, err
		}
		if transport {
			a, b, _, err := i.SplitTransport()
			if a != nil || b != nil || !errors.Is(err, sentinel) {
				t.Fatal("partial split transport returned")
			}
		} else {
			a, b, _, err := i.Split()
			if a != nil || b != nil || !errors.Is(err, sentinel) {
				t.Fatal("partial split returned")
			}
		}
		if staged == nil || staged.Bytes() != nil || !i.Done() {
			t.Fatal("split failure retained staged output or changed completion")
		}
		p.noiseAlloc = nil
		if transport {
			a, b, ih, err := i.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer a.Destroy()
			defer b.Destroy()
			ra, rb, rh, err := r.SplitTransport()
			if err != nil {
				t.Fatal(err)
			}
			defer ra.Destroy()
			defer rb.Destroy()
			if !bytes.Equal(ih, rh) {
				t.Fatal("failed split changed hash")
			}
			out, err := a.Encrypt(nil, []byte{1})
			if err != nil {
				t.Fatal(err)
			}
			if pt, err := ra.Decrypt(nil, out); err != nil || !bytes.Equal(pt, []byte{1}) {
				t.Fatal("failed split changed direction keys")
			}
		} else {
			a, b, ih, err := i.Split()
			if err != nil {
				t.Fatal(err)
			}
			defer a.Release()
			defer b.Release()
			ra, rb, rh, err := r.Split()
			if err != nil {
				t.Fatal(err)
			}
			defer ra.Release()
			defer rb.Release()
			if !a.Equal(ra) || !b.Equal(rb) || !bytes.Equal(ih, rh) {
				t.Fatal("failed split changed hash or direction keys")
			}
		}
		check, err := si.NoiseDH(sr.Public())
		if err != nil {
			t.Fatal("split released borrowed static")
		}
		check.Release()
	}
}
