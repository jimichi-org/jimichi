package c25519

import (
	"bytes"
	"errors"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"testing"
)

func TestNoiseKDF2AllocationFailure(t *testing.T) {
	ck, _ := secmem.New(32)
	defer ck.Release()
	input, _ := secmem.New(32)
	defer input.Release()
	for i := range ck.Bytes() {
		ck.Bytes()[i] = byte(i + 1)
		input.Bytes()[i] = byte(i + 17)
	}
	beforeCK, beforeInput := bytes.Clone(ck.Bytes()), bytes.Clone(input.Bytes())
	sentinel := errors.New("allocation failure")
	for _, at := range []int{1, 2} {
		p := New()
		var allocated []*secmem.Buffer
		calls := 0
		p.noiseAlloc = func(n int) (*secmem.Buffer, error) {
			calls++
			if calls == at {
				return nil, sentinel
			}
			b, err := secmem.New(n)
			if b != nil {
				allocated = append(allocated, b)
			}
			return b, err
		}
		a, b, err := p.NoiseKDF2(ck, input)
		if a != nil || b != nil || !errors.Is(err, sentinel) {
			t.Fatal("partial KDF result returned")
		}
		for _, b := range allocated {
			if b.Bytes() != nil {
				t.Fatal("partial KDF allocation retained")
			}
		}
		if !bytes.Equal(ck.Bytes(), beforeCK) || !bytes.Equal(input.Bytes(), beforeInput) {
			t.Fatal("borrowed KDF input changed")
		}
		p.noiseAlloc = nil
		a, b, err = p.NoiseKDF2(ck, input)
		if err != nil {
			t.Fatal(err)
		}
		a.Release()
		b.Release()
	}
}
func TestNoiseDHAllocationFailure(t *testing.T) {
	p := New()
	priv, _, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Release()
	other, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	before := bytes.Clone(priv.Bytes())
	sentinel := errors.New("allocation failure")
	p.noiseAlloc = func(int) (*secmem.Buffer, error) { return nil, sentinel }
	if b, err := p.NoiseDH(priv, pub); b != nil || !errors.Is(err, sentinel) {
		t.Fatal("DH allocation failure lost")
	}
	if !bytes.Equal(before, priv.Bytes()) {
		t.Fatal("borrowed static changed")
	}
	p.noiseAlloc = nil
	b, err := p.NoiseDH(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	b.Release()
}
