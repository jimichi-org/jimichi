package noisekdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"testing"
)

// RFC 5869 appendix A.1, first 42 output bytes
func TestRFC5869(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, b, err := Derive(sha256.New, decode("000102030405060708090a0b0c"), bytes.Repeat([]byte{0x0b}, 22), decode("f0f1f2f3f4f5f6f7f8f9"), secmem.New)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	defer b.Release()
	got := append(append([]byte(nil), a.Bytes()...), b.Bytes()...)
	defer secmem.Zero(got)
	if !bytes.Equal(got[:42], decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")) {
		t.Fatal("RFC 5869 output mismatch")
	}
}
