package c25519

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func pairHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pairSecret(t *testing.T, raw []byte) *secmem.Buffer {
	t.Helper()
	b, err := secmem.NewFrom(bytes.Clone(raw))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// the unclamped output of the golden vectors of providertest is HKDF-Expand
// with one block, written here through x/crypto hkdf, and the private key is
// that output clamped
func TestDerivePairIsClampedExpand(t *testing.T) {
	p := New()
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0x40 + byte(i)
	}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	for _, v := range []struct {
		a    byte
		raw  string
		priv string
	}{
		{0x00, "efe63d279594802f6dfa444e28b3729e1a05441414a68bfa97257af799752218",
			"e8e63d279594802f6dfa444e28b3729e1a05441414a68bfa97257af799752258"},
		{0x01, "d0807878d286f04711be6f7daa52b676221811d0d6a006a1874dd46f57150d8e",
			"d0807878d286f04711be6f7daa52b676221811d0d6a006a1874dd46f57150d4e"},
	} {
		ctx, err := jcrypto.NewContext(p, "vault/identity", salt, []byte{v.a})
		if err != nil {
			t.Fatal(err)
		}
		label := []byte("jimichi/v2/c25519/pair/1")
		raw := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.Expand(sha256.New, k, info(label, ctx.Sum())), raw); err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(raw) != v.raw {
			t.Fatalf("a %02x: HKDF-Expand %x, want %s", v.a, raw, v.raw)
		}
		clamped := bytes.Clone(raw)
		clamp(clamped)
		if hex.EncodeToString(clamped) != v.priv {
			t.Fatalf("a %02x: clamp(raw) %x, want %s", v.a, clamped, v.priv)
		}

		secret := pairSecret(t, k)
		priv, pub, err := p.DerivePair(secret, ctx)
		secret.Release()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(priv.Bytes(), clamped) {
			t.Fatalf("a %02x: DerivePair stored %x, want the clamped expand", v.a, priv.Bytes())
		}
		fromRaw, err := curve25519.X25519(raw, curve25519.Basepoint)
		priv.Release()
		if err != nil || !bytes.Equal(fromRaw, pub) {
			t.Fatalf("a %02x: X25519 of the unclamped output differs from the public key: %v", v.a, err)
		}
	}
}

// RFC 7748, 6.1: Alice's key changes in byte 0 (77 to 70) and byte 31 (2a to
// 6a). The clamped bytes themselves are compared, since X25519 would clamp a
// wrongly clamped key again and hide the mistake in the public key
func TestClampKnownAnswer(t *testing.T) {
	k := pairHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	clamp(k)
	if hex.EncodeToString(k) != "70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a" {
		t.Fatalf("clamp gave %x", k)
	}
	pub, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil || hex.EncodeToString(pub) != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" {
		t.Fatalf("X25519 of the clamped key %x, %v", pub, err)
	}
}

// bits 0-2 and 255 are clear and bit 254 set in every output, the bits X25519
// fixes anyway, so a derived key reveals nothing a generated one would not
func TestDerivePairBitsAreClamped(t *testing.T) {
	p := New()
	ctx, err := jcrypto.NewContext(p, "test", []byte("session-1"))
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; j < 64; j++ {
		raw := make([]byte, 32)
		raw[0], raw[31] = byte(j), byte(255-j)
		secret := pairSecret(t, raw)
		priv, _, err := p.DerivePair(secret, ctx)
		secret.Release()
		if err != nil {
			t.Fatal(err)
		}
		k := priv.Bytes()
		if k[0]&0x07 != 0 || k[31]&0x80 != 0 || k[31]&0x40 == 0 {
			t.Fatalf("secret %d: private key %x is not clamped", j, k)
		}
		priv.Release()
	}
}
