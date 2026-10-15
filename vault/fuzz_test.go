package vault

import (
	"bytes"
	"errors"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

// whatever the bytes, an open answers with one of its errors or with the
// volume of the seed, and only when the salt and that area are the seed's
func FuzzOpen(f *testing.F) {
	p := cheap{provider(f, suites[0])}
	pw := password(f, "fuzz")
	seed, own := fixedFile(f, p, "fuzz", []byte("seed content"))
	f.Add(seed)
	f.Add(seed[:FileSize-1])
	f.Add(append(bytes.Clone(seed), 0))
	flipped := bytes.Clone(seed)
	flipped[SaltSize+own*RegionSize+100] ^= 1
	f.Add(flipped)
	f.Add(make([]byte, FileSize))
	f.Fuzz(func(t *testing.T, file []byte) {
		v, s, err := open(p, file, pw)
		if err != nil {
			for _, known := range []error{ErrNotVault, ErrNoVolume, ErrCorrupt} {
				if errors.Is(err, known) {
					return
				}
			}
			t.Fatalf("open: %v", err)
		}
		defer v.Close()
		if s != own || !bytes.Equal(file[:SaltSize], seed[:SaltSize]) || !bytes.Equal(areaOf(file, s), areaOf(seed, s)) {
			t.Fatal("a volume opened from bytes that are not the seed's")
		}
		if string(v.Content()) != "seed content" {
			t.Fatalf("content %q", v.Content())
		}
	})
}

// the same bytes in every fuzzing worker: fixed salt, r and empty key
func fixedFile(t testing.TB, p jcrypto.CryptoProvider, pw string, body []byte) ([]byte, int) {
	t.Helper()
	const own = 1
	file := make([]byte, FileSize)
	copy(file, seq(0x00, SaltSize))
	w, err := passwordKey(p, file[:SaltSize], password(t, pw))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Release()
	k, err := volumeKey(p, w, file[:SaltSize], own)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Release()
	for _, a := range []struct {
		s    int
		key  []byte
		body []byte
	}{{own, nil, body}, {1 - own, seq(0xc0, keySize), nil}} {
		key := k
		if a.key != nil {
			key = buffer(t, a.key)
		}
		plain := buffer(t, make([]byte, plainSize))
		if _, err := fillContent(plain.Bytes(), nil, content(a.body)); err != nil {
			t.Fatal(err)
		}
		if err := sealArea(p, key, a.s, seq(byte(0x80+a.s), rSize), plain.Bytes(), areaOf(file, a.s)); err != nil {
			t.Fatal(err)
		}
	}
	return file, own
}
