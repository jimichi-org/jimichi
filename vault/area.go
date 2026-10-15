package vault

import (
	"crypto/rand"
	"errors"
	"fmt"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

const (
	rSize     = 32
	tagSize   = 16
	lenSize   = 2
	plainSize = RegionSize - rSize - tagSize
	keySize   = 32
	fetchSize = 16

	exchangePassword = "vault/password"
	exchangeVolume   = "vault/volume"
	exchangeBlock    = "vault/block"
	exchangeIdentity = "vault/identity"

	purposeVolume = "vault/volume"
	purposeBlock  = "vault/block"
	purposeFetch  = "vault/fetch"
)

var (
	errAEAD      = errors.New("vault: the suite's AEAD does not fit an area")
	errZeroFetch = errors.New("vault: zero fetch capability")
	errReadBack  = errors.New("vault: sealed data does not read back")
)

func areaOf(file []byte, s int) []byte {
	off := SaltSize + s*RegionSize
	return file[off : off+RegionSize : off+RegionSize]
}

func passwordKey(p jcrypto.CryptoProvider, salt []byte, password *secmem.Buffer) (*secmem.Buffer, error) {
	ctx, err := jcrypto.NewContext(p, exchangePassword, salt)
	if err != nil {
		return nil, err
	}
	w, err := p.PasswordKey(password, ctx)
	if err != nil {
		return nil, fmt.Errorf("vault: password key: %w", err)
	}
	return w, nil
}

func volumeKey(p jcrypto.CryptoProvider, w *secmem.Buffer, salt []byte, s int) (*secmem.Buffer, error) {
	ctx, err := jcrypto.NewContext(p, exchangeVolume, salt, []byte{byte(s)})
	if err != nil {
		return nil, err
	}
	k, err := p.DeriveKey(w, purposeVolume, ctx, keySize)
	if err != nil {
		return nil, fmt.Errorf("vault: volume key: %w", err)
	}
	return k, nil
}

// one key per seal: r is fresh at every write, so the nonce can stay zero and
// out of the file
func blockAEAD(p jcrypto.CryptoProvider, k *secmem.Buffer, s int, r []byte) (jcrypto.AEAD, []byte, error) {
	ctx, err := jcrypto.NewContext(p, exchangeBlock, []byte{byte(s)}, r)
	if err != nil {
		return nil, nil, err
	}
	kb, err := p.DeriveKey(k, purposeBlock, ctx, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: block key: %w", err)
	}
	defer kb.Release()
	a, err := p.NewAEAD(kb)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: block cipher: %w", err)
	}
	if a.Overhead() != tagSize {
		a.Destroy()
		return nil, nil, errAEAD
	}
	return a, ctx.Sum(), nil
}

// plain is the whole plaintext of the area: length, content and zeroes
func sealArea(p jcrypto.CryptoProvider, k *secmem.Buffer, s int, r, plain, area []byte) error {
	if len(plain) != plainSize || len(area) != RegionSize || len(r) != rSize {
		return errAEAD
	}
	a, ad, err := blockAEAD(p, k, s, r)
	if err != nil {
		return err
	}
	defer a.Destroy()
	copy(area, r)
	out := a.Seal(area[rSize:rSize:RegionSize], make([]byte, a.NonceSize()), plain, ad)
	if len(out) != RegionSize-rSize {
		return errAEAD
	}
	copy(area[rSize:], out)
	return nil
}

// every attempt decrypts into a buffer of its own: on a wrong tag the AVX2
// path of XChaCha20-Poly1305 clears its output, which must not be another
// attempt's plaintext
func openArea(p jcrypto.CryptoProvider, k *secmem.Buffer, s int, area, plain []byte) (bool, error) {
	if len(plain) != plainSize || len(area) != RegionSize {
		return false, errAEAD
	}
	a, ad, err := blockAEAD(p, k, s, area[:rSize])
	if err != nil {
		return false, err
	}
	defer a.Destroy()
	out, err := a.Open(plain[:0], make([]byte, a.NonceSize()), area[rSize:], ad)
	if err != nil {
		return false, nil
	}
	if len(out) != plainSize {
		return false, errAEAD
	}
	if &out[0] != &plain[0] {
		copy(plain, out)
		secmem.Zero(out)
	}
	return true, nil
}

// seals plain into area with a fresh r and opens it back into a buffer of its
// own, so a seal that does not open fails before anything is written
func sealChecked(p jcrypto.CryptoProvider, k *secmem.Buffer, s int, plain *secmem.Buffer, area []byte) error {
	r := make([]byte, rSize)
	if _, err := rand.Read(r); err != nil {
		return err
	}
	if err := sealArea(p, k, s, r, plain.Bytes(), area); err != nil {
		return err
	}
	return openedAs(p, k, s, area, plain)
}

func openedAs(p jcrypto.CryptoProvider, k *secmem.Buffer, s int, area []byte, plain *secmem.Buffer) error {
	back, err := secmem.New(plainSize)
	if err != nil {
		return err
	}
	defer back.Release()
	ok, err := openArea(p, k, s, area, back.Bytes())
	if err != nil {
		return err
	}
	if !ok || !back.Equal(plain) {
		return errReadBack
	}
	return nil
}

// the content length of an opened area; a written volume is never empty, and
// what follows the content is zero
func contentLength(plain []byte) (int, bool) {
	n := int(plain[0])<<8 | int(plain[1])
	if n == 0 || n > MaxContent {
		return 0, false
	}
	return n, allZero(plain[lenSize+n:])
}

// fill writes into the content part of plain; the length goes in front and
// the rest is cleared whatever fill left there, since the format needs zeroes
// under every policy
func fillContent(plain []byte, id *Identity, fill Fill) (int, error) {
	content := plain[lenSize : lenSize+MaxContent : lenSize+MaxContent]
	n := 0
	var err error
	if fill != nil {
		n, err = fill(id, content)
	}
	if err == nil && n > MaxContent {
		err = ErrTooLarge
	}
	if err == nil && n < 0 {
		err = fmt.Errorf("vault: fill gave a length of %d", n)
	}
	if err != nil {
		clear(plain)
		return 0, err
	}
	clear(content[n:])
	plain[0], plain[1] = byte(n>>8), byte(n)
	return n, nil
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
