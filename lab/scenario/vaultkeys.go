package scenario

import (
	"errors"
	"fmt"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/vault"
)

// the formulas of the CRYPTO container section written again on the provider: lab finds
// the area a password opens, and reseals one, without a seam in vault
const (
	areaR     = 32
	areaTag   = 16
	areaPlain = vault.RegionSize - areaR - areaTag
	areaKey   = 32
)

var (
	errAreaAEAD = errors.New("scenario: the suite's AEAD does not fit an area")
	errNoArea   = errors.New("scenario: the password opens no area or both")
)

func areaOf(file []byte, s int) []byte {
	off := vault.SaltSize + s*vault.RegionSize
	return file[off : off+vault.RegionSize : off+vault.RegionSize]
}

func stretch(p jcrypto.CryptoProvider, salt []byte, password *secmem.Buffer) (*secmem.Buffer, error) {
	ctx, err := jcrypto.NewContext(p, "vault/password", salt)
	if err != nil {
		return nil, err
	}
	return p.PasswordKey(password, ctx)
}

func volumeKey(p jcrypto.CryptoProvider, w *secmem.Buffer, salt []byte, s int) (*secmem.Buffer, error) {
	ctx, err := jcrypto.NewContext(p, "vault/volume", salt, []byte{byte(s)})
	if err != nil {
		return nil, err
	}
	return p.DeriveKey(w, "vault/volume", ctx, areaKey)
}

// K_b and th_b, the associated data of the area
func blockKey(p jcrypto.CryptoProvider, k *secmem.Buffer, s int, r []byte) (*secmem.Buffer, []byte, error) {
	ctx, err := jcrypto.NewContext(p, "vault/block", []byte{byte(s)}, r)
	if err != nil {
		return nil, nil, err
	}
	kb, err := p.DeriveKey(k, "vault/block", ctx, areaKey)
	if err != nil {
		return nil, nil, err
	}
	return kb, ctx.Sum(), nil
}

func blockAEAD(p jcrypto.CryptoProvider, k *secmem.Buffer, s int, r []byte) (jcrypto.AEAD, []byte, error) {
	kb, ad, err := blockKey(p, k, s, r)
	if err != nil {
		return nil, nil, err
	}
	defer kb.Release()
	a, err := p.NewAEAD(kb)
	if err != nil {
		return nil, nil, err
	}
	if a.Overhead() != areaTag {
		a.Destroy()
		return nil, nil, errAreaAEAD
	}
	return a, ad, nil
}

func sealArea(p jcrypto.CryptoProvider, k *secmem.Buffer, s int, r, plain, area []byte) error {
	if len(r) != areaR || len(plain) != areaPlain || len(area) != vault.RegionSize {
		return errAreaAEAD
	}
	a, ad, err := blockAEAD(p, k, s, r)
	if err != nil {
		return err
	}
	defer a.Destroy()
	out := a.Seal(nil, make([]byte, a.NonceSize()), plain, ad)
	if len(out) != vault.RegionSize-areaR {
		return errAreaAEAD
	}
	copy(area, r)
	copy(area[areaR:], out)
	return nil
}

func openArea(p jcrypto.CryptoProvider, k *secmem.Buffer, s int, area, plain []byte) (bool, error) {
	if len(plain) != areaPlain || len(area) != vault.RegionSize {
		return false, errAreaAEAD
	}
	a, ad, err := blockAEAD(p, k, s, area[:areaR])
	if err != nil {
		return false, err
	}
	defer a.Destroy()
	out, err := a.Open(plain[:0], make([]byte, a.NonceSize()), area[areaR:], ad)
	if err != nil {
		return false, nil
	}
	if len(out) != areaPlain {
		return false, errAreaAEAD
	}
	if &out[0] != &plain[0] {
		copy(plain, out)
		secmem.Zero(out)
	}
	return true, nil
}

// one stretch, both areas tried, as Open does; the area is what vault never
// tells
func openedArea(p jcrypto.CryptoProvider, file []byte, password *secmem.Buffer) (int, error) {
	if len(file) != vault.FileSize {
		return 0, vault.ErrNotVault
	}
	salt := file[:vault.SaltSize]
	w, err := stretch(p, salt, password)
	if err != nil {
		return 0, err
	}
	defer w.Release()
	plain, err := secmem.New(areaPlain)
	if err != nil {
		return 0, err
	}
	defer plain.Release()
	var opened [2]bool
	for s := range opened {
		k, err := volumeKey(p, w, salt, s)
		if err != nil {
			return 0, err
		}
		opened[s], err = openArea(p, k, s, areaOf(file, s), plain.Bytes())
		k.Release()
		if err != nil {
			return 0, err
		}
	}
	if opened[0] == opened[1] {
		return 0, errNoArea
	}
	if opened[1] {
		return 1, nil
	}
	return 0, nil
}

// the model of a volume updated in place: the same plaintext under a fresh r
func reseal(p jcrypto.CryptoProvider, file []byte, s int, password *secmem.Buffer, r []byte) error {
	salt := file[:vault.SaltSize]
	w, err := stretch(p, salt, password)
	if err != nil {
		return err
	}
	k, err := volumeKey(p, w, salt, s)
	w.Release()
	if err != nil {
		return err
	}
	defer k.Release()
	plain, err := secmem.New(areaPlain)
	if err != nil {
		return err
	}
	defer plain.Release()
	ok, err := openArea(p, k, s, areaOf(file, s), plain.Bytes())
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("scenario: area %d does not open under its password", s)
	}
	return sealArea(p, k, s, r, plain.Bytes(), areaOf(file, s))
}

// an empty volume as vault seals one: length 0 and zeroes under a key no
// password derives
func sealEmpty(p jcrypto.CryptoProvider, s int, key, r, area []byte) error {
	k, err := secmem.NewFrom(key)
	if err != nil {
		return err
	}
	defer k.Release()
	plain, err := secmem.New(areaPlain)
	if err != nil {
		return err
	}
	defer plain.Release()
	return sealArea(p, k, s, r, plain.Bytes(), area)
}
