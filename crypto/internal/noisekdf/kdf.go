package noisekdf

import (
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func Pair(h func() hash.Hash, ck, input *secmem.Buffer, allocate func(int) (*secmem.Buffer, error)) (*secmem.Buffer, *secmem.Buffer, error) {
	if ck == nil || len(ck.Bytes()) != 32 || input != nil && len(input.Bytes()) != 32 {
		return nil, nil, jcrypto.ErrBadKeySize
	}
	var ikm []byte
	if input != nil {
		ikm = input.Bytes()
	}
	return Derive(h, ck.Bytes(), ikm, nil, allocate)
}

func Derive(h func() hash.Hash, salt, input, info []byte, allocate func(int) (*secmem.Buffer, error)) (*secmem.Buffer, *secmem.Buffer, error) {
	prk := hkdf.Extract(h, input, salt)
	defer secmem.Zero(prk)
	r := hkdf.Expand(h, prk, info)
	first, err := allocate(32)
	if err != nil {
		return nil, nil, err
	}
	second, err := allocate(32)
	if err != nil {
		first.Release()
		return nil, nil, err
	}
	if _, err = io.ReadFull(r, first.Bytes()); err == nil {
		_, err = io.ReadFull(r, second.Bytes())
	}
	if err != nil {
		first.Release()
		second.Release()
		return nil, nil, err
	}
	return first, second, nil
}
