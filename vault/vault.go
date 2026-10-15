package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

const (
	SaltSize   = 32
	RegionSize = 4096
	FileSize   = SaltSize + 2*RegionSize
	MaxContent = RegionSize - 32 - 16 - 2
)

var (
	ErrNotVault     = errors.New("vault: not a container")
	ErrNoVolume     = errors.New("vault: no volume opens with this password")
	ErrCorrupt      = errors.New("vault: the volume is corrupt")
	ErrExists       = errors.New("vault: the file exists")
	ErrSamePassword = errors.New("vault: two volumes under one password")
	ErrTooLarge     = errors.New("vault: content too large")
	ErrWritten      = errors.New("vault: the container is written")
	ErrEmpty        = errors.New("vault: a written volume is empty")

	errNoProvider = errors.New("vault: no provider")
	errVolumes    = errors.New("vault: one or two volumes")
	errClosed     = errors.New("vault: draft closed")
	errFixed      = errors.New("vault: an earlier attempt fixed the content")
)

// writes the content into buf, a locked buffer of MaxContent bytes, and
// returns its length
type Fill func(id *Identity, buf []byte) (int, error)

type Contents struct {
	Password *secmem.Buffer
	Fill     Fill
}

// a container before its only write: every volume but the first is sealed
type Draft struct {
	p jcrypto.CryptoProvider

	mu   sync.Mutex
	file []byte
	// what the first attempt that reached the drive wrote; every retry writes
	// it again, so the drive holds one version of the container
	image   []byte
	first   int
	key     *secmem.Buffer
	id      *Identity
	plain   *secmem.Buffer
	n       int
	written bool
	closed  bool
}

// what one password gives before its volume is sealed
type pending struct {
	key   *secmem.Buffer
	id    *Identity
	plain *secmem.Buffer
	n     int
}

func (v *pending) release() {
	if v.key != nil {
		v.key.Release()
	}
	v.id.close()
	if v.plain != nil {
		v.plain.Release()
	}
}

// nothing is written; the first volume's content may come later, with Write
func Prepare(p jcrypto.CryptoProvider, volumes ...Contents) (*Draft, error) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return prepare(p, b[0]&1, volumes)
}

// volume i goes into area bit xor i, so the place of a volume says nothing
// about how many there are
func place(bit byte, i int) int { return int(bit&1) ^ i }

func prepare(p jcrypto.CryptoProvider, bit byte, volumes []Contents) (*Draft, error) {
	if p == nil {
		return nil, errNoProvider
	}
	if len(volumes) == 0 || len(volumes) > 2 {
		return nil, errVolumes
	}
	// every refusal comes before the first stretch
	for _, v := range volumes {
		if v.Password == nil || !jcrypto.ValidPassword(v.Password.Bytes()) {
			return nil, fmt.Errorf("vault: %w", jcrypto.ErrBadPassword)
		}
	}
	if len(volumes) == 2 && volumes[0].Password.Equal(volumes[1].Password) {
		return nil, ErrSamePassword
	}
	d := &Draft{p: p, file: make([]byte, FileSize), first: place(bit, 0)}
	salt := d.file[:SaltSize]
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	done := false
	defer func() {
		if !done {
			d.Close()
		}
	}()
	for i, c := range volumes {
		s := place(bit, i)
		v, err := newVolume(p, salt, s, c)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			d.key, d.id, d.plain, d.n = v.key, v.id, v.plain, v.n
			continue
		}
		if v.n == 0 {
			v.release()
			return nil, ErrEmpty
		}
		err = sealChecked(p, v.key, s, v.plain, areaOf(d.file, s))
		v.release()
		if err != nil {
			return nil, err
		}
	}
	if len(volumes) == 1 {
		if err := sealEmpty(p, place(bit, 1), areaOf(d.file, place(bit, 1))); err != nil {
			return nil, err
		}
	}
	done = true
	return d, nil
}

// one stretch per volume; the identity comes right after the volume key, so
// fill can check a contact against it
func newVolume(p jcrypto.CryptoProvider, salt []byte, s int, c Contents) (*pending, error) {
	w, err := passwordKey(p, salt, c.Password)
	if err != nil {
		return nil, err
	}
	k, err := volumeKey(p, w, salt, s)
	w.Release()
	if err != nil {
		return nil, err
	}
	v := &pending{key: k}
	if v.id, err = deriveIdentity(p, k, salt, s); err != nil {
		v.release()
		return nil, err
	}
	if v.plain, err = secmem.New(plainSize); err != nil {
		v.release()
		return nil, err
	}
	if v.n, err = fillContent(v.plain.Bytes(), v.id, c.Fill); err != nil {
		v.release()
		return nil, err
	}
	return v, nil
}

// the same code as a volume, with no content, under a random key that no
// password derives
func sealEmpty(p jcrypto.CryptoProvider, s int, area []byte) error {
	k, err := secmem.New(keySize)
	if err != nil {
		return err
	}
	defer k.Release()
	if _, err := rand.Read(k.Bytes()); err != nil {
		return err
	}
	plain, err := secmem.New(plainSize)
	if err != nil {
		return err
	}
	defer plain.Release()
	return sealChecked(p, k, s, plain, area)
}

func (d *Draft) Identity() *Identity { return d.id }

// the only write of a container: it never replaces an existing file. fill may
// be nil. A Write that linked no file leaves the draft usable, with the bytes
// fixed once an attempt reached the drive; one that linked it spends the
// draft, and a failure after the link is ErrWritten with its cause
func (d *Draft) Write(path string, fill Fill) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.written:
		return ErrWritten
	case d.closed:
		return errClosed
	}
	if err := d.fill(fill); err != nil {
		return err
	}
	if d.n == 0 {
		return ErrEmpty
	}
	if err := vacant(path); err != nil {
		return err
	}
	if d.image == nil {
		file := bytes.Clone(d.file)
		if err := sealChecked(d.p, d.key, d.first, d.plain, areaOf(file, d.first)); err != nil {
			return err
		}
		d.image = file
	}
	linked, err := create(path, d.image)
	if !linked {
		return err
	}
	d.written = true
	if rerr := d.readBack(path, d.image); err == nil {
		err = rerr
	}
	d.key.Release()
	d.plain.Release()
	if err != nil {
		return fmt.Errorf("%w, but %w", ErrWritten, err)
	}
	return nil
}

// once the bytes are fixed another content would be a second version of the
// container, so fill writes into a buffer of its own and must match
func (d *Draft) fill(fill Fill) error {
	if fill == nil {
		return nil
	}
	if d.image == nil {
		n, err := fillContent(d.plain.Bytes(), d.id, fill)
		d.n = n
		return err
	}
	again, err := secmem.New(plainSize)
	if err != nil {
		return err
	}
	defer again.Release()
	if _, err := fillContent(again.Bytes(), d.id, fill); err != nil {
		return err
	}
	if !again.Equal(d.plain) {
		return errFixed
	}
	return nil
}

func (d *Draft) readBack(path string, want []byte) error {
	got, err := readFile(path)
	if err != nil {
		return fmt.Errorf("vault: read back: %w", err)
	}
	if !bytes.Equal(got, want) {
		return errReadBack
	}
	return openedAs(d.p, d.key, d.first, areaOf(got, d.first), d.plain)
}

// releases what Take did not move
func (d *Draft) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if d.key != nil {
		d.key.Release()
	}
	if d.plain != nil {
		d.plain.Release()
	}
	d.id.close()
}

// Prepare and Write: the passwords and keys live no longer than the call
func Create(p jcrypto.CryptoProvider, path string, volumes ...Contents) error {
	d, err := Prepare(p, volumes...)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Write(path, nil)
}

type Volume struct {
	id    *Identity
	plain *secmem.Buffer
	n     int
}

// reads the file and changes nothing in it
func Open(p jcrypto.CryptoProvider, path string, password *secmem.Buffer) (*Volume, error) {
	file, err := readFile(path)
	if err != nil {
		return nil, err
	}
	v, _, err := open(p, file, password)
	return v, err
}

// both areas are tried in one order whatever the outcome, so the work does not
// show which area a password opens; the area is for the tests
func open(p jcrypto.CryptoProvider, file []byte, password *secmem.Buffer) (*Volume, int, error) {
	if p == nil {
		return nil, 0, errNoProvider
	}
	if len(file) != FileSize {
		return nil, 0, ErrNotVault
	}
	salt := file[:SaltSize]
	w, err := passwordKey(p, salt, password)
	if err != nil {
		return nil, 0, err
	}
	var keys, plains [2]*secmem.Buffer
	defer func() {
		for s := range keys {
			if keys[s] != nil {
				keys[s].Release()
			}
			if plains[s] != nil {
				plains[s].Release()
			}
		}
	}()
	for s := range keys {
		if keys[s], err = volumeKey(p, w, salt, s); err != nil {
			w.Release()
			return nil, 0, err
		}
	}
	w.Release()
	var opened [2]bool
	for s := range plains {
		if plains[s], err = secmem.New(plainSize); err != nil {
			return nil, 0, err
		}
		if opened[s], err = openArea(p, keys[s], s, areaOf(file, s), plains[s].Bytes()); err != nil {
			return nil, 0, err
		}
	}
	if opened[0] == opened[1] {
		if opened[0] {
			return nil, 0, ErrCorrupt
		}
		return nil, 0, ErrNoVolume
	}
	s := 0
	if opened[1] {
		s = 1
	}
	keys[1-s].Release()
	plains[1-s].Release()
	n, ok := contentLength(plains[s].Bytes())
	if !ok {
		return nil, 0, ErrCorrupt
	}
	id, err := deriveIdentity(p, keys[s], salt, s)
	keys[s].Release()
	if errors.Is(err, jcrypto.ErrNoScalar) || errors.Is(err, errZeroFetch) {
		return nil, 0, ErrCorrupt
	}
	if err != nil {
		return nil, 0, err
	}
	v := &Volume{id: id, plain: plains[s], n: n}
	plains[s] = nil
	return v, s, nil
}

// borrowed: valid until Close
func (v *Volume) Content() []byte {
	b := v.plain.Bytes()
	if b == nil {
		return nil
	}
	return b[lenSize : lenSize+v.n : lenSize+v.n]
}

func (v *Volume) Identity() *Identity { return v.id }

// releases what Take did not move
func (v *Volume) Close() {
	v.plain.Release()
	v.id.close()
}
