package vault

import (
	"errors"
	"fmt"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// a refused sample (below 2^-128) and a zero fetch capability (about 2^-128)
// cannot come from a sound file: Prepare fails without a file and Open calls
// the volume corrupt. A memory error is not corruption and comes back as it
// is. Nothing is retried, so DerivePair runs once per volume
func TestDerivationFaults(t *testing.T) {
	notLocked := fmt.Errorf("%w: mlock 4096 bytes (check RLIMIT_MEMLOCK)", secmem.ErrNotLocked)
	cases := []struct {
		name     string
		set      func(s *spy, at int)
		prepare  error
		open     error
		notMasks error
	}{
		{"no scalar", func(s *spy, at int) { s.pairErr, s.pairErrAt = jcrypto.ErrNoScalar, at }, jcrypto.ErrNoScalar, ErrCorrupt, nil},
		{"not locked", func(s *spy, at int) { s.pairErr, s.pairErrAt = notLocked, at }, secmem.ErrNotLocked, secmem.ErrNotLocked, ErrCorrupt},
		{"zero fetch", func(s *spy, at int) { s.zeroFetchAt = at }, errZeroFetch, ErrCorrupt, nil},
	}
	eachSuite(t, func(t *testing.T, p *spy) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, sound := mustCreate(t, p, volume(t, "a", []byte("x")))

				for _, at := range []int{1, 2} {
					p.reset()
					tc.set(p, at)
					path := vaultPath(t)
					err := Create(p, path, volume(t, "a", []byte("x")), volume(t, "b", []byte("y")))
					wantErr(t, "Create", err, tc.prepare)
					if tc.notMasks != nil && errors.Is(err, tc.notMasks) {
						t.Fatalf("Create: %v reads as %v", err, tc.notMasks)
					}
					noFile(t, path)
					if n := p.count("DerivePair"); n != at {
						t.Fatalf("Create with a fault at volume %d: %d DerivePair calls, want %d", at, n, at)
					}
					p.pairErr, p.zeroFetchAt = nil, 0
				}

				p.reset()
				tc.set(p, 1)
				_, _, err := open(p, sound, password(t, "a"))
				wantErr(t, "open", err, tc.open)
				if tc.notMasks != nil && errors.Is(err, tc.notMasks) {
					t.Fatalf("open: %v reads as %v", err, tc.notMasks)
				}
				if n := p.count("DerivePair"); n != 1 {
					t.Fatalf("open: %d DerivePair calls, want 1", n)
				}
				p.pairErr, p.zeroFetchAt = nil, 0
			})
		}
	})
}

// a memory error anywhere in an open is reported as such, never as a wrong
// password or a corrupt volume
func TestOpenMemoryError(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		_, file := mustCreate(t, p, volume(t, "a", []byte("x")))
		failing := &failingKDF{CryptoProvider: p.CryptoProvider, purpose: purposeBlock}
		_, _, err := open(failing, file, password(t, "a"))
		wantErr(t, "a block key without memory", err, secmem.ErrNotMapped)
		if errors.Is(err, ErrNoVolume) || errors.Is(err, ErrCorrupt) {
			t.Fatalf("a memory error reads as %v", err)
		}
		err = Create(failing, vaultPath(t), volume(t, "a", []byte("x")))
		wantErr(t, "a seal without memory", err, secmem.ErrNotMapped)
	})
}

type failingKDF struct {
	jcrypto.CryptoProvider
	purpose string
}

func (f *failingKDF) DeriveKey(secret *secmem.Buffer, purpose string, ctx jcrypto.Context, size int) (*secmem.Buffer, error) {
	if purpose == f.purpose {
		return nil, fmt.Errorf("%w: mmap %d bytes", secmem.ErrNotMapped, size)
	}
	return f.CryptoProvider.DeriveKey(secret, purpose, ctx, size)
}
