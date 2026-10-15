package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// the three tests at the production cost of PasswordKey stay out of -short.
// Under -race one GOST stretch takes seconds, so the tests, the suites and the
// stretches that do not depend on each other run side by side
func eachProductionSuite(t *testing.T, run func(t *testing.T, p *spy)) {
	t.Helper()
	if testing.Short() {
		t.Skip("PasswordKey at production cost")
	}
	t.Parallel()
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()
			run(t, newSpy(t, provider(t, s)))
		})
	}
}

func TestProductionCreateOpen(t *testing.T) {
	eachProductionSuite(t, func(t *testing.T, p *spy) {
		path, _ := mustCreate(t, p, volume(t, "first password", []byte("decoy")), volume(t, "second password", []byte("real")))
		pws := []*secmem.Buffer{password(t, "first password"), password(t, "second password")}
		wants := []string{"decoy", "real"}
		pubs := make([][]byte, 2)
		err := parallel(2, func(i int) error {
			v, err := Open(p, path, pws[i])
			if err != nil {
				return err
			}
			defer v.Close()
			if string(v.Content()) != wants[i] {
				return fmt.Errorf("content %q, want %q", v.Content(), wants[i])
			}
			pubs[i] = v.Identity().Public()
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(pubs[0], pubs[1]) {
			t.Fatal("two volumes with one identity")
		}
		if n := p.count("PasswordKey"); n != 4 {
			t.Fatalf("%d stretches, want 4", n)
		}
	})
}

// a wrong password costs one stretch and the work of an open up to its
// identity; a container made with the cheap stretch does not open here
func TestProductionWrongPassword(t *testing.T) {
	eachProductionSuite(t, func(t *testing.T, p *spy) {
		path, _ := mustCreate(t, p, volume(t, "password", []byte("x")))
		cheapFile := mustFile(t, cheap{p.CryptoProvider}, volume(t, "password", []byte("x")))
		p.reset()
		wrong, cheapPassword := password(t, "wrong password"), password(t, "password")
		err := parallel(2, func(i int) error {
			var err error
			if i == 0 {
				_, err = Open(p, path, wrong)
			} else {
				_, _, err = open(newSpy(t, p.CryptoProvider), cheapFile, cheapPassword)
			}
			if !errors.Is(err, ErrNoVolume) {
				return fmt.Errorf("open %d: %v, want ErrNoVolume", i, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"Hash", "PasswordKey", "Hash", "DeriveKey " + purposeVolume, "Hash", "DeriveKey " + purposeVolume}
		for range 2 {
			want = append(want, "Hash", "DeriveKey "+purposeBlock, "NewAEAD", "Open")
		}
		if got := p.seen(); !slices.Equal(got, want) {
			t.Fatalf("a wrong password costs %v\nwant %v", got, want)
		}
	})
}

// the file and the password give the identity of the draft again; a new
// container under the same password gives another
func TestProductionIdentity(t *testing.T) {
	eachProductionSuite(t, func(t *testing.T, p *spy) {
		d, err := Prepare(p, volume(t, "password", []byte("contact")))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		pub, fetch := d.Identity().Public(), bytes.Clone(d.Identity().Fetch().Bytes())
		path := vaultPath(t)
		if err := d.Write(path, nil); err != nil {
			t.Fatal(err)
		}
		file, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		pw := password(t, "password")
		err = parallel(2, func(i int) error {
			if i == 1 {
				other, err := Prepare(p, Contents{Password: pw, Fill: content([]byte("contact"))})
				if err != nil {
					return err
				}
				defer other.Close()
				if bytes.Equal(other.Identity().Public(), pub) || bytes.Equal(other.Identity().Fetch().Bytes(), fetch) {
					return errors.New("a new container under the same password gave the same identity")
				}
				return nil
			}
			v, _, err := open(p, file, pw)
			if err != nil {
				return err
			}
			defer v.Close()
			if !bytes.Equal(v.Identity().Public(), pub) || !bytes.Equal(v.Identity().Fetch().Bytes(), fetch) {
				return errors.New("an open gave another identity than the draft")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
