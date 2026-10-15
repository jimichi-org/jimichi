package vault

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// every flipped bit of an area keeps that area from opening under the key
// that sealed it, checked on the area function for both areas of a file with
// two volumes; every flipped bit of the salt keeps the whole open from finding
// the volume. An open tries each area on its own bytes, so a bit of the other
// area leaves the opened volume as it was: the full opens at the borders of
// the fields check that too. Every bit on c25519 without -race; under -race
// and on GOST a fixed sample of 512 bits, one bit of every salt byte and the
// borders
func TestBitFlips(t *testing.T) {
	t.Parallel()
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()
			p := cheap{provider(t, s)}
			pw, other := password(t, "the password"), password(t, "the other password")
			body := []byte("integrity of the opened volume")
			_, file := mustCreate(t, p, Contents{Password: pw, Fill: content(body)}, Contents{Password: other, Fill: content([]byte("the other volume"))})
			_, own := mustOpen(t, p, file, pw)
			var sealing [2]*secmem.Buffer
			sealing[own], sealing[1-own] = areaKeys(t, p, file, pw)[own], areaKeys(t, p, file, other)[1-own]
			for a := range sealing {
				if ok, err := openArea(p, sealing[a], a, areaOf(file, a), make([]byte, plainSize)); err != nil || !ok {
					t.Fatalf("area %d does not open under the key that sealed it: %v", a, err)
				}
			}
			bits, borders := flipSample(own)
			if s == jcrypto.SuiteC25519 && !raceOn {
				bits = bits[:0]
				for i := range FileSize * 8 {
					bits = append(bits, i)
				}
			}
			err := parallel(len(bits), func(i int) error {
				bit := bits[i]
				pos := bit / 8
				f := bytes.Clone(file)
				f[pos] ^= 1 << (bit % 8)
				if pos >= SaltSize {
					a := (pos - SaltSize) / RegionSize
					ok, err := openArea(p, sealing[a], a, areaOf(f, a), make([]byte, plainSize))
					if err != nil || ok {
						return fmt.Errorf("bit %d: area %d opens: %v, %v", bit, a, ok, err)
					}
				}
				if pos >= SaltSize && !borders[bit] {
					return nil
				}
				v, area, err := open(p, f, pw)
				if v != nil {
					defer v.Close()
				}
				inOther := pos >= SaltSize+(1-own)*RegionSize && pos < SaltSize+(2-own)*RegionSize
				switch {
				case inOther && err != nil:
					return fmt.Errorf("bit %d of the other area: %w", bit, err)
				case inOther && (area != own || !bytes.Equal(v.Content(), body)):
					return fmt.Errorf("bit %d of the other area changed the volume", bit)
				case !inOther && !errors.Is(err, ErrNoVolume):
					return fmt.Errorf("bit %d: %v, want ErrNoVolume", bit, err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// the sample, and the bits at the borders of the fields of both areas: the
// first and last bytes of r, of the ciphertext and of the tag
func flipSample(own int) ([]int, map[int]bool) {
	rng := rand.New(rand.NewPCG(20, 26))
	var bits []int
	for range 512 {
		bits = append(bits, rng.IntN(FileSize*8))
	}
	for i := range SaltSize {
		bits = append(bits, i*8+i%8)
	}
	borders := map[int]bool{}
	for _, area := range []int{own, 1 - own} {
		base := SaltSize + area*RegionSize
		for _, off := range []int{0, rSize - 1, rSize, RegionSize - tagSize - 1, RegionSize - tagSize, RegionSize - 1} {
			for _, b := range []int{(base + off) * 8, (base+off)*8 + 7} {
				bits = append(bits, b)
				borders[b] = true
			}
		}
	}
	return bits, borders
}

func TestAreasSwapped(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		_, file := mustCreate(t, p, volume(t, "a", []byte("x")), volume(t, "b", []byte("y")))
		swapped := bytes.Clone(file)
		copy(swapped[SaltSize:], areaOf(file, 1))
		copy(swapped[SaltSize+RegionSize:], areaOf(file, 0))
		for _, pw := range []string{"a", "b"} {
			_, _, err := open(p, swapped, password(t, pw))
			wantErr(t, "swapped areas", err, ErrNoVolume)
		}
		other := bytes.Clone(file)
		copy(other[:SaltSize], seq(0, SaltSize))
		_, _, err := open(p, other, password(t, "a"))
		wantErr(t, "another salt", err, ErrNoVolume)
	})
}

func TestTruncatedOrExtended(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		path, file := mustCreate(t, p, volume(t, "a", []byte("x")))
		pw := password(t, "a")
		for name, f := range map[string][]byte{
			"one byte short":  file[:FileSize-1],
			"one area":        file[:SaltSize+RegionSize],
			"one byte longer": append(bytes.Clone(file), 0),
			"another area":    append(bytes.Clone(file), file[SaltSize:SaltSize+RegionSize]...),
		} {
			_, _, err := open(p, f, pw)
			wantErr(t, name, err, ErrNotVault)
			if err := os.WriteFile(path, f, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = Open(p, path, pw)
			wantErr(t, name+" on disk", err, ErrNotVault)
		}
	})
}

// someone who can write the file between two seizures puts a fresh empty
// volume over the other area: the opened volume does not change, the other
// password finds nothing
func TestOtherAreaReplaced(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		_, file := mustCreate(t, p, volume(t, "a", []byte("first")), volume(t, "b", []byte("second")))
		before, sa := mustOpen(t, p, file, password(t, "a"))
		replaced := bytes.Clone(file)
		if err := sealEmpty(p, 1-sa, areaOf(replaced, 1-sa)); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(replaced, file) {
			t.Fatal("the replacement changed nothing")
		}
		after, s := mustOpen(t, p, replaced, password(t, "a"))
		if s != sa || string(after.Content()) != "first" || !bytes.Equal(after.Identity().Public(), before.Identity().Public()) {
			t.Fatal("the opened volume changed with the other area")
		}
		_, _, err := open(p, replaced, password(t, "b"))
		wantErr(t, "the replaced volume", err, ErrNoVolume)
	})
}
