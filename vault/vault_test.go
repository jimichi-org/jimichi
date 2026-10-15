package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func TestCreateOpenOneVolume(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		body := []byte("one volume")
		path, file := mustCreate(t, p, volume(t, "first password", body))
		if len(file) != FileSize {
			t.Fatalf("file of %d bytes, want %d", len(file), FileSize)
		}
		if _, err := os.Stat(path + tmpSuffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("tmp left after Create: %v", err)
		}
		v, err := Open(p, path, password(t, "first password"))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer v.Close()
		if !bytes.Equal(v.Content(), body) {
			t.Fatalf("content %q, want %q", v.Content(), body)
		}
		id := v.Identity()
		if f := id.Fetch(); f == nil || f.Len() != fetchSize || allZero(f.Bytes()) {
			t.Fatal("no fetch capability of 16 nonzero bytes")
		}
		if len(id.Public()) == 0 {
			t.Fatal("no public key")
		}
		_, err = Open(p, path, password(t, "other password"))
		wantErr(t, "a wrong password", err, ErrNoVolume)
	})
}

func TestCreateOpenTwoVolumes(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		_, file := mustCreate(t, p, volume(t, "first", []byte("decoy")), volume(t, "second", []byte("real")))
		a, sa := mustOpen(t, p, file, password(t, "first"))
		b, sb := mustOpen(t, p, file, password(t, "second"))
		if string(a.Content()) != "decoy" || string(b.Content()) != "real" {
			t.Fatalf("contents %q and %q", a.Content(), b.Content())
		}
		if sa == sb {
			t.Fatalf("both volumes in area %d", sa)
		}
		if bytes.Equal(a.Identity().Public(), b.Identity().Public()) || a.Identity().Fetch().Equal(b.Identity().Fetch()) {
			t.Fatal("two volumes with one identity")
		}
		_, _, err := open(p, file, password(t, "third"))
		wantErr(t, "a third password", err, ErrNoVolume)
	})
}

func TestPrepareThenWrite(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		d, err := Prepare(p, Contents{Password: password(t, "first")}, volume(t, "second", []byte("hidden")))
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		defer d.Close()
		priv, pub, fetch := d.Identity().Take()
		defer priv.Release()
		defer fetch.Release()
		if _, err := d.Identity().Agree(pub, jcrypto.Context{}); err == nil {
			t.Fatal("Agree after Take")
		}
		var seen []byte
		path := vaultPath(t)
		err = d.Write(path, func(id *Identity, buf []byte) (int, error) {
			seen = id.Public()
			if len(buf) != MaxContent || cap(buf) != MaxContent {
				t.Errorf("fill buffer of %d bytes, capacity %d", len(buf), cap(buf))
			}
			return copy(buf, "contact"), nil
		})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if !bytes.Equal(seen, pub) {
			t.Fatal("Write gave fill another identity")
		}
		wantErr(t, "a second Write", d.Write(path, nil), ErrWritten)
		d.Close()
		if priv.Bytes() == nil || fetch.Bytes() == nil {
			t.Fatal("Close released keys that Take had moved")
		}
		file, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := mustOpen(t, p, file, password(t, "first"))
		if string(v.Content()) != "contact" || !bytes.Equal(v.Identity().Public(), pub) || !v.Identity().Fetch().Equal(fetch) {
			t.Fatal("the written volume does not open to the content and identity of the draft")
		}
		w, _ := mustOpen(t, p, file, password(t, "second"))
		if string(w.Content()) != "hidden" {
			t.Fatalf("second volume %q", w.Content())
		}
	})
}

// the file and the password give the identity again; another password or
// another container give another one
func TestIdentityFollowsPasswordAndFile(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		body := []byte("the same contact")
		_, file := mustCreate(t, p, volume(t, "password", body))
		a, _ := mustOpen(t, p, file, password(t, "password"))
		b, _ := mustOpen(t, p, file, password(t, "password"))
		if !bytes.Equal(a.Identity().Public(), b.Identity().Public()) || !a.Identity().Fetch().Equal(b.Identity().Fetch()) {
			t.Fatal("two opens with one password gave two identities")
		}
		privA, _, fetchA := a.Identity().Take()
		privB, _, fetchB := b.Identity().Take()
		defer privA.Release()
		defer privB.Release()
		defer fetchA.Release()
		defer fetchB.Release()
		if !privA.Equal(privB) {
			t.Fatal("two opens with one password gave two private keys")
		}
		for name, f := range map[string][]byte{
			"another password":  mustFile(t, p, volume(t, "another password", body)),
			"another container": mustFile(t, p, volume(t, "password", body)),
		} {
			pw := "password"
			if name == "another password" {
				pw = name
			}
			c, _ := mustOpen(t, p, f, password(t, pw))
			if bytes.Equal(c.Identity().Public(), a.Identity().Public()) || c.Identity().Fetch().Equal(fetchA) {
				t.Fatalf("%s gave the same identity", name)
			}
		}
	})
}

func mustFile(t testing.TB, p jcrypto.CryptoProvider, volumes ...Contents) []byte {
	t.Helper()
	_, file := mustCreate(t, p, volumes...)
	return file
}

func TestRefusals(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		path := vaultPath(t)
		err := Create(p, path, volume(t, "same", []byte("a")), volume(t, "same", []byte("b")))
		wantErr(t, "two equal passwords", err, ErrSamePassword)

		_, err = Prepare(p)
		wantErr(t, "no volume", err, errVolumes)
		_, err = Prepare(p, volume(t, "a", nil), volume(t, "b", nil), volume(t, "c", nil))
		wantErr(t, "three volumes", err, errVolumes)
		_, err = Prepare(nil, volume(t, "a", nil))
		wantErr(t, "no provider", err, errNoProvider)

		p.reset()
		for _, bad := range []*secmem.Buffer{nil, password(t, "line\n"), password(t, strings.Repeat("a", jcrypto.PasswordMax+1))} {
			_, err = Prepare(p, volume(t, "good", []byte("a")), Contents{Password: bad, Fill: content([]byte("b"))})
			wantErr(t, "a bad second password", err, jcrypto.ErrBadPassword)
		}
		if n := p.count("PasswordKey"); n != 0 {
			t.Fatalf("a refused password cost %d stretches", n)
		}

		big := func(_ *Identity, buf []byte) (int, error) { return MaxContent + 1, nil }
		err = Create(p, path, Contents{Password: password(t, "a"), Fill: big})
		wantErr(t, "content over MaxContent", err, ErrTooLarge)
		err = Create(p, path, volume(t, "a", []byte("x")), Contents{Password: password(t, "b"), Fill: big})
		wantErr(t, "second content over MaxContent", err, ErrTooLarge)
		negative := func(_ *Identity, buf []byte) (int, error) { return -1, nil }
		if err = Create(p, path, Contents{Password: password(t, "a"), Fill: negative}); err == nil {
			t.Fatal("a negative length passed")
		}
		failing := errors.New("fill failed")
		err = Create(p, path, Contents{Password: password(t, "a"), Fill: func(*Identity, []byte) (int, error) { return 0, failing }})
		wantErr(t, "a failing fill", err, failing)

		err = Create(p, path, volume(t, "a", []byte("x")), Contents{Password: password(t, "b")})
		wantErr(t, "a second volume without fill", err, ErrEmpty)
		err = Create(p, path, volume(t, "a", []byte("x")), volume(t, "b", nil))
		wantErr(t, "a second volume with no content", err, ErrEmpty)
		err = Create(p, path, Contents{Password: password(t, "a")})
		wantErr(t, "a written volume with no content", err, ErrEmpty)
		noFile(t, path)

		d, err := Prepare(p, Contents{Password: password(t, "a")})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		wantErr(t, "Write with L = 0", d.Write(path, nil), ErrEmpty)
		wantErr(t, "Write with a fill of 0", d.Write(path, content(nil)), ErrEmpty)
		wantErr(t, "Write over MaxContent", d.Write(path, big), ErrTooLarge)
		noFile(t, path)
		if err := d.Write(path, content([]byte("now"))); err != nil {
			t.Fatalf("Write after refusals: %v", err)
		}
		d.Close()
		wantErr(t, "Write after a write and Close", d.Write(vaultPath(t), content([]byte("x"))), ErrWritten)
		closed, err := Prepare(p, Contents{Password: password(t, "a")})
		if err != nil {
			t.Fatal(err)
		}
		closed.Close()
		wantErr(t, "Write of a closed draft", closed.Write(vaultPath(t), content([]byte("x"))), errClosed)
	})
}

// a fill that writes past its length leaves no trace: the tail is zeroed and
// the volume opens to exactly n bytes
func TestFillTailCleared(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		sloppy := func(_ *Identity, buf []byte) (int, error) {
			for i := range buf {
				buf[i] = 0xff
			}
			return 10, nil
		}
		_, file := mustCreate(t, p, Contents{Password: password(t, "a"), Fill: sloppy}, Contents{Password: password(t, "b"), Fill: sloppy})
		for _, pw := range []string{"a", "b"} {
			v, _ := mustOpen(t, p, file, password(t, pw))
			if !bytes.Equal(v.Content(), bytes.Repeat([]byte{0xff}, 10)) {
				t.Fatalf("volume %s opened to %d bytes", pw, len(v.Content()))
			}
			if !allZero(v.plain.Bytes()[lenSize+10:]) {
				t.Fatalf("volume %s keeps what fill wrote past its length", pw)
			}
		}
	})
}

func TestOpenNotVault(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		path, file := mustCreate(t, p, volume(t, "a", []byte("x")))
		pw := password(t, "a")
		for _, size := range []int{0, 1, FileSize - 1, FileSize + 1, 2 * FileSize} {
			other := vaultPath(t)
			data := make([]byte, size)
			copy(data, file)
			if err := os.WriteFile(other, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Open(p, other, pw)
			wantErr(t, fmt.Sprintf("a file of %d bytes", size), err, ErrNotVault)
		}
		_, err := Open(p, t.TempDir(), pw)
		wantErr(t, "a directory", err, ErrNotVault)
		_, err = Open(p, path+".missing", pw)
		wantErr(t, "a missing file", err, os.ErrNotExist)
		_, err = Open(nil, path, pw)
		wantErr(t, "no provider", err, errNoProvider)
		_, err = Open(p, path, nil)
		wantErr(t, "no password", err, jcrypto.ErrBadPassword)
	})
}

// an area that opens under the password but breaks the format is corrupt, not
// absent
func TestOpenCorrupt(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		pw := password(t, "a")
		_, file := mustCreate(t, p, volume(t, "a", []byte("good")))
		_, s := mustOpen(t, p, file, pw)
		keys := areaKeys(t, p, file, pw)
		reseal := func(s int, edit func(plain []byte)) []byte {
			out := bytes.Clone(file)
			plain, err := secmem.New(plainSize)
			if err != nil {
				t.Fatal(err)
			}
			defer plain.Release()
			edit(plain.Bytes())
			r := bytes.Repeat([]byte{byte(0x70 + s)}, rSize)
			if err := sealArea(p, keys[s], s, r, plain.Bytes(), areaOf(out, s)); err != nil {
				t.Fatal(err)
			}
			return out
		}
		length := func(n int) func([]byte) {
			return func(b []byte) { b[0], b[1] = byte(n>>8), byte(n) }
		}
		for name, f := range map[string][]byte{
			"L over MaxContent": reseal(s, length(MaxContent+1)),
			"L of 0xffff":       reseal(s, length(0xffff)),
			"L of 0":            reseal(s, length(0)),
			"a nonzero tail": reseal(s, func(b []byte) {
				length(4)(b)
				b[plainSize-1] = 1
			}),
			"a byte right after the content": reseal(s, func(b []byte) {
				length(4)(b)
				b[lenSize+4] = 1
			}),
			"both areas open": reseal(1-s, length(4)),
		} {
			_, _, err := open(p, f, pw)
			wantErr(t, name, err, ErrCorrupt)
		}
		full := reseal(s, func(b []byte) {
			length(MaxContent)(b)
			for i := lenSize; i < plainSize; i++ {
				b[i] = 0xaa
			}
		})
		v, _ := mustOpen(t, p, full, pw)
		if len(v.Content()) != MaxContent {
			t.Fatalf("a full volume opened to %d bytes", len(v.Content()))
		}
	})
}

// the keys of both areas under a password, as Open derives them
func areaKeys(t *testing.T, p jcrypto.CryptoProvider, file []byte, pw *secmem.Buffer) [2]*secmem.Buffer {
	t.Helper()
	w, err := passwordKey(p, file[:SaltSize], pw)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Release()
	var keys [2]*secmem.Buffer
	for s := range keys {
		if keys[s], err = volumeKey(p, w, file[:SaltSize], s); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(keys[s].Release)
	}
	return keys
}

func TestPlacementGivenBit(t *testing.T) {
	for _, c := range []struct {
		bit     byte
		i, want int
	}{{0, 0, 0}, {0, 1, 1}, {1, 0, 1}, {1, 1, 0}, {2, 0, 0}, {3, 1, 0}} {
		if got := place(c.bit, c.i); got != c.want {
			t.Fatalf("place(%d, %d) = %d, want %d", c.bit, c.i, got, c.want)
		}
	}
	eachSuite(t, func(t *testing.T, p *spy) {
		for bit := byte(0); bit < 2; bit++ {
			d, err := prepare(p, bit, []Contents{volume(t, "first", []byte("1")), volume(t, "second", []byte("2"))})
			if err != nil {
				t.Fatal(err)
			}
			if d.first != int(bit) {
				t.Fatalf("bit %d put the first volume in area %d", bit, d.first)
			}
			path := vaultPath(t)
			if err := d.Write(path, nil); err != nil {
				t.Fatal(err)
			}
			d.Close()
			file, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for i, pw := range []string{"first", "second"} {
				if _, s := mustOpen(t, p, file, password(t, pw)); s != place(bit, i) {
					t.Fatalf("bit %d: volume %d opened in area %d", bit, i, s)
				}
			}
		}
	})
}

// the first volume lands in area 0 with probability 1/2. Over 400 creations
// the count is Binomial(400, 1/2), mean 200, sd 10. By the exact binomial sum
// P(count <= 138) = P(count >= 262) = 2.84e-10, so a fair choice fails the
// test with probability 5.7e-10 < 1e-9 (alpha). A choice stuck on one area
// always fails it, one that picks area 0 with probability 0.7 fails it with
// probability 0.977
func TestPlacementIsFair(t *testing.T) {
	p := newSpy(t, cheap{provider(t, jcrypto.SuiteC25519)})
	v := volume(t, "a", []byte("x"))
	zero := 0
	for range 400 {
		d, err := Prepare(p, v)
		if err != nil {
			t.Fatal(err)
		}
		if d.first == 0 {
			zero++
		}
		d.Close()
		p.reset()
	}
	if zero < 139 || zero > 261 {
		t.Fatalf("first volume in area 0 in %d of 400 creations, want 139-261", zero)
	}
}

// the provider calls of an open do not depend on which area opens, and every
// failure costs what a success costs before its identity
func TestOpenWorkIsUniform(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		other := newSpy(t, cheap{provider(t, otherSuite(p.Suite()))})
		calls := func(file []byte, pw string, want error) []string {
			t.Helper()
			p.reset()
			v, _, err := open(p, file, password(t, pw))
			if want == nil && err != nil || want != nil && !errors.Is(err, want) {
				t.Fatalf("open with %s: %v, want %v", pw, err, want)
			}
			if v != nil {
				v.Close()
			}
			return p.seen()
		}
		var files [2][]byte
		for bit := byte(0); bit < 2; bit++ {
			d, err := prepare(p, bit, []Contents{volume(t, "a", []byte("x"))})
			if err != nil {
				t.Fatal(err)
			}
			path := vaultPath(t)
			if err := d.Write(path, nil); err != nil {
				t.Fatal(err)
			}
			d.Close()
			if files[bit], err = os.ReadFile(path); err != nil {
				t.Fatal(err)
			}
		}
		area0, area1 := calls(files[0], "a", nil), calls(files[1], "a", nil)
		if !slices.Equal(area0, area1) {
			t.Fatalf("area 0 costs %v\narea 1 costs %v", area0, area1)
		}
		identity := []string{"Hash", "DerivePair", "DeriveKey " + purposeFetch}
		if !slices.Equal(area0[len(area0)-len(identity):], identity) {
			t.Fatalf("an open ends with %v, want the identity %v", area0[len(area0)-len(identity):], identity)
		}
		failure := area0[:len(area0)-len(identity)]
		two := mustFile(t, p, volume(t, "a", []byte("x")), volume(t, "b", []byte("y")))
		brokenSalt := bytes.Clone(files[0])
		brokenSalt[7] ^= 0x10
		foreign := mustFile(t, other, volume(t, "a", []byte("x")))
		for name, got := range map[string][]string{
			"a wrong password":   calls(two, "c", ErrNoVolume),
			"an absent volume":   calls(files[0], "b", ErrNoVolume),
			"another suite":      calls(foreign, "a", ErrNoVolume),
			"a broken salt":      calls(brokenSalt, "a", ErrNoVolume),
			"a broken salt, two": calls(func() []byte { f := bytes.Clone(two); f[0] ^= 1; return f }(), "b", ErrNoVolume),
		} {
			if !slices.Equal(got, failure) {
				t.Fatalf("%s costs %v\nwant %v", name, got, failure)
			}
		}
	})
}

func otherSuite(s jcrypto.Suite) jcrypto.Suite {
	if s == jcrypto.SuiteGOST {
		return jcrypto.SuiteC25519
	}
	return jcrypto.SuiteGOST
}

// the empty volume is sealed by the code of a volume: the same provider calls
// from its key on, with a seal and an open back
func TestEmptyVolumeSealedAsVolume(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		tail := func(volumes ...Contents) []string {
			p.reset()
			d, err := Prepare(p, volumes...)
			if err != nil {
				t.Fatal(err)
			}
			d.Close()
			calls := p.seen()
			last := len(calls) - 1
			for last >= 0 && calls[last] != "DeriveKey "+purposeFetch {
				last--
			}
			return calls[last+1:]
		}
		empty := tail(volume(t, "a", []byte("x")))
		second := tail(volume(t, "a", []byte("x")), volume(t, "b", []byte("y")))
		want := []string{"Hash", "DeriveKey " + purposeBlock, "NewAEAD", "Seal", "Hash", "DeriveKey " + purposeBlock, "NewAEAD", "Open"}
		if !slices.Equal(empty, want) || !slices.Equal(second, want) {
			t.Fatalf("the empty volume costs %v, a second volume %v, want %v", empty, second, want)
		}
	})
}

// a fresh 32-byte salt per file, in every context the password starts from
func TestSaltFreshAndBound(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		a, b := mustFile(t, p, volume(t, "a", []byte("x"))), mustFile(t, p, volume(t, "a", []byte("x")))
		if bytes.Equal(a[:SaltSize], b[:SaltSize]) {
			t.Fatal("two containers with one salt")
		}
		p.reset()
		_, s := mustOpen(t, p, a, password(t, "a"))
		salt := a[:SaltSize]
		want := map[string]bool{}
		for _, tc := range []struct {
			exchange string
			parts    [][]byte
		}{
			{exchangePassword, [][]byte{salt}},
			{exchangeVolume, [][]byte{salt, {0}}},
			{exchangeVolume, [][]byte{salt, {1}}},
			{exchangeIdentity, [][]byte{salt, {byte(s)}}},
		} {
			tr, err := jcrypto.TranscriptBytes(p.Suite(), tc.exchange, tc.parts...)
			if err != nil {
				t.Fatal(err)
			}
			want[string(tr)] = true
		}
		got := map[string]bool{}
		for _, h := range p.hashed {
			if isVaultTranscript(h, p.Suite()) && !strings.Contains(string(h), "/"+exchangeBlock) {
				got[string(h)] = true
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%d password-side transcripts, want %d", len(got), len(want))
		}
		for tr := range got {
			if !want[tr] {
				t.Fatalf("a transcript without the salt of the file: %q", tr[:40])
			}
		}
	})
}

// the file holds no key in any form, and neither do the opened areas: only
// salt, r, ciphertext and tags; the content does not show through either
func TestNoKeyMaterial(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		first, second := []byte("first volume content, long enough"), []byte("second volume content, longer than that")
		p.reset()
		path := vaultPath(t)
		if err := Create(p, path, volume(t, "first password", first), volume(t, "second password", second)); err != nil {
			t.Fatal(err)
		}
		file, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := mustOpen(t, p, file, password(t, "first password"))
		b, _ := mustOpen(t, p, file, password(t, "second password"))
		secrets := append([][]byte{[]byte("first password"), []byte("second password")}, p.secrets...)
		if len(p.secrets) < 12 {
			t.Fatalf("only %d secrets recorded", len(p.secrets))
		}
		for i, s := range secrets {
			if leaks(file, s) {
				t.Fatalf("secret %d of %d bytes is in the file", i, len(s))
			}
			for _, v := range []*Volume{a, b} {
				if leaks(v.plain.Bytes(), s) {
					t.Fatalf("secret %d of %d bytes is in an opened area", i, len(s))
				}
			}
		}
		for _, c := range [][]byte{first, second} {
			if leaks(file, c) {
				t.Fatal("the content is in the file")
			}
		}
	})
}
