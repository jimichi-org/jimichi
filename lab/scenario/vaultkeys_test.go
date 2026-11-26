package scenario

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/vault"
)

var vaultSuites = []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST}

func realProvider(t testing.TB, s jcrypto.Suite) jcrypto.CryptoProvider {
	t.Helper()
	p, err := suite.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// the production stretch replaced by a DeriveKey of a hash of the password,
// as the vault tests replace it; DerivePair and the rest stay real
type cheap struct{ jcrypto.CryptoProvider }

func (c cheap) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if password == nil || !jcrypto.ValidPassword(password.Bytes()) {
		return nil, jcrypto.ErrBadPassword
	}
	h, err := secmem.NewFrom(c.Hash(password.Bytes()))
	if err != nil {
		return nil, err
	}
	defer h.Release()
	return c.DeriveKey(h, "test/password", ctx, c.KeySize())
}

func seq(first byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

func keyBuffer(t testing.TB, b []byte) *secmem.Buffer {
	t.Helper()
	k, err := secmem.NewFrom(bytes.Clone(b))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Release)
	return k
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// k_s of vault/golden_test.go goldenIdentity: W = 40 41 .. 5f in place of
// PasswordKey, salt = 00 01 .. 1f
var goldenVolumeKeys = map[jcrypto.Suite][2]string{
	jcrypto.SuiteC25519: {
		"ba4b8bb352fac6bc71075708c58d28d5ab2deef93eb9cd7701d16d87979138b6",
		"f4a0ff57b0cc4a064ea4babcb2d9222e7fa26fc54297f95c9a8870c39e16218e",
	},
	jcrypto.SuiteGOST: {
		"214795170cadc4e7907199a7a1358b42290d027d87c9f0eded2507bd23baa1b5",
		"9c9aae7eaedea68e60e7e035e9d4dc2c96d08d483cc0f095e1389faf0dd5c985",
	},
}

// the rows of vault/golden_test.go goldenAreas, copied as they are: under the
// W and salt above, or under the key k for the empty volume,
//
//	th_b  = H("jimichi/v2/<suite>/transcript/vault/block" || 00 || 02 || 0001 || s || 0020 || r)
//	K_b   = KDF(k_s, "vault/block", th_b), 32 bytes
//	plain = u16be(L) || content || zeroes, 4048 bytes
//	area  = r || AEAD(K_b).Seal(nonce = zero, plain, ad = th_b), 4096 bytes
//
// ct is the first 32 bytes after r, tag the last 16, hash the suite's hash of
// the whole area
var goldenAreas = map[jcrypto.Suite][]struct {
	k             string
	s             int
	r, content    []byte
	th, kb        string
	ct, tag, hash string
}{
	jcrypto.SuiteC25519: {
		{
			s: 0, r: seq(0x80, 32), content: []byte("jimichi vault area 0"),
			th:   "e8e89f1b49afaea4cbf77041776432e383cd380e36e1b01766bf07931161be39",
			kb:   "9eae30809a2474836d3dc1efd2a3b3f210b6dd83ec9b7913af224e8a377c8587",
			ct:   "851e70b545ff2db6e5773c2267a1a3b6ce2ddba26dee81db66b9afc5e0616796",
			tag:  "e8aa8bd0a0ce4e659197645b7604466d",
			hash: "e1f3e09771f06f76e59acf7bb89f2317af174218e150f826654804f35be0bb54",
		},
		{
			s: 1, r: seq(0xa0, 32), content: seq(0x00, 339),
			th:   "cd7f3ae87be27c0c0cf5163e9ce4459a20a147b48b7819d201d89366d0917ce2",
			kb:   "1ea169b22f31f767910e4837a4247fdcc20d5f8be49cf5fdfa6e0be506073db3",
			ct:   "e439226091d85f796939518220ef0d26cc1eac8e0a09719904e31e2302883d1d",
			tag:  "88b71bcc50f22827108289c06c5ad4e8",
			hash: "9e5bc8e5e8956caab550d7bbf156e8158b44c10a4d4337b2c716709593e88e3f",
		},
		{
			k: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
			s: 1, r: seq(0xe0, 32),
			th:   "bd85927c6750ba4244a2e336f85a4c3e6830730927ef940f339e979a52b74903",
			kb:   "f3492a5b3cfa2c1398b2f2d84355499abc67e95e7a5d0cf2964c23c73d063a3b",
			ct:   "d2ddbcf5c08795a140178572c94af1baff72178b434d0edcc23e704974ab1ff9",
			tag:  "db9a4cc44c49c7c07a11312c7ae349d3",
			hash: "68c3f75c51d2c956a5d11b87814e09acac2868ce502fc70044abe3400dc55205",
		},
	},
	jcrypto.SuiteGOST: {
		{
			s: 0, r: seq(0x80, 32), content: []byte("jimichi vault area 0"),
			th:   "cb16571bef883de5a681e349b0962cb5966019772442e57e2fa8b3e6b3a1838a",
			kb:   "e3a8e26f77615537bdc05bad56d19f74817d44eb1a1845e2dcd46f252de18768",
			ct:   "9d76037405fac45b616945dae861d77f02eb65f24394800a3fdb27c90830e54b",
			tag:  "65c2191ad4dfbde41ec270ff33692cc5",
			hash: "fd66de19bc3a4809ceb06732bab2ec93882270584b29faafecd627952a98ef86",
		},
		{
			s: 1, r: seq(0xa0, 32), content: seq(0x00, 339),
			th:   "510fef47c1dac1d571b7a5644e9338f903f57f06ab1056730a4820bb30935254",
			kb:   "d14435cadbc61eaf2df9ca75542889754e883134bcb77ad4f07174212e9439ed",
			ct:   "9b5ce3a7854f5724a362088817d51e2de5e18883a15a9934212aef3036d99921",
			tag:  "b69b01545e106e6d35238e23c4c6deb2",
			hash: "d75ceadfc9b9d81026e09d8b504680f81686475444e8e75be50d4f8ffeaf2b6e",
		},
		{
			k: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
			s: 1, r: seq(0xe0, 32),
			th:   "05bf4354239a2408930c242dfb61a75ac28514ee67e5d615a48507ad22898de7",
			kb:   "e7da829b8092ab8abfc35226b4b3e0705940a68f2f7e0005e86bb762f4565246",
			ct:   "43625a118ba6296276a5f20747f666c4fb1ec77c7ecc35be2f1fcebe18f70788",
			tag:  "18141c5a12d29afc8a3ccf6c0168fc44",
			hash: "7545490516510b3462d3fdd75cde3747288fd4337e123aa68c4d3f641765025e",
		},
	},
}

// the derivation lab writes again gives the keys, the associated data and the
// sealed bytes of the vault vectors, and opens its own areas only at their place
func TestAreaDerivationMatchesTheVaultVectors(t *testing.T) {
	for _, st := range vaultSuites {
		t.Run(st.String(), func(t *testing.T) {
			p := realProvider(t, st)
			w, salt := keyBuffer(t, seq(0x40, 32)), seq(0x00, vault.SaltSize)
			keys := map[int]*secmem.Buffer{}
			for s, want := range goldenVolumeKeys[st] {
				k, err := volumeKey(p, w, salt, s)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(k.Release)
				if got := hex.EncodeToString(k.Bytes()); got != want {
					t.Fatalf("k_%d = %s, want %s", s, got, want)
				}
				keys[s] = k
			}
			rows := goldenAreas[st]
			if len(rows) != 3 {
				t.Fatalf("%d rows", len(rows))
			}
			for _, g := range rows {
				k := keys[g.s]
				if g.k != "" {
					k = keyBuffer(t, unhex(t, g.k))
				}
				kb, th, err := blockKey(p, k, g.s, g.r)
				if err != nil {
					t.Fatal(err)
				}
				gotKB := hex.EncodeToString(kb.Bytes())
				kb.Release()
				if hex.EncodeToString(th) != g.th || gotKB != g.kb {
					t.Fatalf("area %d: th_b %x, K_b %s; want %s, %s", g.s, th, gotKB, g.th, g.kb)
				}
				plain := make([]byte, areaPlain)
				plain[0], plain[1] = byte(len(g.content)>>8), byte(len(g.content))
				copy(plain[2:], g.content)
				area := make([]byte, vault.RegionSize)
				if err := sealArea(p, k, g.s, g.r, plain, area); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(area[:areaR], g.r) ||
					hex.EncodeToString(area[areaR:areaR+32]) != g.ct ||
					hex.EncodeToString(area[vault.RegionSize-areaTag:]) != g.tag ||
					hex.EncodeToString(p.Hash(area)) != g.hash {
					t.Fatalf("area %d: ct %x, tag %x, hash %x", g.s, area[areaR:areaR+32], area[vault.RegionSize-areaTag:], p.Hash(area))
				}
				back := make([]byte, areaPlain)
				if ok, err := openArea(p, k, g.s, area, back); err != nil || !ok || !bytes.Equal(back, plain) {
					t.Fatalf("area %d does not open back: %v, %v", g.s, ok, err)
				}
				if ok, _ := openArea(p, k, 1-g.s, area, back); ok {
					t.Fatalf("area %d opens as area %d", g.s, 1-g.s)
				}
			}
			empty := make([]byte, vault.RegionSize)
			if err := sealEmpty(p, 1, unhex(t, rows[2].k), rows[2].r, empty); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(p.Hash(empty)) != rows[2].hash {
				t.Fatalf("the empty volume of lab hashes to %x, want %s", p.Hash(empty), rows[2].hash)
			}
		})
	}
}

func fixedFill(content []byte) vault.Fill {
	return func(_ *vault.Identity, buf []byte) (int, error) { return copy(buf, content), nil }
}

func password(t testing.TB, s string) *secmem.Buffer {
	t.Helper()
	return keyBuffer(t, []byte(s))
}

// on files vault itself wrote: each password finds the area vault opens for it,
// two volumes lie in different areas, and a resealed area still opens under
// its password while its bytes change
func TestOpenedAreaOnProductionFiles(t *testing.T) {
	for _, st := range vaultSuites {
		t.Run(st.String(), func(t *testing.T) {
			t.Parallel()
			p := cheap{realProvider(t, st)}
			dir := t.TempDir()
			for n := range 8 {
				a, b := password(t, "cover password"), password(t, "other password")
				path := filepath.Join(dir, fmt.Sprintf("c%d.vault", n))
				if err := vault.Create(p, path, vault.Contents{Password: a, Fill: fixedFill([]byte("cover"))},
					vault.Contents{Password: b, Fill: fixedFill([]byte("other"))}); err != nil {
					t.Fatal(err)
				}
				file, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				sa, err := openedArea(p, file, a)
				if err != nil {
					t.Fatal(err)
				}
				sb, err := openedArea(p, file, b)
				if err != nil || sa == sb {
					t.Fatalf("areas %d and %d, %v", sa, sb, err)
				}
				if _, err := openedArea(p, file, password(t, "third password")); !errors.Is(err, errNoArea) {
					t.Fatalf("a third password: %v", err)
				}
				before := bytes.Clone(areaOf(file, sb))
				if err := reseal(p, file, sb, b, seq(byte(n), areaR)); err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(before, areaOf(file, sb)) || !bytes.Equal(areaOf(file, sb)[:areaR], seq(byte(n), areaR)) {
					t.Fatal("the resealed area kept its bytes or took another r")
				}
				if err := os.WriteFile(path, file, 0o600); err != nil {
					t.Fatal(err)
				}
				for _, pw := range []*secmem.Buffer{a, b} {
					v, err := vault.Open(p, path, pw)
					if err != nil {
						t.Fatalf("after the reseal: %v", err)
					}
					v.Close()
				}
				if err := reseal(p, file, sa, b, seq(0, areaR)); err == nil {
					t.Fatal("a password resealed the area it does not open")
				}
			}
		})
	}
}
