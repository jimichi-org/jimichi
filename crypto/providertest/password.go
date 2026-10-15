package providertest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"runtime/metrics"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// The golden values of PasswordKey, checked under -short too: the call is paid
// for at the production cost anyway. Password "jimichi vault password", ctx =
// NewContext(p, "vault/password", 00..1f):
//
//	T = "jimichi/v2/<suite>/transcript/vault/password" || 00 || 01 || 0020 || 00..1f     79 / 77 bytes
//	S = "jimichi/v2/<suite>/password/1" || 00 || th                                      61 / 59 bytes
//
//	c25519  th = SHA-256(T);  W = Argon2id(P, S, t 3, m 65536 KiB, p 4, version 0x13, T 32)
//	gost    th = Streebog-256(T);  W = PBKDF2(HMAC_GOSTR3411_2012_512, P, S, c 2600, dkLen 32)
//
// The c25519 value comes from Argon2id written in Python over hashlib BLAKE2b,
// which first reproduced RFC 9106 (5.3) and the PHC reference vectors. The GOST
// value comes from Streebog-512, HMAC and PBKDF2 written in Python from the
// standards, which first reproduced RFC 6986, RFC 7836 appendix B and the
// examples of R 50.1.111-2016.
var goldenPassword = map[jcrypto.Suite]struct{ th, key string }{
	jcrypto.SuiteC25519: {
		th:  "c3b95d598563a7c7c2a1c4e1bd09e15422e3009c2559f5ca14d9abbba34a124c",
		key: "d66406506688ecf0f184a634365ef67cbc63a5580fd5fbdd492a372b3dabca1d",
	},
	jcrypto.SuiteGOST: {
		th:  "f7dfd1c3fdbee3bd9e580cc0d43e6347b6eba31fb2e26fae026d572649d70bc9",
		key: "597955a0d04a2864259ec8a03ebea0b2d5624b96b4b282ce53d09e643d81a2ed",
	},
}

func testPasswordKey(t *testing.T, p jcrypto.CryptoProvider) {
	ctx := mustContext(t, p, "vault/password", seq(0x00, 32))
	pw := mustPassword(t, "jimichi vault password")
	defer pw.Release()
	released := mustPassword(t, "jimichi vault password")
	released.Release()

	// every refusal comes before the stretch, so these cost nothing
	for _, tc := range []struct {
		name     string
		password string
		buf      *secmem.Buffer
		ctx      jcrypto.Context
		want     error
	}{
		{name: "nil password", ctx: ctx, want: jcrypto.ErrBadPassword},
		{name: "released password", buf: released, ctx: ctx, want: jcrypto.ErrBadPassword},
		{name: "257 bytes", password: strings.Repeat("a", 257), ctx: ctx, want: jcrypto.ErrBadPassword},
		{name: "NUL", password: "jimichi\x00vault", ctx: ctx, want: jcrypto.ErrBadPassword},
		{name: "CR", password: "jimichi\rvault", ctx: ctx, want: jcrypto.ErrBadPassword},
		{name: "LF at the end", password: "jimichi vault password\n", ctx: ctx, want: jcrypto.ErrBadPassword},
		{name: "CRLF at the end", password: "jimichi vault password\r\n", ctx: ctx, want: jcrypto.ErrBadPassword},
		{name: "zero context", buf: pw, ctx: jcrypto.Context{}, want: jcrypto.ErrBadContext},
		{name: "context of another suite", buf: pw, ctx: foreignContext(t, p), want: jcrypto.ErrBadContext},
		// the password is checked before the context
		{name: "NUL and a zero context", password: "a\x00b", want: jcrypto.ErrBadPassword},
	} {
		buf := tc.buf
		if tc.password != "" {
			buf = mustPassword(t, tc.password)
		}
		out, err := p.PasswordKey(buf, tc.ctx)
		if tc.password != "" {
			buf.Release()
		}
		if !errors.Is(err, tc.want) || out != nil {
			drop(out)
			t.Fatalf("PasswordKey(%s): %v, want %v and no key", tc.name, err, tc.want)
		}
	}

	g, ok := goldenPassword[p.Suite()]
	if !ok {
		t.Fatalf("no golden password key listed for suite %v", p.Suite())
	}
	if got := hex.EncodeToString(ctx.Sum()); got != g.th {
		t.Fatalf("th(vault/password) = %s, want %s", got, g.th)
	}

	// once more under the other zeroing: the key is the same, and only with
	// zeroing on does the call hand the freed heap back, which takes one forced
	// collection
	before := bytes.Clone(pw.Bytes())
	policy := secmem.CurrentPolicy()
	defer func() { _ = secmem.SetPolicy(policy) }()
	other := policy
	other.Zero = !policy.Zero
	var key []byte
	for _, pol := range []secmem.Policy{policy, other} {
		if err := secmem.SetPolicy(pol); err != nil {
			t.Fatal(err)
		}
		forced := forcedCollections()
		key = mustPasswordKey(t, p, pw, ctx)
		forced = forcedCollections() - forced
		if !bytes.Equal(pw.Bytes(), before) {
			t.Fatalf("PasswordKey under %v changed the password", pol)
		}
		if got := hex.EncodeToString(key); got != g.key {
			t.Fatalf("PasswordKey under %v = %s, want %s", pol, got, g.key)
		}
		var want uint64
		if pol.Zero {
			want = 1
		}
		if forced != want {
			t.Fatalf("PasswordKey under %v forced %d collections, want %d", pol, forced, want)
		}
	}
	if err := secmem.SetPolicy(policy); err != nil {
		t.Fatal(err)
	}

	if testing.Short() {
		return
	}
	another := mustPassword(t, "jimichi vault passwore")
	defer another.Release()
	if bytes.Equal(mustPasswordKey(t, p, another, ctx), key) {
		t.Fatal("another password gave the same key")
	}
	if bytes.Equal(mustPasswordKey(t, p, pw, mustContext(t, p, "vault/password", seq(0x01, 32))), key) {
		t.Fatal("another salt gave the same key")
	}
	longest := mustPassword(t, strings.Repeat("\xd0\xb6", jcrypto.PasswordMax/2))
	defer longest.Release()
	mustPasswordKey(t, p, longest, ctx)
}

// FreeOSMemory forces a collection, and the runtime counts those apart from
// the ones it starts itself
func forcedCollections() uint64 {
	s := []metrics.Sample{{Name: "/gc/cycles/forced:gc-cycles"}}
	metrics.Read(s)
	return s[0].Value.Uint64()
}

func mustPassword(t *testing.T, s string) *secmem.Buffer {
	t.Helper()
	b, err := secmem.NewFrom([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPasswordKey(t *testing.T, p jcrypto.CryptoProvider, pw *secmem.Buffer, ctx jcrypto.Context) []byte {
	t.Helper()
	key, err := p.PasswordKey(pw, ctx)
	if err != nil {
		t.Fatalf("PasswordKey: %v", err)
	}
	defer key.Release()
	return bytes.Clone(key.Bytes())
}
