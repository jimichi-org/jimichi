package c25519

import (
	"bytes"
	"go/ast"
	"go/types"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/internal/srccheck"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// the stretch takes the password bytes of the buffer themselves, the salt and
// the cost of the formula, and its whole output on the heap, any capacity past
// the key included, is cleared once the key is in a secmem buffer; with
// zeroing off it is left as it is, which shows the check can fail
func TestPasswordKeyClearsTheStretchOutput(t *testing.T) {
	orig := argon2id
	t.Cleanup(func() { argon2id = orig })
	var gotPw, gotSalt, out []byte
	var gotCost [4]uint32
	argon2id = func(password, salt []byte, time, memory uint32, threads uint8, size uint32) []byte {
		gotPw, gotSalt = password, bytes.Clone(salt)
		gotCost = [4]uint32{time, memory, uint32(threads), size}
		block := make([]byte, 2*size)
		for i := range block {
			block[i] = byte(i + 1)
		}
		out = block[:size]
		return out
	}
	p := New()
	ctx, err := jcrypto.NewContext(p, "vault/password", seq(0x00, 32))
	if err != nil {
		t.Fatal(err)
	}
	pw, err := secmem.NewFrom([]byte("jimichi vault password"))
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Release()
	salt := append([]byte("jimichi/v2/c25519/password/1\x00"), ctx.Sum()...)
	policy := secmem.CurrentPolicy()
	t.Cleanup(func() { _ = secmem.SetPolicy(policy) })

	for _, pol := range []secmem.Policy{secmem.Protected, {OffHeap: true, Lock: true, DontDump: true}} {
		if err := secmem.SetPolicy(pol); err != nil {
			t.Fatal(err)
		}
		k, err := p.PasswordKey(pw, ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := bytes.Clone(k.Bytes())
		k.Release()
		if !bytes.Equal(got, seq(0x01, 32)) {
			t.Fatalf("under %v the key is %x, not the stretch output", pol, got)
		}
		if len(gotPw) != pw.Len() || &gotPw[0] != &pw.Bytes()[0] {
			t.Fatalf("under %v the stretch got a copy of the password", pol)
		}
		if !bytes.Equal(gotSalt, salt) || gotCost != [4]uint32{3, 65536, 4, 32} {
			t.Fatalf("under %v the stretch got salt %x and t, m, p, T %v", pol, gotSalt, gotCost)
		}
		if whole := out[:cap(out)]; bytes.Equal(whole, make([]byte, len(whole))) != pol.Zero {
			t.Fatalf("under %v the output is %x once PasswordKey returned", pol, whole)
		}
	}
}

// what the test above cannot see: a copy of a library output or of a private
// key kept on the heap. The Argon2id output goes only into a secmem buffer and
// the clearing of its own slice, and X25519 takes every private key as the
// bytes of its secmem buffer
func TestKeyMaterialFlow(t *testing.T) {
	files := srccheck.Files(t, ".")
	sinks := srccheck.Sinks(srccheck.Func(t, files, "PasswordKey").Body, "key")
	if len(sinks) == 0 {
		t.Fatal("PasswordKey: no use of key")
	}
	for _, s := range sinks {
		if s != "secmem.NewFrom" && s != "secmem.Zero" {
			t.Errorf("PasswordKey: key goes into %q", s)
		}
	}

	calls := 0
	for _, file := range files {
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || srccheck.CallName(call) != "curve25519.X25519" {
					return true
				}
				calls++
				arg, ok := call.Args[0].(*ast.CallExpr)
				if !ok || len(arg.Args) != 0 || !strings.HasSuffix(srccheck.CallName(arg), ".Bytes") {
					t.Errorf("%s: X25519 takes a scalar other than the bytes of a buffer", fn.Name.Name)
				}
				return true
			})
		}
	}
	// GenerateEphemeral, Agree and DerivePair
	if calls < 3 {
		t.Fatalf("%d calls of curve25519.X25519 found, want 3 or more", calls)
	}
}

// what the stub of the stretch test cannot see: the real stretch hands
// argon2.IDKey the password parameter as it is, not a copy on the heap where
// nothing wipes it
func TestStretchTakesThePassword(t *testing.T) {
	lit := srccheck.VarFunc(t, srccheck.Files(t, "."), "argon2id")
	keys := srccheck.Calls(lit.Body, "argon2.IDKey")
	if len(keys) != 1 || len(keys[0].Args) != 6 {
		t.Fatalf("argon2id: %d calls of argon2.IDKey, want one", len(keys))
	}
	if !srccheck.Param(lit, "password") {
		t.Fatal("argon2id: password is bound other than as its parameter")
	}
	if arg, ok := keys[0].Args[0].(*ast.Ident); !ok || arg.Name != "password" {
		t.Errorf("argon2id: argon2.IDKey gets %s, not the password parameter", types.ExprString(keys[0].Args[0]))
	}
	if n := len(srccheck.Sinks(lit.Body, "password")); n != 1 {
		t.Errorf("argon2id: %d uses of password, want the argument of argon2.IDKey alone", n)
	}
}

func seq(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}
