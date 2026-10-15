package gost

import (
	"bytes"
	"encoding/hex"
	"go/ast"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/internal/srccheck"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// the protected policy and the same with zeroing off, the control that shows
// a check of cleared memory can fail
var zeroingOnAndOff = []secmem.Policy{
	secmem.Protected,
	{OffHeap: true, Lock: true, DontDump: true},
}

func withPolicy(t *testing.T, p secmem.Policy) {
	t.Helper()
	before := secmem.CurrentPolicy()
	t.Cleanup(func() { _ = secmem.SetPolicy(before) })
	if err := secmem.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
}

func cleared(b []byte) bool {
	return bytes.Equal(b, make([]byte, len(b)))
}

type keptKDF struct {
	deriver
	outs [][]byte
}

func (k *keptKDF) Derive(dst, label, seed []byte) []byte {
	out := k.deriver.Derive(dst, label, seed)
	k.outs = append(k.outs, out)
	return out
}

// the KDF is keyed with the secmem bytes of the secret, and every candidate it
// hands out, the private key taken among them, is cleared before DerivePair
// returns
func TestDerivePairClearsEveryCandidate(t *testing.T) {
	orig := pairKDF
	t.Cleanup(func() { pairKDF = orig })
	var key []byte
	var kept *keptKDF
	pairKDF = func(k []byte) deriver {
		key = k
		kept = &keptKDF{deriver: orig(k)}
		return kept
	}
	secret, err := secmem.NewFrom(seqBytes(0x40, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Release()
	// the golden row of providertest that takes the fourth candidate
	ctx := pairContext(t, seqBytes(0x00, 32), 0x00)

	for _, pol := range zeroingOnAndOff {
		withPolicy(t, pol)
		priv, _, err := New().DerivePair(secret, ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := hex.EncodeToString(priv.Bytes())
		priv.Release()
		if got != "e8a3416c63a889e2dcf22ae71da838920dd3ee719a74b6c9d4e23b2fe062601b" {
			t.Fatalf("under %v DerivePair gave %s", pol, got)
		}
		if len(key) != 32 || &key[0] != &secret.Bytes()[0] {
			t.Fatalf("under %v the KDF is keyed with a copy of the secret", pol)
		}
		if len(kept.outs) != 4 {
			t.Fatalf("under %v %d candidates drawn, want 4", pol, len(kept.outs))
		}
		for i, out := range kept.outs {
			if cleared(out) != pol.Zero {
				t.Fatalf("under %v candidate %d is %x once DerivePair returned", pol, i, out)
			}
		}
	}
}

// the stretch takes the password bytes of the buffer themselves, the salt and
// the cost of the formula, and its whole output block on the heap, the tail
// past the key included, is cleared once the key is in a secmem buffer
func TestPasswordKeyClearsTheStretchOutput(t *testing.T) {
	orig := pbkdf2Streebog
	t.Cleanup(func() { pbkdf2Streebog = orig })
	var gotPw, gotSalt, out []byte
	var gotIter, gotSize int
	pbkdf2Streebog = func(password, salt []byte, iter, size int) ([]byte, error) {
		gotPw, gotSalt, gotIter, gotSize = password, bytes.Clone(salt), iter, size
		block := make([]byte, 64)
		for i := range block {
			block[i] = byte(i + 1)
		}
		out = block[:size]
		return out, nil
	}
	p := New()
	ctx, err := jcrypto.NewContext(p, "vault/password", seqBytes(0x00, 32))
	if err != nil {
		t.Fatal(err)
	}
	pw, err := secmem.NewFrom([]byte("jimichi vault password"))
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Release()
	salt := append([]byte("jimichi/v2/gost/password/1\x00"), ctx.Sum()...)

	for _, pol := range zeroingOnAndOff {
		withPolicy(t, pol)
		k, err := p.PasswordKey(pw, ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := bytes.Clone(k.Bytes())
		k.Release()
		if !bytes.Equal(got, seqBytes(0x01, 32)) {
			t.Fatalf("under %v the key is %x, not the start of the block", pol, got)
		}
		if len(gotPw) != pw.Len() || &gotPw[0] != &pw.Bytes()[0] {
			t.Fatalf("under %v the stretch got a copy of the password", pol)
		}
		if !bytes.Equal(gotSalt, salt) || gotIter != 2600 || gotSize != 32 {
			t.Fatalf("under %v the stretch got salt %x, c %d, dkLen %d", pol, gotSalt, gotIter, gotSize)
		}
		if cleared(out[:cap(out)]) != pol.Zero {
			t.Fatalf("under %v the block is %x once PasswordKey returned", pol, out[:cap(out)])
		}
	}
}

// what the stub of the test above cannot see: the real stretch hands
// crypto/pbkdf2 a string that unsafe.String makes over the password parameter,
// not a conversion that copies the password to the heap where nothing wipes it
func TestStretchViewsThePassword(t *testing.T) {
	lit := srccheck.VarFunc(t, srccheck.Files(t, "."), "pbkdf2Streebog")
	if !srccheck.Param(lit, "password") {
		t.Fatal("pbkdf2Streebog: password is bound other than as its parameter")
	}
	sinks := srccheck.Sinks(lit.Body, "password")
	if len(sinks) == 0 {
		t.Fatal("pbkdf2Streebog: no use of password")
	}
	for _, s := range sinks {
		if s != "unsafe.SliceData" && s != "unsafe.String" {
			t.Errorf("pbkdf2Streebog: password goes into %q", s)
		}
	}
	views, keys := srccheck.Calls(lit.Body, "unsafe.String"), srccheck.Calls(lit.Body, "pbkdf2.Key")
	if len(views) != 1 || len(keys) != 1 || len(keys[0].Args) != 5 {
		t.Fatalf("pbkdf2Streebog: %d calls of unsafe.String and %d of pbkdf2.Key, want one each", len(views), len(keys))
	}
	if len(srccheck.Sinks(views[0], "password")) != len(sinks) {
		t.Error("pbkdf2Streebog: password is used outside the call of unsafe.String")
	}
	if !isView(lit, keys[0].Args[1], views[0]) {
		t.Error("pbkdf2Streebog: pbkdf2.Key gets a password other than the string unsafe.String makes")
	}
}

func isView(lit *ast.FuncLit, arg ast.Expr, view *ast.CallExpr) bool {
	if arg == view {
		return true
	}
	id, ok := arg.(*ast.Ident)
	if !ok {
		return false
	}
	b := srccheck.Binds(lit, id.Name)
	if len(b) != 1 || len(srccheck.Sinks(lit.Body, id.Name)) != 1 {
		return false
	}
	set := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && as.Lhs[0] == b[0] && as.Rhs[0] == view {
			set = true
		}
		return true
	})
	return set
}

// the count of the purpose password/1, from the calibration on the testbed
func TestPasswordIterationsAreTheCalibratedOnes(t *testing.T) {
	if passwordIterations != 2600 {
		t.Fatalf("C_GOST = %d", passwordIterations)
	}
}

// what the tests above cannot see: a copy of a library output kept on the
// heap. Each output goes only into a secmem buffer, a copy into dst, the
// parameter of the closure drawFrom returns, which pickScalar calls with the
// secmem bytes of the private key, and the clearing of its own slice; every
// private key number gogost makes is wiped when its function returns
func TestKeyMaterialFlow(t *testing.T) {
	files := srccheck.Files(t, ".")
	for _, f := range []struct {
		fn, name string
		allowed  map[string]bool
	}{
		{"PasswordKey", "key", map[string]bool{"secmem.NewFrom": true, "secmem.Zero": true}},
		{"drawFrom", "out", map[string]bool{"copy(dst)": true, "secmem.Zero": true}},
	} {
		sinks := srccheck.Sinks(srccheck.Func(t, files, f.fn).Body, f.name)
		if len(sinks) == 0 {
			t.Fatalf("%s: no use of %s", f.fn, f.name)
		}
		for _, s := range sinks {
			if !f.allowed[s] {
				t.Errorf("%s: %s goes into %q", f.fn, f.name, s)
			}
		}
	}
	draw := srccheck.Func(t, files, "drawFrom")
	lit := closure(t, draw)
	if !srccheck.Param(lit, "dst") {
		t.Error("drawFrom: dst is not only the parameter of the closure it returns")
	}
	if len(srccheck.Sinks(lit.Body, "out")) != len(srccheck.Sinks(draw.Body, "out")) {
		t.Error("drawFrom: out is used outside the closure it returns")
	}

	keys := 0
	for _, file := range files {
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, prv := range privateKeys(fn.Body) {
				keys++
				if !wipesKey(fn.Body, prv) {
					t.Errorf("%s: %s.Key is not wiped by a deferred wipe", fn.Name.Name, prv)
				}
			}
		}
	}
	// generate, DerivePair, vko and Sign
	if keys < 4 {
		t.Fatalf("%d calls of gost3410.NewPrivateKey found, want 4 or more", keys)
	}
}

func privateKeys(body *ast.BlockStmt) []string {
	var names []string
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || srccheck.CallName(call) != "gost3410.NewPrivateKey" {
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); ok {
			names = append(names, id.Name)
		}
		return true
	})
	return names
}

func wipesKey(body *ast.BlockStmt, prv string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		d, ok := n.(*ast.DeferStmt)
		if !ok || srccheck.CallName(d.Call) != "wipe" || len(d.Call.Args) != 1 {
			return true
		}
		sel, ok := d.Call.Args[0].(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Key" {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == prv {
			found = true
		}
		return true
	})
	return found
}

func closure(t *testing.T, fn *ast.FuncDecl) *ast.FuncLit {
	t.Helper()
	for _, s := range fn.Body.List {
		if r, ok := s.(*ast.ReturnStmt); ok && len(r.Results) == 1 {
			if lit, ok := r.Results[0].(*ast.FuncLit); ok {
				return lit
			}
		}
	}
	t.Fatalf("%s returns no function literal", fn.Name.Name)
	return nil
}
