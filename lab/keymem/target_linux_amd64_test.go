//go:build linux && amd64

package keymem

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

type syntheticProvider struct {
	jcrypto.CryptoProvider
	size        int
	deriveError error
	aeadError   error
	derived     []*secmem.Buffer
}

func (p *syntheticProvider) KeySize() int { return p.size }

func (p *syntheticProvider) DeriveKey(_ *secmem.Buffer, _ string, _ jcrypto.Context, size int) (*secmem.Buffer, error) {
	if p.deriveError != nil {
		return nil, p.deriveError
	}
	b, e := secmem.New(size)
	if e == nil {
		p.derived = append(p.derived, b)
	}
	return b, e
}

func (p *syntheticProvider) NewAEAD(_ *secmem.Buffer) (jcrypto.AEAD, error) { return nil, p.aeadError }

func TestTargetSelectionIgnoresProbesAndTracksOriginalBuffers(t *testing.T) {
	if e := secmem.SetPolicy(secmem.Protected); e != nil {
		t.Fatal(e)
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	p := &syntheticProvider{size: 32}
	defer func() {
		for _, b := range p.derived {
			b.Release()
		}
	}()
	tracked := &trackedProvider{CryptoProvider: p, oracle: w}
	probe, e := tracked.DeriveKey(nil, "probe", jcrypto.Context{}, 32)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tracked.NewAEAD(probe); e != nil {
		t.Fatal(e)
	}
	if tracked.count != 0 || tracked.uses != [3]uint64{} {
		t.Fatal("probe selected")
	}
	for i := 0; i < 3; i++ {
		key, e := tracked.DeriveKey(nil, "cell", jcrypto.Context{}, 32)
		if e != nil {
			t.Fatal(e)
		}
		if key != tracked.selected[i] || key.Len() != 32 {
			t.Fatal("original buffer not retained")
		}
		if _, e = tracked.NewAEAD(key); e != nil {
			t.Fatal(e)
		}
	}
	if tracked.count != 3 || tracked.uses != [3]uint64{1, 1, 1} || !tracked.locked() {
		t.Fatal("three cell-key contract")
	}
	for _, b := range tracked.selected {
		b.Release()
	}
	if tracked.lengths() != [3]uint64{} {
		t.Fatal("safe post-release metadata")
	}
	if _, e = tracked.DeriveKey(nil, "cell", jcrypto.Context{}, 32); !errors.Is(e, errOracleInvalid) {
		t.Fatal("fourth cell accepted")
	}
	if p.derived[len(p.derived)-1].Len() != 0 {
		t.Fatal("unreturned instrumentation key not released")
	}
}

func TestTargetInstrumentationFailuresReleaseResult(t *testing.T) {
	for _, test := range []struct {
		size, request int
		close         bool
	}{{31, 32, false}, {32, 31, false}, {32, 32, true}} {
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		p := &syntheticProvider{size: test.size}
		tracked := &trackedProvider{CryptoProvider: p, oracle: w}
		if test.close {
			w.Close()
		}
		if _, e = tracked.DeriveKey(nil, "cell", jcrypto.Context{}, test.request); !errors.Is(e, errOracleInvalid) {
			t.Fatal("instrumentation failure accepted")
		}
		for _, b := range p.derived {
			if b.Len() != 0 {
				t.Fatal("failed export retained key")
			}
		}
		r.Close()
		w.Close()
	}
}

func TestTargetPropagatesTypedProductionFailures(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{{secmem.ErrNotLocked, "protection_unavailable"}, {secmem.ErrNotMapped, "allocation_failed"}, {errOracleInvalid, "oracle_invalid"}, {errors.New("opaque"), "workload_failed"}} {
		if got := childClass(test.err, "workload_failed"); got != test.want {
			t.Fatal("typed cause mismatch")
		}
	}
}

func TestTargetSourceScope(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "target_linux_amd64.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	methods := map[string]bool{}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil {
			if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
				if ident, ok := star.X.(*ast.Ident); ok && ident.Name == "trackedProvider" {
					methods[fn.Name.Name] = true
				}
			}
		}
	}
	for _, name := range []string{"DeriveKey", "NewAEAD"} {
		if !methods[name] {
			t.Fatal("missing narrow wrapper")
		}
	}
	for name := range methods {
		if name != "DeriveKey" && name != "NewAEAD" && name != "lengths" && name != "locked" {
			t.Fatal("provider wrapper expanded")
		}
	}
	for _, file := range []string{"target_linux_amd64.go", "run_linux_amd64.go", "fixture_linux_amd64.go", "ipc_linux_amd64.go", "heap.go", "match.go"} {
		parsed, e := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		for _, imp := range parsed.Imports {
			path := imp.Path.Value
			if len(path) > 8 && path[:8] == `"crypto/` {
				t.Fatal("direct primitive import")
			}
		}
	}
}
