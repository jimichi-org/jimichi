//go:build linux && amd64

package keymem

import (
	"context"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"golang.org/x/sys/unix"
)

func selfFDCount(t *testing.T) int {
	t.Helper()
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal("cannot inspect owned descriptors")
	}
	return len(entries)
}

func TestCaptureCommandHeldWriterTimesOutOwnedChild(t *testing.T) {
	t.Setenv("JIMICHI_KEYMEM_SYNTHETIC_CHILD", "")
	if secmem.SetPolicy(secmem.Protected) != nil || secmem.HardenProcess() != nil {
		t.Fatal("controller protection unavailable")
	}
	p, e := suite.New(jcrypto.SuiteC25519)
	if e != nil {
		t.Fatal("provider unavailable")
	}
	digest, e := ownDigest(p)
	if e != nil {
		t.Fatal("own binary digest unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	f, e := newFixture(ctx, p)
	if e != nil {
		t.Fatal("fixture unavailable")
	}
	defer f.close()
	beforeFDs := selfFDCount(t)
	var nonce [16]byte
	if randomFill(nonce[:]) != nil {
		t.Fatal("public nonce unavailable")
	}
	cfg := childConfig{Version: 1, Nonce: hex.EncodeToString(nonce[:]), Suite: "c25519", Policy: "none", Checkpoint: "closed-now", Anchor: f.ca.Anchor().String(), Relays: f.public}
	c := Config{Suite: jcrypto.SuiteC25519, Repeats: 1, Seed: 1, Revision: strings.Repeat("0", 40)}
	row := newTrial(c, plannedCell{ID: 1, Policy: cfg.Policy, Checkpoint: cfg.Checkpoint})
	var inspection trialInspection
	got := runTrialWithCommandHold(ctx, row, cfg, digest, true, &inspection)
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) || got.Status != "capture_timeout" || got.ErrorClass == nil || *got.ErrorClass != "capture_timeout" {
		t.Fatal("held command writer did not reach watchdog timeout")
	}
	if !inspection.commandWritten || !inspection.writerHeld || !inspection.workloadReady || !inspection.oracleReady {
		t.Fatal("sole capture frame was not written with a retained writer")
	}
	if got.EchoOK == nil || !*got.EchoOK || got.ActiveLengths == nil || *got.ActiveLengths != [3]uint64{32, 32, 32} || got.SelectedCount == nil || *got.SelectedCount != 3 || got.AEADUses == nil || *got.AEADUses != [3]uint64{1, 1, 1} || got.NumGC.EchoReady == nil {
		t.Fatal("real child did not reach workload readiness")
	}
	if got.StreamBytes == nil || *got.StreamBytes != 0 || got.ParseComplete == nil || *got.ParseComplete {
		t.Fatal("export occurred before command EOF")
	}
	if got.ReleasedLengths != nil || got.Timing.CloseDurationNS != nil || got.Timing.CloseToCaptureNS != nil || got.Timing.CaptureDurationNS != nil || got.NumGC.BeforeCapture != nil || got.NumGC.AfterCapture != nil {
		t.Fatal("endpoint or capture status reached before command EOF")
	}
	if got.CleanupError != nil || got.AnyMatch != nil {
		t.Fatal("supervised timeout manufactured cleanup failure or outcome")
	}
	for _, key := range got.Keys {
		if key.Matches != nil {
			t.Fatal("timeout published key outcome")
		}
	}
	if inspection.waitCalls != 1 || !inspection.processReaped || inspection.readersStarted != 3 || inspection.readersJoined != 3 || !inspection.allDescriptorsClosed {
		t.Fatal("owned process, readers or descriptors remained unjoined")
	}
	if !errors.Is(unix.Kill(inspection.pid, 0), unix.ESRCH) {
		t.Fatal("owned process remains after Wait")
	}
	if e = f.close(); e != nil {
		t.Fatal("fixture cleanup failed")
	}
	if afterFDs := selfFDCount(t); afterFDs != beforeFDs-3 {
		t.Fatal("owned descriptor leak after fixture and command-writer cleanup")
	}
}

func callNamed(expr ast.Expr, name string) (*ast.CallExpr, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return call, ok && ident.Name == name
}

func captureErrorGuard(stmt ast.Stmt) bool {
	guard, ok := stmt.(*ast.IfStmt)
	if !ok || guard.Init != nil || guard.Else != nil || len(guard.Body.List) != 1 {
		return false
	}
	condition, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || condition.Op != token.NEQ {
		return false
	}
	call, ok := callNamed(condition.X, "readCapture")
	if !ok || len(call.Args) != 2 {
		return false
	}
	nilIdent, ok := condition.Y.(*ast.Ident)
	if !ok || nilIdent.Name != "nil" {
		return false
	}
	index, ok := call.Args[0].(*ast.IndexExpr)
	if !ok {
		return false
	}
	files, ok := index.X.(*ast.Ident)
	if !ok || files.Name != "files" {
		return false
	}
	zero, ok := index.Index.(*ast.BasicLit)
	if !ok || zero.Kind != token.INT || zero.Value != "0" {
		return false
	}
	nonce, ok := call.Args[1].(*ast.SelectorExpr)
	if !ok || nonce.Sel.Name != "Nonce" {
		return false
	}
	config, ok := nonce.X.(*ast.Ident)
	if !ok || config.Name != "c" {
		return false
	}
	ret, ok := guard.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	fail, ok := callNamed(ret.Results[0], "fail")
	if !ok || len(fail.Args) != 1 {
		return false
	}
	code, ok := fail.Args[0].(*ast.BasicLit)
	if !ok || code.Kind != token.STRING {
		return false
	}
	value, e := strconv.Unquote(code.Value)
	return e == nil && value == "protocol_invalid"
}

func targetBody(t *testing.T) *ast.BlockStmt {
	t.Helper()
	f, e := parser.ParseFile(token.NewFileSet(), "target_linux_amd64.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	var body *ast.BlockStmt
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "runChild" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("missing private target")
	}
	return body
}

func captureDominates(body *ast.BlockStmt) bool {
	guardIndex := -1
	for i, stmt := range body.List {
		if captureErrorGuard(stmt) {
			if guardIndex != -1 {
				return false
			}
			guardIndex = i
		}
	}
	if guardIndex < 0 {
		return false
	}
	endpointCalls, exports, cleanupClosures := 0, 0, 0
	for i, stmt := range body.List {
		errorCleanup := false
		if assign, ok := stmt.(*ast.AssignStmt); ok && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 {
			if name, ok := assign.Lhs[0].(*ast.Ident); ok && name.Name == "cleanup" {
				if _, ok := assign.Rhs[0].(*ast.FuncLit); !ok {
					return false
				}
				cleanupClosures++
				continue
			}
			if name, ok := assign.Lhs[0].(*ast.Ident); ok && name.Name == "fail" {
				_, errorCleanup = assign.Rhs[0].(*ast.FuncLit)
			}
		}
		valid := true
		ast.Inspect(stmt, func(node ast.Node) bool {
			if branch, ok := node.(*ast.BranchStmt); ok && branch.Tok == token.GOTO {
				valid = false
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if target, ok := call.Fun.(*ast.Ident); ok && target.Name == "cleanup" && i <= guardIndex && !errorCleanup {
				valid = false
				return false
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			endpoint := receiver.Name == "cl" && selector.Sel.Name == "Close"
			export := receiver.Name == "debug" && selector.Sel.Name == "WriteHeapDump"
			if endpoint || export {
				if i <= guardIndex {
					valid = false
					return false
				}
				if endpoint {
					endpointCalls++
				} else {
					exports++
				}
			}
			return true
		})
		if !valid {
			return false
		}
	}
	return cleanupClosures == 1 && endpointCalls == 1 && exports == 1
}

func TestTargetCommandEOFGuardDominatesEndpointAndExport(t *testing.T) {
	if !captureDominates(targetBody(t)) {
		t.Fatal("successful command EOF guard does not dominate endpoint/export")
	}
}

func TestTargetCommandEOFGuardRejectsControlFlowMutations(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ast.BlockStmt, int)
	}{
		{"missing-error-return", func(body *ast.BlockStmt, index int) {
			guard := body.List[index].(*ast.IfStmt)
			ret := guard.Body.List[0].(*ast.ReturnStmt)
			guard.Body.List[0] = &ast.ExprStmt{X: ret.Results[0]}
		}},
		{"reversed-error-condition", func(body *ast.BlockStmt, index int) {
			body.List[index].(*ast.IfStmt).Cond.(*ast.BinaryExpr).Op = token.EQL
		}},
		{"wrong-command-descriptor", func(body *ast.BlockStmt, index int) {
			guard := body.List[index].(*ast.IfStmt)
			call := guard.Cond.(*ast.BinaryExpr).X.(*ast.CallExpr)
			call.Args[0].(*ast.IndexExpr).Index = &ast.BasicLit{Kind: token.INT, Value: "1"}
		}},
		{"conditional-guard", func(body *ast.BlockStmt, index int) {
			body.List[index] = &ast.IfStmt{Cond: ast.NewIdent("true"), Body: &ast.BlockStmt{List: []ast.Stmt{body.List[index]}}}
		}},
		{"endpoint-before-eof", func(body *ast.BlockStmt, index int) { moveTargetAction(t, body, index, "cl", "Close") }},
		{"export-before-eof", func(body *ast.BlockStmt, index int) { moveTargetAction(t, body, index, "debug", "WriteHeapDump") }},
		{"goto-bypass", func(body *ast.BlockStmt, index int) {
			insertBeforeGuard(body, index, &ast.BranchStmt{Tok: token.GOTO, Label: ast.NewIdent("endpoint")})
		}},
		{"deferred-endpoint-before-eof", func(body *ast.BlockStmt, index int) {
			insertBeforeGuard(body, index, &ast.DeferStmt{Call: &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent("cl"), Sel: ast.NewIdent("Close")}}})
		}},
		{"cleanup-before-eof", func(body *ast.BlockStmt, index int) {
			insertBeforeGuard(body, index, &ast.ExprStmt{X: &ast.CallExpr{Fun: ast.NewIdent("cleanup")}})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := targetBody(t)
			guardIndex := -1
			for i, stmt := range body.List {
				if captureErrorGuard(stmt) {
					guardIndex = i
				}
			}
			if guardIndex < 0 {
				t.Fatal("missing source guard")
			}
			test.mutate(body, guardIndex)
			if captureDominates(body) {
				t.Fatal("unsafe control-flow mutation passed EOF dominance guard")
			}
		})
	}
}

func insertBeforeGuard(body *ast.BlockStmt, index int, stmt ast.Stmt) {
	list := append([]ast.Stmt{}, body.List[:index]...)
	list = append(list, stmt)
	body.List = append(list, body.List[index:]...)
}

func moveTargetAction(t *testing.T, body *ast.BlockStmt, guardIndex int, receiver, method string) {
	t.Helper()
	for i := guardIndex + 1; i < len(body.List); i++ {
		found := false
		ast.Inspect(body.List[i], func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != method {
				return true
			}
			name, ok := selector.X.(*ast.Ident)
			if ok && name.Name == receiver {
				found = true
			}
			return true
		})
		if found {
			stmt := body.List[i]
			body.List = append(body.List[:i], body.List[i+1:]...)
			insertBeforeGuard(body, guardIndex, stmt)
			return
		}
	}
	t.Fatal("missing source action")
}
