//go:build linux && amd64

package nodeview

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"runtime"
	"testing"
)

type witnessPrinter struct {
	witness taskWitness
	exec    string
}

func (p *witnessPrinter) executed(e error) {
	if p == nil {
		return
	}
	p.exec = "ok"
	if e != nil {
		p.exec = "err"
	}
}

// printed from Cleanup so outcome reflects every assertion of the case
func witnessTask(t *testing.T, ctx context.Context, suite, name string) (context.Context, *witnessPrinter) {
	p := &witnessPrinter{exec: "none"}
	t.Cleanup(func() {
		outcome := "pass"
		if t.Failed() {
			outcome = "fail"
		}
		limit, _ := readCPULimit()
		for _, line := range p.witness.lines(suite, name, p.exec, outcome, runtime.NumCPU(), limit, runtime.GOMAXPROCS(0)) {
			t.Log(line)
		}
	})
	return withTaskWitness(ctx, &p.witness), p
}

func logBinaryIdentity(t *testing.T) {
	t.Helper()
	path, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		t.Fatal(e)
	}
	t.Logf("nodeview-binary sha256=%x", h.Sum(nil))
}
