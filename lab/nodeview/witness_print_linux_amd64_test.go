//go:build linux && amd64

package nodeview

import (
	"context"
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
		clear(p.witness.routes)
		clear(p.witness.clients)
		p.witness = taskWitness{}
	})
	return withTaskWitness(ctx, &p.witness), p
}
