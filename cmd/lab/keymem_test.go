package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestKeymemCLIRejectsUnrelatedExplicitFlags(t *testing.T) {
	base := []string{"-set", "keymem", "-rev", strings.Repeat("a", 40)}
	for _, arg := range []string{"-flows=6", "-hops=3", "-duration=20s", "-send=200ms", "-bins=100ms", "-mark-replay=", "-nodes=5", "-rogue=2", "-samples=100000", "-missing=1", "-leftout=0", "-withhold=0", "-train=5", "-corridor=0.2", "-claims=1", "-base=0.001", "positional"} {
		t.Run(arg, func(t *testing.T) {
			var out, err bytes.Buffer
			args := append(append([]string{}, base...), arg)
			if code := command(args, &out, &err); code != 2 {
				t.Fatalf("exit %d", code)
			}
		})
	}
}

func TestKeymemCLIInvalidConfig(t *testing.T) {
	for _, args := range [][]string{{"-set", "keymem"}, {"-set", "keymem", "-rev", strings.Repeat("A", 40)}, {"-set", "keymem", "-rev", strings.Repeat("a", 40), "-repeats=0"}, {"-set", "keymem", "-rev", strings.Repeat("a", 40), "-repeats=101"}, {"-set", "keymem", "-rev", strings.Repeat("a", 40), "-suite=other"}, {"-set", "keymem", "-unknown"}} {
		var out, err bytes.Buffer
		if code := command(args, &out, &err); code != 2 {
			t.Fatalf("exit %d", code)
		}
	}
}

func TestKeymemHelpStatesFixedMatrix(t *testing.T) {
	var out, err bytes.Buffer
	if code := command([]string{"-set", "keymem", "-help"}, &out, &err); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(err.String(), "both policies and every endpoint fixed") {
		t.Fatal("missing fixed matrix")
	}
}
