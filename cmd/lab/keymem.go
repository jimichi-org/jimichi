package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"

	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/lab/keymem"
)

type keymemFlags struct {
	suite      string
	repeats    int
	seed       int64
	revision   string
	out        string
	explicit   map[string]bool
	positional int
}

func keymemCommand(f keymemFlags, stdout, stderr io.Writer) int {
	allowed := map[string]bool{"set": true, "suite": true, "repeats": true, "seed": true, "rev": true, "out": true}
	for name := range f.explicit {
		if !allowed[name] {
			fmt.Fprintln(stderr, "keymem: invalid_flag")
			return 2
		}
	}
	s, e := suite.Parse(f.suite)
	if e != nil || f.repeats < 1 || f.repeats > 100 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(f.revision) || f.positional != 0 {
		fmt.Fprintln(stderr, "keymem: invalid_config")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	report, runErr := keymem.Run(ctx, keymem.Config{Suite: s, Repeats: f.repeats, Seed: f.seed, Revision: f.revision})
	dir, e := report.Write(f.out)
	if e != nil {
		fmt.Fprintln(stderr, "keymem: controller_failed")
		return 1
	}
	fmt.Fprintln(stdout, dir)
	if runErr != nil {
		fmt.Fprintln(stderr, "keymem: series_unavailable")
		return 1
	}
	return 0
}
