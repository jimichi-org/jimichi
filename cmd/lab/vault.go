package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/lab/scenario"
)

// replaced in tests to make the stretches cheap; a series always runs at the
// production cost
var vaultProvider = suite.New

type vaultFlags struct {
	suite                 string
	seed                  int64
	containers, resamples int
	revision, out         string
	explicit              map[string]bool
	positional            int
}

func vaultCommand(f vaultFlags, stdout, stderr io.Writer) int {
	allowed := map[string]bool{"set": true, "suite": true, "seed": true, "rev": true, "out": true, "containers": true, "resamples": true}
	for name := range f.explicit {
		if !allowed[name] {
			fmt.Fprintf(stderr, "vault: -%s does not apply to the set\n", name)
			return 2
		}
	}
	switch {
	case f.positional != 0:
		fmt.Fprintln(stderr, "vault: no positional arguments")
		return 2
	case f.containers < 4 || f.containers > 100000:
		fmt.Fprintln(stderr, "vault: -containers must lie in 4..100000")
		return 2
	case f.resamples < scenario.VaultMinResamples || f.resamples > 1000000:
		fmt.Fprintf(stderr, "vault: -resamples must lie in %d..1000000\n", scenario.VaultMinResamples)
		return 2
	}
	chosen, err := suite.Parse(f.suite)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	p, err := vaultProvider(chosen)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if f.revision == "unknown" {
		fmt.Fprintln(stderr, "warning: no -rev given, rows cannot be traced to a revision")
	}
	dir, err := os.MkdirTemp("", "jimichi-vault-")
	if err != nil {
		fmt.Fprintf(stderr, "vault: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)
	before := loadavg()
	rep, err := scenario.Vault(p, scenario.VaultConfig{
		Containers: f.containers, Resamples: f.resamples, Seed: f.seed, Dir: dir, Random: rand.Reader,
	})
	if err != nil {
		fmt.Fprintf(stderr, "vault: %v\n", err)
		return 1
	}
	rep.Rev, rep.CPUModel, rep.LoadBefore, rep.LoadAfter = f.revision, cpuModel(), before, loadavg()
	printVault(stdout, rep)
	if err := write(stdout, f.out, "vault-"+rep.Suite+"-"+time.Now().UTC().Format("20060102-150405"), rep); err != nil {
		fmt.Fprintf(stderr, "report: %v\n", err)
		return 1
	}
	status := 0
	if len(rep.Failed) > 0 {
		fmt.Fprintf(stderr, "vault: %s: %s\n", rep.Status, strings.Join(rep.Failed, ", "))
		status = 1
	}
	for _, c := range rep.Integrity {
		if !c.Holds {
			fmt.Fprintf(stderr, "vault: integrity %s with the %s password: %v, want %s\n", c.Case, c.Password, c.Outcomes, c.Want)
			status = 1
		}
	}
	return status
}

// the model name of /proc/cpuinfo, or what Windows names the processor
func cpuModel() string {
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		defer f.Close()
		lines := bufio.NewScanner(f)
		for lines.Scan() {
			key, value, ok := strings.Cut(lines.Text(), ":")
			if ok && strings.TrimSpace(key) == "model name" {
				return strings.TrimSpace(value)
			}
		}
	}
	return os.Getenv("PROCESSOR_IDENTIFIER")
}

func printVault(w io.Writer, rep scenario.VaultReport) {
	fmt.Fprintf(w, "vault: suite %s, rev %s, %d containers of each kind, %d resamples, level %.4f\n",
		rep.Suite, rep.Rev, rep.Containers, rep.Resamples, rep.Level)
	fmt.Fprintf(w, "stretch %s; %d workers; cpu %q\n", rep.Stretch, rep.Workers, rep.CPUModel)
	k1, k2, k3 := rep.Controls.K1, rep.Controls.K2, rep.Controls.K3
	fmt.Fprintf(w, "K1 zero area: best %s, |auc - 0.5| %s, want >= %.2f: %s\n", k1.Best, dash(k1.Distance), k1.Threshold, passed(k1.Passed))
	fmt.Fprintf(w, "K2 r bit: learned bit auc %s %s, want >= %.2f and 0.5 outside: %s\n",
		dash(k2.LearnedBit.AUC), vaultInterval(k2.LearnedBit), k2.Threshold, passed(k2.Passed))
	fmt.Fprintf(w, "K3 resealed area: %d of %d resealed, %d of %d one-volume, want %d and 0: %s\n",
		k3.Resealed.Changed, k3.Resealed.Pairs, k3.OneVolume.Changed, k3.OneVolume.Pairs, k3.Want, passed(k3.Passed))
	fmt.Fprintln(w, rep.Status)
	for _, v := range []struct {
		name string
		v    *scenario.VaultVariant
	}{{"A2", rep.A2}, {"A1", rep.A1}} {
		if v.v == nil {
			continue
		}
		fmt.Fprintf(w, "%s %s, %s against %s: %s\n", v.name, v.v.Object, v.v.Positives, v.v.Negatives, v.v.Verdict)
		for _, f := range v.v.Features {
			fmt.Fprintf(w, "  %-17s %4d/%-4d auc %s %s\n", f.Name, f.Positives, f.Negatives, dash(f.AUC), vaultInterval(f))
		}
	}
	if t := rep.Trace; t != nil {
		fmt.Fprintf(w, "trace: %d of %d one-volume, %d of %d two-volume: %s\n",
			t.OneVolume.Changed, t.OneVolume.Pairs, t.TwoVolume.Changed, t.TwoVolume.Pairs, t.Verdict)
	}
	for _, c := range rep.Integrity {
		fmt.Fprintf(w, "integrity %-29s %-5s %3d trials, refused %.2f, want %s: %s\n", c.Case, c.Password, c.Trials, c.Refused, c.Want, passed(c.Holds))
	}
	c := rep.Cost
	fmt.Fprintf(w, "cost: %d opens each; wall median/p95 right %.3f/%.3f s, wrong %.3f/%.3f s\n",
		c.Runs, c.RightWall.Median, c.RightWall.P95, c.WrongWall.Median, c.WrongWall.P95)
	if c.WrongCore != nil {
		fmt.Fprintf(w, "cost: core median/p95 right %.3f/%.3f s, wrong %.3f/%.3f s; guesses per core-second %s\n",
			c.RightCore.Median, c.RightCore.P95, c.WrongCore.Median, c.WrongCore.P95, dash(c.GuessesPerCoreSecond))
	}
	for _, g := range c.GuessTime {
		fmt.Fprintf(w, "guess time H %.0f: %.3g core-seconds, %.3g years\n", g.Bits, g.CoreSeconds, g.Years)
	}
}

func vaultInterval(f scenario.VaultFeature) string {
	if f.Low == nil || f.High == nil {
		return "[-]"
	}
	return fmt.Sprintf("[%.3f, %.3f]", *f.Low, *f.High)
}

func passed(ok bool) string {
	if ok {
		return "passed"
	}
	return "failed"
}
