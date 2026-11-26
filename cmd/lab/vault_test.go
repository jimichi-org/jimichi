package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/lab/scenario"
)

// the production stretch replaced by a DeriveKey of a hash of the password,
// as the vault tests replace it
type cheapStretch struct{ jcrypto.CryptoProvider }

func (c cheapStretch) PasswordKey(password *secmem.Buffer, ctx jcrypto.Context) (*secmem.Buffer, error) {
	if password == nil || !jcrypto.ValidPassword(password.Bytes()) {
		return nil, jcrypto.ErrBadPassword
	}
	h, err := secmem.NewFrom(c.Hash(password.Bytes()))
	if err != nil {
		return nil, err
	}
	defer h.Release()
	return c.DeriveKey(h, "test/password", ctx, c.KeySize())
}

func cheapVault(t *testing.T) {
	t.Helper()
	saved := vaultProvider
	t.Cleanup(func() { vaultProvider = saved })
	vaultProvider = func(s jcrypto.Suite) (jcrypto.CryptoProvider, error) {
		p, err := suite.New(s)
		if err != nil {
			return nil, err
		}
		return cheapStretch{p}, nil
	}
}

func TestVaultCLIRejectsUnrelatedExplicitFlags(t *testing.T) {
	for _, arg := range []string{"-flows=6", "-hops=3", "-duration=20s", "-send=200ms", "-bins=100ms", "-repeats=1", "-mark-replay=", "-nodes=5", "-rogue=2", "-samples=100000", "-missing=1", "-leftout=0", "-withhold=0", "-train=5", "-corridor=0.2", "-claims=1", "-base=0.001"} {
		t.Run(arg, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := command([]string{"-set", "vault", arg}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "does not apply") {
				t.Fatalf("exit %d, %q", code, errOut.String())
			}
		})
	}
}

func TestVaultCLIInvalidConfig(t *testing.T) {
	for _, args := range [][]string{
		{"-containers=3"}, {"-containers=100001"}, {"-resamples=119"}, {"-resamples=1000001"}, {"-suite=other"}, {"positional"},
	} {
		var out, errOut bytes.Buffer
		if code := command(append([]string{"-set", "vault"}, args...), &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestVaultFlagsRequireTheSet(t *testing.T) {
	for _, args := range [][]string{{"-containers=10"}, {"-set", "deny", "-resamples=5"}, {"-set", "paths", "-containers=4"}} {
		var out, errOut bytes.Buffer
		if code := command(args, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "require -set vault") {
			t.Errorf("%v: exit %d, %q", args, code, errOut.String())
		}
	}
	for _, args := range [][]string{{"-set", "keymem", "-containers=10"}, {"-set", "mark", "-resamples=5"}} {
		var out, errOut bytes.Buffer
		if code := command(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestVaultHelpNamesTheSet(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := command([]string{"-help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"vault: block 5", "-containers", "-resamples"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("help without %q", want)
		}
	}
}

// the flags reach the report, which is named after the suite, the set leaves
// none of its containers behind, and the exit follows the controls and the
// integrity: four containers of each kind are too few for K2 to hold every time
func TestVaultSetFromTheCommandLine(t *testing.T) {
	cheapVault(t)
	tmp := t.TempDir()
	for _, v := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(v, tmp)
	}
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	status := command([]string{"-set", "vault", "-suite", "gost", "-containers", "4", "-resamples", "120", "-seed", "3", "-rev", "abc", "-out", dir}, &out, &errOut)
	names := reports(t, dir)
	if len(names) != 1 || !regexp.MustCompile(`^vault-gost-\d{8}-\d{6}\.json$`).MatchString(names[0]) {
		t.Fatalf("reports %v, status %d, stderr %q", names, status, errOut.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	var rep scenario.VaultReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Set != "vault" || rep.Suite != "gost" || rep.Rev != "abc" || rep.Seed != 3 || rep.Containers != 4 || rep.Resamples != 120 ||
		rep.Cost.Runs != scenario.CostRuns || len(rep.Integrity) == 0 {
		t.Fatalf("report %s", raw)
	}
	if !strings.Contains(out.String(), "report: "+filepath.Join(dir, names[0])) || !strings.Contains(out.String(), "K1 zero area") {
		t.Errorf("stdout %q", out.String())
	}
	failed := rep.Status != "controls passed"
	if want := map[bool]int{false: 0, true: 1}[failed]; status != want || failed != strings.Contains(errOut.String(), "controls failed") {
		t.Fatalf("status %d with %q, stderr %q", status, rep.Status, errOut.String())
	}
	if left := reports(t, tmp); len(left) != 0 {
		t.Fatalf("left behind %v", left)
	}
}

// at the size of a series every control holds and the exit is 0
func TestVaultSetAtTheSizeOfASeriesFromTheCommandLine(t *testing.T) {
	if testing.Short() {
		t.Skip("600 containers")
	}
	cheapVault(t)
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if status := command([]string{"-set", "vault", "-resamples", "1000", "-rev", "abc", "-out", dir}, &out, &errOut); status != 0 {
		t.Fatalf("status %d, stderr %q\n%s", status, errOut.String(), out.String())
	}
	for _, want := range []string{"controls passed", "A2 ", "A1 ", "trace: 0 of 15 one-volume, 0 of 15 two-volume"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout without %q:\n%s", want, out.String())
		}
	}
}
