package scenario

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/e2e"
	"github.com/jimichi-org/jimichi/lab/metrics"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/vault"
	"github.com/jimichi-org/jimichi/vault/profile"
)

const (
	// three features share one verdict
	VaultLevel = 1 - 0.05/3
	CostRuns   = 30

	k1Distance     = 0.45
	k2Point        = 0.65
	traceStates    = 6
	tracePairs     = traceStates * (traceStates - 1) / 2
	k3Changed      = 8
	integrityFlips = 100
	passwordBytes  = 16
	maxWorkers     = 16

	featureChi       = "chi_square_bytes"
	featureDuplicate = "duplicate_chunks"
	featureLearned   = "learned_bit"

	statusPassed = "controls passed"
	statusFailed = "controls failed"
)

var GuessBits = []float64{40, 60, 80}

// what each suite's password/1 costs, as CRYPTO states it
var stretchName = map[jcrypto.Suite]string{
	jcrypto.SuiteC25519: "password/1: argon2id t=3 m=64MiB p=4",
	jcrypto.SuiteGOST:   "password/1: pbkdf2 hmac-streebog-512 c=2600",
}

var passwordEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type VaultConfig struct {
	// containers of each kind: as many one-volume as two-volume
	Containers int
	Resamples  int
	Seed       int64
	// containers made at once; 0 is GOMAXPROCS up to 16, which keeps 64 MiB
	// stretches within the memory of a stand
	Workers int
	// every file the set writes there is removed before it returns
	Dir string
	// the reference bytes of A1 and the r and keys lab seals with
	Random io.Reader
}

type VaultReport struct {
	Set        string  `json:"set"`
	Suite      string  `json:"suite"`
	Rev        string  `json:"rev"`
	Seed       int64   `json:"seed"`
	Containers int     `json:"containers_per_kind"`
	Resamples  int     `json:"resamples"`
	Level      float64 `json:"interval_level"`
	Stretch    string  `json:"stretch"`
	Workers    int     `json:"workers"`
	GOOS       string  `json:"goos"`
	NumCPU     int     `json:"num_cpu"`
	GOMAXPROCS int     `json:"gomaxprocs"`
	CPUModel   string  `json:"cpu_model"`
	LoadBefore string  `json:"loadavg_before,omitempty"`
	LoadAfter  string  `json:"loadavg_after,omitempty"`

	Status   string        `json:"status"`
	Failed   []string      `json:"failed_controls,omitempty"`
	Controls VaultControls `json:"controls"`
	// A2 and A1 only when K1 and K2 pass, the trace only when K3 passes
	Verdict   string          `json:"verdict,omitempty"`
	A2        *VaultVariant   `json:"a2,omitempty"`
	A1        *VaultVariant   `json:"a1,omitempty"`
	Trace     *VaultTrace     `json:"trace,omitempty"`
	Integrity []IntegrityCase `json:"integrity"`
	Cost      VaultCost       `json:"cost"`
}

type VaultControls struct {
	K1 VaultK1 `json:"k1_zero_area"`
	K2 VaultK2 `json:"k2_r_bit"`
	K3 VaultK3 `json:"k3_resealed_area"`
}

type VaultK1 struct {
	Features  []VaultFeature `json:"features"`
	Best      string         `json:"best_feature"`
	Distance  *float64       `json:"best_distance_from_half"`
	Threshold float64        `json:"threshold"`
	Passed    bool           `json:"passed"`
}

type VaultK2 struct {
	LearnedBit VaultFeature `json:"learned_bit"`
	Threshold  float64      `json:"point_threshold"`
	Passed     bool         `json:"passed"`
}

type VaultK3 struct {
	Resealed  SnapshotCount `json:"two_volume_resealed"`
	OneVolume SnapshotCount `json:"one_volume"`
	Want      int           `json:"want_resealed_changed"`
	Passed    bool          `json:"passed"`
}

type SnapshotCount struct {
	Changed int `json:"changed_pairs"`
	Pairs   int `json:"pairs"`
}

type VaultTrace struct {
	OneVolume SnapshotCount `json:"one_volume"`
	TwoVolume SnapshotCount `json:"two_volume"`
	Verdict   string        `json:"verdict"`
}

type VaultVariant struct {
	Object    string         `json:"object"`
	Positives string         `json:"positives"`
	Negatives string         `json:"negatives"`
	Features  []VaultFeature `json:"features"`
	Verdict   string         `json:"verdict"`
}

// Positives and Negatives count the scored containers; LearnedBit scores the
// half it did not train on
type VaultFeature struct {
	Name      string   `json:"feature"`
	Positives int      `json:"positives"`
	Negatives int      `json:"negatives"`
	AUC       *float64 `json:"auc"`
	Low       *float64 `json:"ci_low,omitempty"`
	High      *float64 `json:"ci_high,omitempty"`
	Excludes  *bool    `json:"interval_excludes_half,omitempty"`
	Bit       *int     `json:"learned_bit_position,omitempty"`
	Direction *float64 `json:"learned_bit_direction,omitempty"`
	Trained   int      `json:"trained_on,omitempty"`
}

type IntegrityCase struct {
	Case     string         `json:"case"`
	Password string         `json:"password"`
	Trials   int            `json:"trials"`
	Opened   int            `json:"opened"`
	Refused  float64        `json:"refused_share"`
	Want     string         `json:"want"`
	Outcomes map[string]int `json:"outcomes"`
	Holds    bool           `json:"holds"`
}

type VaultCost struct {
	Runs                 int        `json:"runs"`
	RightWall            Spread     `json:"right_password_wall"`
	WrongWall            Spread     `json:"wrong_password_wall"`
	RightCore            *Spread    `json:"right_password_core,omitempty"`
	WrongCore            *Spread    `json:"wrong_password_core,omitempty"`
	GuessesPerCoreSecond *float64   `json:"guesses_per_core_second,omitempty"`
	GuessTime            []GuessRow `json:"guess_time,omitempty"`
}

type Spread struct {
	Median float64 `json:"median_s"`
	P95    float64 `json:"p95_s"`
}

type GuessRow struct {
	Bits        float64 `json:"entropy_bits"`
	CoreSeconds float64 `json:"core_seconds"`
	Years       float64 `json:"years"`
}

const (
	groupPopulation uint64 = iota + 1
	groupTrace
	groupIntegrity
	groupCost
)

const (
	streamPassword uint64 = iota + 1
	streamContact
	streamSplit
	streamBootstrap
	streamFlip
	streamWrong
)

const (
	variantA2 uint64 = iota + 1
	variantA1
	variantK1
	variantK2
)

func Vault(p jcrypto.CryptoProvider, cfg VaultConfig) (VaultReport, error) {
	switch {
	case p == nil:
		return VaultReport{}, errors.New("scenario: no provider")
	case cfg.Containers < 4:
		return VaultReport{}, errors.New("scenario: at least 4 containers of each kind, so each half has two")
	case cfg.Resamples < 1:
		return VaultReport{}, errors.New("scenario: at least one resample")
	case cfg.Dir == "" || cfg.Random == nil:
		return VaultReport{}, errors.New("scenario: no directory or random source")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = min(runtime.GOMAXPROCS(0), maxWorkers)
	}
	pop, err := population(p, cfg)
	if err != nil {
		return VaultReport{}, err
	}
	var run vaultRun
	second := sample{}
	for _, c := range pop {
		second.areas = append(second.areas, areaOf(c.file, 1-c.cover))
		second.truth = append(second.truth, c.two)
	}
	halves := split(second.truth, cfg.Seed, variantA2)
	run.k1 = controlK1(second, halves, cfg)
	run.k2 = controlK2(second, halves, cfg)
	if run.k1.Passed && run.k2.Passed {
		run.a2 = &VaultVariant{
			Object: "the area the cover password does not open", Positives: "two-volume", Negatives: "one-volume",
			Features: features(second, halves, cfg, variantA2, true),
		}
		files, err := againstRandom(pop, cfg)
		if err != nil {
			return VaultReport{}, err
		}
		run.a1 = &VaultVariant{
			Object: "the whole file", Positives: "container", Negatives: "random bytes of the same size",
			Features: features(files, split(files.truth, cfg.Seed, variantA1), cfg, variantA1, true),
		}
	}

	one, err := trace(p, cfg, 0, false, false)
	if err != nil {
		return VaultReport{}, err
	}
	two, err := trace(p, cfg, 1, true, false)
	if err != nil {
		return VaultReport{}, err
	}
	resealed, err := trace(p, cfg, 2, true, true)
	if err != nil {
		return VaultReport{}, err
	}
	run.k3 = VaultK3{Resealed: resealed, OneVolume: one, Want: k3Changed,
		Passed: resealed == SnapshotCount{k3Changed, tracePairs} && one == SnapshotCount{0, tracePairs}}
	run.trace = VaultTrace{OneVolume: one, TwoVolume: two, Verdict: "states differ"}
	if one.Changed == 0 && two.Changed == 0 {
		run.trace.Verdict = "states equal"
	}

	if run.integrity, err = integrity(p, cfg); err != nil {
		return VaultReport{}, err
	}
	if run.cost, err = cost(p, cfg); err != nil {
		return VaultReport{}, err
	}
	rep := run.report()
	rep.Suite, rep.Seed, rep.Containers, rep.Resamples = p.Suite().String(), cfg.Seed, cfg.Containers, cfg.Resamples
	rep.Stretch, rep.Workers = stretchName[p.Suite()], cfg.Workers
	rep.GOOS, rep.NumCPU, rep.GOMAXPROCS = runtime.GOOS, runtime.NumCPU(), runtime.GOMAXPROCS(0)
	return rep, nil
}

// what the set measured before the controls decide what the report may say
type vaultRun struct {
	k1        VaultK1
	k2        VaultK2
	k3        VaultK3
	a2, a1    *VaultVariant
	trace     VaultTrace
	integrity []IntegrityCase
	cost      VaultCost
}

// a failed control leaves only its own numbers: the AUC of A2 and A1 rest on
// K1 and K2, and the verdict of the trace on K3
func (r vaultRun) report() VaultReport {
	rep := VaultReport{
		Set: "vault", Level: VaultLevel, Status: statusPassed,
		Controls:  VaultControls{K1: r.k1, K2: r.k2, K3: r.k3},
		Integrity: r.integrity, Cost: r.cost,
	}
	for _, c := range []struct {
		name   string
		passed bool
	}{{"K1", r.k1.Passed}, {"K2", r.k2.Passed}, {"K3", r.k3.Passed}} {
		if !c.passed {
			rep.Failed = append(rep.Failed, c.name)
			rep.Status = statusFailed
		}
	}
	if r.k1.Passed && r.k2.Passed && r.a2 != nil {
		rep.A2, rep.A1 = withVerdict(r.a2), withVerdict(r.a1)
		rep.Verdict = rep.A2.Verdict
	}
	if r.k3.Passed {
		t := r.trace
		rep.Trace = &t
	}
	return rep
}

// the direction of an effect is not fixed in advance: an interval wholly
// below 0.5 distinguishes as well
func withVerdict(v *VaultVariant) *VaultVariant {
	if v == nil {
		return nil
	}
	out := *v
	out.Features = slices.Clone(v.Features)
	out.Verdict = "does not distinguish"
	for _, f := range out.Features {
		if f.Excludes != nil && *f.Excludes {
			out.Verdict = "distinguishes"
		}
	}
	return &out
}

type container struct {
	two   bool
	file  []byte
	cover int
}

func population(p jcrypto.CryptoProvider, cfg VaultConfig) ([]container, error) {
	out := make([]container, 2*cfg.Containers)
	jobs := make(chan int)
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		first  error
		failed atomic.Bool
	)
	for range cfg.Workers {
		wg.Go(func() {
			for i := range jobs {
				c, err := makeContainer(p, cfg, i, i >= cfg.Containers)
				if err != nil {
					mu.Lock()
					if first == nil {
						first = fmt.Errorf("container %d: %w", i, err)
					}
					mu.Unlock()
					failed.Store(true)
					continue
				}
				out[i] = c
			}
		})
	}
	for i := range out {
		if failed.Load() {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out, first
}

// the population through the production API, read back as an adversary
// reads a seized file; lab finds the cover's area by its own derivation
func makeContainer(p jcrypto.CryptoProvider, cfg VaultConfig, i int, two bool) (container, error) {
	v, err := newVolumes(p, cfg.Seed, groupPopulation, uint64(i), two)
	if err != nil {
		return container{}, err
	}
	defer v.release()
	file, err := createAndRead(p, filepath.Join(cfg.Dir, fmt.Sprintf("population-%d.vault", i)), v.contents)
	if err != nil {
		return container{}, err
	}
	s, err := openedArea(p, file, v.passwords[0])
	if err != nil {
		return container{}, err
	}
	return container{two: two, file: file, cover: s}, nil
}

func createAndRead(p jcrypto.CryptoProvider, path string, contents []vault.Contents) ([]byte, error) {
	if err := vault.Create(p, path, contents...); err != nil {
		return nil, err
	}
	file, err := os.ReadFile(path)
	if rerr := os.Remove(path); err == nil {
		err = rerr
	}
	return file, err
}

// volume 0 is the cover, the volume whose password the adversary holds
type volumes struct {
	passwords []*secmem.Buffer
	contents  []vault.Contents
}

func newVolumes(p jcrypto.CryptoProvider, seed int64, group, i uint64, two bool) (*volumes, error) {
	n := 1
	if two {
		n = 2
	}
	v := &volumes{}
	for vol := range uint64(n) {
		pw, err := newPassword(seed, streamPassword, group, i, vol)
		if err != nil {
			v.release()
			return nil, err
		}
		v.passwords = append(v.passwords, pw)
		card, err := contactCard(p, seed, streamContact, group, i, vol)
		if err != nil {
			v.release()
			return nil, err
		}
		v.contents = append(v.contents, vault.Contents{Password: pw, Fill: profile.New(p, Mailbox, &card)})
	}
	return v, nil
}

func (v *volumes) release() {
	for _, pw := range v.passwords {
		pw.Release()
	}
}

// 128 bits as jimichi vault init prints them, above the 80 the claim needs
func newPassword(seed int64, parts ...uint64) (*secmem.Buffer, error) {
	raw, err := secmem.New(passwordBytes)
	if err != nil {
		return nil, err
	}
	defer raw.Release()
	if _, err := stream(seed, parts...).Read(raw.Bytes()); err != nil {
		return nil, err
	}
	pw, err := secmem.New(passwordEncoding.EncodedLen(passwordBytes))
	if err != nil {
		return nil, err
	}
	passwordEncoding.Encode(pw.Bytes(), raw.Bytes())
	return pw, nil
}

// a card of a key nobody keeps, made as jimichi keygen-card makes one
func contactCard(p jcrypto.CryptoProvider, seed int64, parts ...uint64) (e2e.Card, error) {
	var f [mailbox.CapSize]byte
	if _, err := stream(seed, parts...).Read(f[:]); err != nil {
		return e2e.Card{}, err
	}
	f[0] |= 1
	queue, err := mailbox.QueueID(p, f[:])
	if err != nil {
		return e2e.Card{}, err
	}
	id, err := e2e.NewIdentity(p, Mailbox, queue)
	if err != nil {
		return e2e.Card{}, err
	}
	card := id.Card()
	id.Close()
	return card, nil
}

func stream(seed int64, parts ...uint64) *rand.ChaCha8 {
	var key [32]byte
	x := mix(seed, parts...)
	for i := range 4 {
		x = splitmix64(x)
		binary.LittleEndian.PutUint64(key[8*i:], x)
	}
	return rand.NewChaCha8(key)
}

func mix(seed int64, parts ...uint64) uint64 {
	x := uint64(seed)
	for _, p := range parts {
		x = splitmix64(x ^ splitmix64(p))
	}
	return splitmix64(x)
}

func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// the positives are Score.True
type sample struct {
	areas [][]byte
	truth []bool
}

// LearnedBit trains on half of each class and is scored on the rest; the
// seed draws the halves
type halves struct{ train, test []int }

func split(truth []bool, seed int64, variant uint64) halves {
	r := rand.New(stream(seed, streamSplit, variant))
	var pos, neg []int
	for i, t := range truth {
		if t {
			pos = append(pos, i)
		} else {
			neg = append(neg, i)
		}
	}
	var h halves
	for _, class := range [][]int{pos, neg} {
		r.Shuffle(len(class), func(i, j int) { class[i], class[j] = class[j], class[i] })
		h.train = append(h.train, class[:len(class)/2]...)
		h.test = append(h.test, class[len(class)/2:]...)
	}
	slices.Sort(h.train)
	slices.Sort(h.test)
	return h
}

func (s sample) pick(idx []int) sample {
	out := sample{areas: make([][]byte, len(idx)), truth: make([]bool, len(idx))}
	for j, i := range idx {
		out.areas[j], out.truth[j] = s.areas[i], s.truth[i]
	}
	return out
}

var plainFeatures = []struct {
	name  string
	value func([]byte) float64
}{
	{featureChi, metrics.ChiSquareBytes},
	{featureDuplicate, func(a []byte) float64 { return float64(metrics.DuplicateChunks(a)) }},
}

// Score.Entry is the container's place in the scored set, one score each, so
// the bootstrap resamples containers
func features(s sample, h halves, cfg VaultConfig, variant uint64, intervals bool) []VaultFeature {
	out := make([]VaultFeature, 0, len(plainFeatures)+1)
	for fi, f := range plainFeatures {
		scores := make([]metrics.Score, len(s.areas))
		for i, a := range s.areas {
			scores[i] = metrics.Score{Entry: i, Value: f.value(a), True: s.truth[i]}
		}
		out = append(out, rate(f.name, scores, cfg, variant, uint64(fi), intervals))
	}
	train, test := s.pick(h.train), s.pick(h.test)
	bit, ok := metrics.FitLearnedBit(train.areas, train.truth)
	if !ok {
		return append(out, VaultFeature{Name: featureLearned, Trained: len(h.train)})
	}
	scores := make([]metrics.Score, len(test.areas))
	for i, a := range test.areas {
		scores[i] = metrics.Score{Entry: i, Value: bit.Score(a), True: test.truth[i]}
	}
	f := rate(featureLearned, scores, cfg, variant, uint64(len(plainFeatures)), intervals)
	position := bit.Position
	// an area of ones scores the sign of the fit
	direction := bit.Score(bytes.Repeat([]byte{0xff}, len(test.areas[0])))
	f.Bit, f.Direction, f.Trained = &position, &direction, len(h.train)
	return append(out, f)
}

func rate(name string, scores []metrics.Score, cfg VaultConfig, variant, feature uint64, intervals bool) VaultFeature {
	f := VaultFeature{Name: name}
	for _, s := range scores {
		if s.True {
			f.Positives++
		} else {
			f.Negatives++
		}
	}
	if !intervals {
		f.AUC = finite(metrics.AUC(scores))
		return f
	}
	seed := int64(mix(cfg.Seed, streamBootstrap, variant, feature) >> 1)
	ci := metrics.BootstrapAUCLevel(scores, len(scores), cfg.Resamples, seed, VaultLevel)
	f.AUC, f.Low, f.High = finite(ci.Point), finite(ci.Low), finite(ci.High)
	excludes := ci.Low > 0.5 || ci.High < 0.5
	f.Excludes = &excludes
	return f
}

// one-volume areas replaced by zeroes: every feature should see that
func controlK1(second sample, h halves, cfg VaultConfig) VaultK1 {
	zero := make([]byte, vault.RegionSize)
	k1 := sample{truth: second.truth}
	for i, a := range second.areas {
		if !second.truth[i] {
			a = zero
		}
		k1.areas = append(k1.areas, a)
	}
	out := VaultK1{Features: features(k1, h, cfg, variantK1, false), Threshold: k1Distance}
	best := math.Inf(-1)
	for _, f := range out.Features {
		if f.AUC != nil && math.Abs(*f.AUC-0.5) > best {
			best, out.Best = math.Abs(*f.AUC-0.5), f.Name
		}
	}
	out.Distance = finite(best)
	out.Passed = out.Distance != nil && best >= k1Distance
	return out
}

// the top bit of r cleared in two-volume areas, the model of an MGM nonce
// stored as it is
func controlK2(second sample, h halves, cfg VaultConfig) VaultK2 {
	k2 := sample{truth: second.truth}
	for i, a := range second.areas {
		if second.truth[i] {
			a = bytes.Clone(a)
			a[0] &^= 0x80
		}
		k2.areas = append(k2.areas, a)
	}
	fs := features(k2, h, cfg, variantK2, true)
	out := VaultK2{LearnedBit: fs[len(fs)-1], Threshold: k2Point}
	out.Passed = out.LearnedBit.AUC != nil && *out.LearnedBit.AUC >= k2Point && out.LearnedBit.Excludes != nil && *out.LearnedBit.Excludes
	return out
}

func againstRandom(pop []container, cfg VaultConfig) (sample, error) {
	var s sample
	for _, c := range pop {
		s.areas = append(s.areas, c.file)
		s.truth = append(s.truth, true)
	}
	for range pop {
		b := make([]byte, vault.FileSize)
		if _, err := io.ReadFull(cfg.Random, b); err != nil {
			return sample{}, err
		}
		s.areas = append(s.areas, b)
		s.truth = append(s.truth, false)
	}
	return s, nil
}

// state 0 after the only Write, states 1 to 5 after opens, a two-volume
// container opened by its passwords in turn
func trace(p jcrypto.CryptoProvider, cfg VaultConfig, i uint64, two, resealed bool) (SnapshotCount, error) {
	v, err := newVolumes(p, cfg.Seed, groupTrace, i, two)
	if err != nil {
		return SnapshotCount{}, err
	}
	defer v.release()
	path := filepath.Join(cfg.Dir, fmt.Sprintf("trace-%d.vault", i))
	d, err := vault.Prepare(p, v.contents...)
	if err != nil {
		return SnapshotCount{}, err
	}
	err = d.Write(path, nil)
	d.Close()
	if err != nil {
		return SnapshotCount{}, err
	}
	defer os.Remove(path)
	file, err := os.ReadFile(path)
	if err != nil {
		return SnapshotCount{}, err
	}
	s, err := openedArea(p, file, v.passwords[0])
	if err != nil {
		return SnapshotCount{}, err
	}
	other := 1 - s
	states := [][]byte{bytes.Clone(areaOf(file, other))}
	for k := 1; k < traceStates; k++ {
		if resealed && k == 2 {
			r := make([]byte, areaR)
			if _, err := io.ReadFull(cfg.Random, r); err != nil {
				return SnapshotCount{}, err
			}
			if err := reseal(p, file, other, v.passwords[1], r); err != nil {
				return SnapshotCount{}, err
			}
			if err := os.WriteFile(path, file, 0o600); err != nil {
				return SnapshotCount{}, err
			}
		}
		pw := v.passwords[0]
		if two && k%2 == 0 {
			pw = v.passwords[1]
		}
		if err := openProfile(p, path, pw); err != nil {
			return SnapshotCount{}, fmt.Errorf("trace %d, open %d: %w", i, k, err)
		}
		if file, err = os.ReadFile(path); err != nil {
			return SnapshotCount{}, err
		}
		states = append(states, bytes.Clone(areaOf(file, other)))
	}
	changed, pairs := metrics.SnapshotReveal(states)
	return SnapshotCount{Changed: changed, Pairs: pairs}, nil
}

func openProfile(p jcrypto.CryptoProvider, path string, pw *secmem.Buffer) error {
	v, err := vault.Open(p, path, pw)
	if err != nil {
		return err
	}
	defer v.Close()
	pr, err := profile.Parse(p, v)
	if err != nil {
		return err
	}
	pr.Close()
	return nil
}

func integrity(p jcrypto.CryptoProvider, cfg VaultConfig) ([]IntegrityCase, error) {
	v, err := newVolumes(p, cfg.Seed, groupIntegrity, 0, true)
	if err != nil {
		return nil, err
	}
	defer v.release()
	file, err := createAndRead(p, filepath.Join(cfg.Dir, "integrity.vault"), v.contents)
	if err != nil {
		return nil, err
	}
	s, err := openedArea(p, file, v.passwords[0])
	if err != nil {
		return nil, err
	}
	probe := filepath.Join(cfg.Dir, "integrity-probe.vault")
	try := func(c *IntegrityCase, data []byte, pw *secmem.Buffer) error {
		if err := os.WriteFile(probe, data, 0o600); err != nil {
			return err
		}
		defer os.Remove(probe)
		vol, err := vault.Open(p, probe, pw)
		outcome := ""
		switch {
		case err == nil:
			vol.Close()
			outcome = "opened"
			c.Opened++
		case errors.Is(err, vault.ErrNoVolume):
			outcome = "no_volume"
		case errors.Is(err, vault.ErrNotVault):
			outcome = "not_vault"
		case errors.Is(err, vault.ErrCorrupt):
			outcome = "corrupt"
		default:
			return fmt.Errorf("integrity %s: %w", c.Case, err)
		}
		c.Trials++
		c.Outcomes[outcome]++
		return nil
	}
	var out []IntegrityCase
	add := func(name, password, want string) *IntegrityCase {
		out = append(out, IntegrityCase{Case: name, Password: password, Want: want, Outcomes: map[string]int{}})
		return &out[len(out)-1]
	}
	cover, other := v.passwords[0], v.passwords[1]

	r := rand.New(stream(cfg.Seed, streamFlip))
	regions := []struct {
		name      string
		off, size int
		want      string
	}{
		{"flip_salt", 0, vault.SaltSize, "no_volume"},
		{"flip_opened_area", vault.SaltSize + s*vault.RegionSize, vault.RegionSize, "no_volume"},
		{"flip_other_area", vault.SaltSize + (1-s)*vault.RegionSize, vault.RegionSize, "opened"},
	}
	for ri, reg := range regions {
		c := add(reg.name, "cover", reg.want)
		n := integrityFlips / len(regions)
		if ri < integrityFlips%len(regions) {
			n++
		}
		for range n {
			bit := r.IntN(8 * reg.size)
			flipped := bytes.Clone(file)
			flipped[reg.off+bit/8] ^= 0x80 >> (bit % 8)
			if err := try(c, flipped, cover); err != nil {
				return nil, err
			}
		}
	}

	swapped := bytes.Clone(file)
	copy(areaOf(swapped, 0), areaOf(file, 1))
	copy(areaOf(swapped, 1), areaOf(file, 0))
	for _, pw := range []struct {
		name string
		buf  *secmem.Buffer
	}{{"cover", cover}, {"other", other}} {
		if err := try(add("swap_areas", pw.name, "no_volume"), swapped, pw.buf); err != nil {
			return nil, err
		}
	}
	if err := try(add("truncate_one_byte", "cover", "not_vault"), file[:len(file)-1], cover); err != nil {
		return nil, err
	}
	if err := try(add("extend_one_byte", "cover", "not_vault"), append(bytes.Clone(file), 0), cover); err != nil {
		return nil, err
	}

	key, fresh := make([]byte, areaKey), make([]byte, areaR)
	if _, err := io.ReadFull(cfg.Random, key); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(cfg.Random, fresh); err != nil {
		return nil, err
	}
	replaced := bytes.Clone(file)
	if err := sealEmpty(p, 1-s, key, fresh, areaOf(replaced, 1-s)); err != nil {
		return nil, err
	}
	if err := try(add("replace_other_area_with_empty", "cover", "opened"), replaced, cover); err != nil {
		return nil, err
	}
	if err := try(add("replace_other_area_with_empty", "other", "no_volume"), replaced, other); err != nil {
		return nil, err
	}

	for i := range out {
		c := &out[i]
		c.Refused = float64(c.Trials-c.Opened) / float64(c.Trials)
		c.Holds = c.Outcomes[c.Want] == c.Trials
	}
	return out, nil
}

// right and wrong passwords in turn, so a drift of the host falls on both
func cost(p jcrypto.CryptoProvider, cfg VaultConfig) (VaultCost, error) {
	v, err := newVolumes(p, cfg.Seed, groupCost, 0, false)
	if err != nil {
		return VaultCost{}, err
	}
	defer v.release()
	path := filepath.Join(cfg.Dir, "cost.vault")
	if err := vault.Create(p, path, v.contents...); err != nil {
		return VaultCost{}, err
	}
	defer os.Remove(path)

	const wrongAt, rightAt = 0, 1
	var wall, core [2][]time.Duration
	coreOK := true
	runtime.GC()
	for k := range CostRuns {
		wrong, err := newPassword(cfg.Seed, streamWrong, uint64(k))
		if err != nil {
			return VaultCost{}, err
		}
		for at, pw := range []*secmem.Buffer{wrongAt: wrong, rightAt: v.passwords[0]} {
			c0, ok0 := processCPU()
			start := time.Now()
			vol, err := vault.Open(p, path, pw)
			elapsed := time.Since(start)
			c1, ok1 := processCPU()
			if vol != nil {
				vol.Close()
			}
			switch {
			case at == rightAt && err != nil:
				wrong.Release()
				return VaultCost{}, fmt.Errorf("cost: the right password: %w", err)
			case at == wrongAt && err == nil:
				wrong.Release()
				return VaultCost{}, errors.New("cost: a wrong password opened a volume")
			case at == wrongAt && !errors.Is(err, vault.ErrNoVolume):
				wrong.Release()
				return VaultCost{}, fmt.Errorf("cost: a wrong password: %w", err)
			}
			wall[at] = append(wall[at], elapsed)
			core[at] = append(core[at], c1-c0)
			coreOK = coreOK && ok0 && ok1
		}
		wrong.Release()
	}
	out := VaultCost{Runs: CostRuns, RightWall: spread(wall[rightAt]), WrongWall: spread(wall[wrongAt])}
	if !coreOK {
		return out, nil
	}
	right, wrongCore := spread(core[rightAt]), spread(core[wrongAt])
	out.RightCore, out.WrongCore = &right, &wrongCore
	// a clock that ticks coarser than an open reads zero, which prices nothing
	if wrongCore.Median <= 0 {
		return out, nil
	}
	out.GuessesPerCoreSecond = finite(1 / wrongCore.Median)
	for _, h := range GuessBits {
		t := metrics.GuessTime(wrongCore.Median, h)
		out.GuessTime = append(out.GuessTime, GuessRow{Bits: h, CoreSeconds: t, Years: t / (365.25 * 24 * 3600)})
	}
	return out, nil
}

func spread(d []time.Duration) Spread {
	median, _ := metrics.Percentile(d, 0.5)
	p95, _ := metrics.Percentile(d, 0.95)
	return Spread{Median: median.Seconds(), P95: p95.Seconds()}
}

// encoding/json refuses NaN and infinities
func finite(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return &v
}
