//go:build linux && amd64

package nodeview

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

type fitFrozenOwner struct {
	budget    *memoryBudget
	history   uint64
	plan      Plan
	models    [8]FrozenModel
	refs      [8]ModelReference
	count     int
	poolPairs uint64
}

func (o *fitFrozenOwner) admit(t *testing.T, n uint64) {
	t.Helper()
	a := outputArithmetic{}
	history := a.add(o.history, n)
	if a.err != nil {
		t.Fatal("frozen graph history overflow")
	}
	if o.budget.reserve(n) != nil {
		t.Fatal("frozen graph cumulative admission failed")
	}
	if o.budget.checkAllocation(n) != nil {
		o.budget.release(n)
		t.Fatal("frozen graph fresh host admission failed")
	}
	o.history = history
}

func newFitFrozenOwner(t *testing.T, b *memoryBudget, suite jcrypto.Suite) *fitFrozenOwner {
	t.Helper()
	o, err := newFitFrozenOwnerWithConstructors(t, b, suite, fitV2ColdProfile, fitV2ColdBackendProfile, allocateFitFrozenOwner, initializeFitFrozenOwner)
	if err != nil {
		t.Fatal("canonical frozen fixture admission or construction failed")
	}
	return o
}

func allocateFitFrozenOwner() *fitFrozenOwner { return &fitFrozenOwner{} }

func newFitFrozenOwnerWithConstructors(t *testing.T, b *memoryBudget, suite jcrypto.Suite, profile, backend func() bool, allocate func() *fitFrozenOwner, initialize func(*testing.T, *fitFrozenOwner, jcrypto.Suite) error) (*fitFrozenOwner, error) {
	if b == nil || b.beforeAllocation == nil || profile == nil || backend == nil || allocate == nil || initialize == nil {
		return nil, fail(ReasonContract)
	}
	if !profile() {
		return nil, fail(ReasonUnsupported)
	}
	early, err := fitV2ColdEarlyBudget()
	if err != nil {
		return nil, err
	}
	if err = b.reserve(early); err != nil {
		return nil, err
	}
	pending := early
	defer func() {
		if pending != 0 {
			b.release(pending)
		}
	}()
	if err = b.checkAllocation(early); err != nil {
		return nil, err
	}
	if !backend() || !fitV2ColdMetadataProfile() {
		return nil, fail(ReasonUnsupported)
	}
	a := &outputArithmetic{}
	shape := outputShape{strings: 128, catalog: true, models: 8, references: 8}
	plan := plannedOutputType(reflect.TypeFor[Plan](), shape, a)
	coordinates := plannedOutputSlice(reflect.TypeFor[[]Coordinate](), 32, shape, a)
	// fixed constructors include canonical coordinate/family copies, source strings and bounded caller metadata
	initial := a.add(outputRoundObject(uint64(unsafe.Sizeof(fitFrozenOwner{})), a), plan.backing, coordinates.backing, a.mul(fitV2ColdDecodeMetadata(reflect.TypeFor[Plan](), a), 4), 65536)
	history := a.add(early, initial)
	if a.err != nil {
		return nil, a.err
	}
	if err = b.reserve(initial); err != nil {
		return nil, err
	}
	pending = history
	if err = b.checkAllocation(initial); err != nil {
		return nil, err
	}
	o := allocate()
	if o == nil {
		return nil, fail(ReasonContract)
	}
	*o = fitFrozenOwner{budget: b, history: history}
	pending = 0
	complete := false
	defer func() {
		if !complete {
			o.close()
		}
	}()
	if err = initialize(t, o, suite); err != nil {
		return nil, err
	}
	complete = true
	return o, nil
}

func initializeFitFrozenOwner(t *testing.T, o *fitFrozenOwner, suite jcrypto.Suite) error {
	t.Helper()
	o.plan = defaultPlan(Config{Set: Mailbox, Phase: Structural, Suite: suite, Revision: strings.Repeat("a", 40)}, strings.Repeat("b", 40), strings.Repeat("c", 64))
	o.seal(t)
	o.marshalCharge(t, o.plan)
	if ValidatePlan(o.plan) != nil || !validPhasePredecessor(Config{Set: Mailbox, Phase: Train, Suite: suite}, o.plan) {
		return ErrInvalid
	}
	parent := o.plan.Digest
	o.plan.Phase, o.plan.ParentDigest, o.plan.Digest = Train, parent, ""
	o.seal(t)
	o.marshalCharge(t, o.plan)
	if ValidatePlan(o.plan) != nil {
		return ErrInvalid
	}
	return nil
}

func (o *fitFrozenOwner) marshalCharge(t *testing.T, value any) {
	t.Helper()
	a := &outputArithmetic{}
	v := reflect.ValueOf(value)
	size := actualOutputValue(v, a)
	metadata, pairs := fitV2ColdMarshalMetadata(v, a)
	poolPairs := a.add(o.poolPairs, pairs)
	if a.err != nil || poolPairs > fitV2FrozenPoolPairs {
		t.Fatal("frozen owner codec pair inventory exceeded")
	}
	n := a.add(outputMarshalAllocation(size, uint64(v.Type().Size()), a), metadata, fitJSONHashBudget(a), fitV2ColdPoolLocals(pairs, a))
	if a.err != nil {
		t.Fatal("frozen marshal history overflow")
	}
	o.admit(t, n)
	o.poolPairs = poolPairs
}

func (o *fitFrozenOwner) marshal(t *testing.T, value any) []byte {
	t.Helper()
	o.marshalCharge(t, value)
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal("canonical allowed-model serialization failed")
	}
	return b
}

func (o *fitFrozenOwner) seal(t *testing.T) {
	o.plan.Digest = ""
	b := o.marshal(t, o.plan)
	o.plan.Digest = publicHash(b)
	clear(b[:cap(b)])
}

func (o *fitFrozenOwner) decodeCharge(t *testing.T, b []byte, typ reflect.Type) {
	t.Helper()
	codec, err := fitJSONCodecBudget(b, typ)
	if err != nil {
		t.Fatal("frozen lexical admission failed")
	}
	if o.poolPairs >= fitV2FrozenPoolPairs {
		t.Fatal("frozen owner codec pair inventory exceeded")
	}
	o.admit(t, codec)
	o.poolPairs++
	graph, err := fitJSONShapeBound(b, typ)
	if err != nil {
		t.Fatal("frozen typed graph sizing failed")
	}
	o.admit(t, graph)
}

func (o *fitFrozenOwner) semantic(t *testing.T, m *FrozenModel, p *Plan) error {
	t.Helper()
	if frozenModelMetadataValid(m, p) {
		o.marshalCharge(t, *m)
	}
	return validateFrozenModel(m, p)
}

func (o *fitFrozenOwner) leaf(t *testing.T, training MailboxTraining, coordinate, population string) FrozenModel {
	t.Helper()
	m := FrozenModel{Schema: "jimichi-nodeview-model-v1", Features: featureVersion, Population: population, Configuration: coordinate, Suite: o.plan.Suite, TrainRevision: o.plan.Revision, TransformDigest: o.plan.TransformDigest, Training: training}
	preimage := o.marshal(t, m)
	defer clear(preimage[:cap(preimage)])
	m.Digest = publicHash(preimage)
	if o.count == 0 {
		o.decodeCharge(t, preimage, reflect.TypeFor[FrozenModel]())
		var missing FrozenModel
		if strictJSON(bytes.NewReader(preimage), &missing) != nil {
			t.Fatal("digest-less negative strict shape failed")
		}
		refs := [1]ModelReference{{coordinate, population, m.Digest}}
		partial := o.plan
		partial.FrozenModels = refs[:]
		if o.semantic(t, &missing, &partial) == nil {
			t.Fatal("final bytes missing Digest passed production validation")
		}
		wipeMailboxTraining(&missing.Training)
	}
	clear(preimage[:cap(preimage)])
	encoded := o.marshal(t, m)
	defer clear(encoded[:cap(encoded)])
	o.decodeCharge(t, encoded, reflect.TypeFor[FrozenModel]())
	var decoded FrozenModel
	transferred := false
	defer func() {
		if !transferred {
			wipeMailboxTraining(&decoded.Training)
		}
	}()
	if strictJSON(bytes.NewReader(encoded), &decoded) != nil {
		wipeMailboxTraining(&decoded.Training)
		t.Fatal("digest-bearing wrapper strict decode failed")
	}
	refs := [1]ModelReference{{coordinate, population, decoded.Digest}}
	partial := o.plan
	partial.FrozenModels = refs[:]
	partial.Digest = ""
	sealed := o.marshal(t, partial)
	partial.Digest = publicHash(sealed)
	clear(sealed[:cap(sealed)])
	o.marshalCharge(t, partial)
	if ValidatePlan(partial) != nil || o.semantic(t, &decoded, &partial) != nil || decoded.Digest == "" || decoded.Training.Model == nil {
		wipeMailboxTraining(&decoded.Training)
		t.Fatal("actual production single-wrapper semantic validation failed")
	}
	if o.count == 0 {
		o.negativeLeaf(t, &decoded, &partial)
	}
	transferred = true
	return decoded
}

func (o *fitFrozenOwner) negativeLeaf(t *testing.T, original *FrozenModel, plan *Plan) {
	t.Helper()
	for _, kind := range []string{"empty-digest", "wrong-digest", "source", "suite", "feature", "transform", "coordinate", "population", "failed-attachment", "reference"} {
		m := *original
		p := *plan
		refs := [1]ModelReference{plan.FrozenModels[0]}
		p.FrozenModels = refs[:]
		switch kind {
		case "empty-digest":
			m.Digest = ""
		case "wrong-digest":
			m.Digest = strings.Repeat("d", 64)
		case "source":
			m.TrainRevision = strings.Repeat("d", 40)
		case "suite":
			m.Suite = "invalid"
		case "feature":
			m.Features = "invalid"
		case "transform":
			m.TransformDigest = strings.Repeat("d", 64)
		case "coordinate":
			m.Configuration = "missing"
		case "population":
			m.Population = "missing"
		case "failed-attachment":
			m.Training.Releasable = false
			m.Training.Reason = string(ReasonFitSensitive)
		case "reference":
			refs[0].Digest = strings.Repeat("d", 64)
		}
		if o.semantic(t, &m, &p) == nil {
			t.Fatal("production frozen metadata validator accepted a mutated wrapper")
		}
	}
	m := *original
	model := *original.Training.Model
	model.Normalizer = math.Nextafter(model.Normalizer, math.Inf(1))
	m.Training.Model = &model
	if o.semantic(t, &m, plan) == nil {
		t.Fatal("production frozen validator accepted a wrong canonical digest preimage")
	}
}

func (o *fitFrozenOwner) take(t *testing.T, m *FrozenModel) {
	t.Helper()
	if o.count >= 8 {
		t.Fatal("frozen bundle exceeds its exact eight slots")
	}
	for i := 0; i < o.count; i++ {
		if o.models[i].Training.Model == m.Training.Model || o.models[i].Training.Witness == m.Training.Witness {
			t.Fatal("frozen bundle aliases another independently trained model")
		}
	}
	o.models[o.count] = *m
	o.refs[o.count] = ModelReference{m.Configuration, m.Population, m.Digest}
	*m = FrozenModel{}
	o.count++
}

func (o *fitFrozenOwner) bundleValidationCharge(t *testing.T, p *Plan) {
	t.Helper()
	o.marshalCharge(t, *p)
	for i := range o.models {
		o.marshalCharge(t, o.models[i])
	}
}

func (o *fitFrozenOwner) extraModels(t *testing.T, models []FrozenModel) []FrozenModel {
	t.Helper()
	a := &outputArithmetic{}
	charge := a.add(outputRoundObject(a.mul(18, uint64(unsafe.Sizeof(FrozenModel{}))), a), 160)
	if a.err != nil {
		t.Fatal("extra frozen bundle growth admission overflow")
	}
	o.admit(t, charge)
	return append(models[:8:8], o.models[0])
}

func (o *fitFrozenOwner) finish(t *testing.T) {
	t.Helper()
	if o.count != 8 {
		t.Fatal("complete bundle lacks an actual independent fit")
	}
	o.plan.TrainingReady = true
	o.plan.FrozenModels = o.refs[:]
	o.seal(t)
	o.bundleValidationCharge(t, &o.plan)
	if validateFrozenModels(o.models[:], &o.plan) != nil {
		t.Fatal("production complete frozen-bundle validation failed")
	}
	for _, kind := range []string{"missing", "extra", "duplicate-key", "duplicate-reference", "missing-reference", "swapped-reference"} {
		p := o.plan
		refs := o.refs
		p.FrozenModels = refs[:]
		headers := o.models
		models := headers[:]
		switch kind {
		case "missing":
			models = models[:7]
		case "extra":
			models = o.extraModels(t, models)
		case "duplicate-key":
			headers[1].Configuration, headers[1].Population = headers[0].Configuration, headers[0].Population
		case "duplicate-reference":
			refs[7] = refs[0]
		case "missing-reference":
			p.FrozenModels = refs[:7]
		case "swapped-reference":
			refs[0].Digest, refs[1].Digest = refs[1].Digest, refs[0].Digest
		}
		o.marshalCharge(t, p)
		if validateFrozenModels(models, &p) == nil {
			t.Fatal("production complete bundle validator accepted a mutated key/reference inventory")
		}
		if kind == "extra" {
			clear(models)
		}
		clear(headers[:])
		clear(refs[:])
	}
	encoded := o.marshal(t, o.models[:])
	defer clear(encoded[:cap(encoded)])
	o.decodeCharge(t, encoded, reflect.TypeFor[[]FrozenModel]())
	o.bundleValidationCharge(t, &o.plan)
	o.marshalCharge(t, o.plan)
	o.admit(t, 4096)
	directory := t.TempDir()
	path := filepath.Join(directory, "plan.json")
	if os.WriteFile(filepath.Join(directory, "frozen-models.json"), encoded, 0600) != nil {
		t.Fatal("allowed-model-only fixture write failed")
	}
	loaded, err := loadFrozen(path, o.plan)
	defer func() {
		for i := range loaded {
			wipeMailboxTraining(&loaded[i].Training)
		}
		clear(loaded)
	}()
	if err != nil || len(loaded) != 8 {
		t.Fatal("actual frozen loader rejected the canonical independent bundle")
	}
	for i := range loaded {
		if loaded[i].Digest != o.models[i].Digest || !sameMailboxModel(*loaded[i].Training.Model, *o.models[i].Training.Model) {
			t.Fatal("production loader changed a frozen model or source digest")
		}
	}
	if o.poolPairs != fitV2FrozenPoolPairs {
		t.Fatal("complete frozen owner lacks an admitted codec operation")
	}
}

func (o *fitFrozenOwner) close() {
	if o == nil || o.budget == nil {
		return
	}
	for i := range o.models {
		wipeMailboxTraining(&o.models[i].Training)
		o.models[i] = FrozenModel{}
	}
	clear(o.refs[:])
	o.plan = Plan{}
	o.budget.release(o.history)
	o.history = 0
	o.count = 0
	o.poolPairs = 0
	o.budget = nil
}
