//go:build linux && amd64

package nodeview

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"unsafe"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/lab/metrics"
)

func TestFitColdExtraBundleGrowthAdmission(t *testing.T) {
	// 16*256=4096 requests scan class4864, giving cap18 and 4608 logical bytes; 4864+160=5024
	a := &outputArithmetic{}
	if unsafe.Sizeof(FrozenModel{}) != 256 || outputRoundObject(4096, a) != 4864 || outputRoundObject(4608, a) != 4864 || a.err != nil || uint64(18)*uint64(unsafe.Sizeof(FrozenModel{}))+160 != 4768 {
		t.Fatal("extra bundle scan class differs from the independent growth calculation")
	}
	const oldOwner, growthOwner = uint64(2048), uint64(5024)
	budget := &memoryBudget{used: oldOwner, high: oldOwner, limit: oldOwner + growthOwner}
	headers := [8]FrozenModel{{Digest: "old-first"}, {}, {}, {}, {}, {}, {}, {Digest: "old-last"}}
	owner := &fitFrozenOwner{budget: budget, count: 8}
	defer owner.close()
	owner.models[0].Digest = "extra"
	host := &hostCapacity{}
	calls := 0
	budget.beforeAllocation = func(n uint64) error {
		calls++
		if n != growthOwner || budget.used != 7072 || owner.history != 0 || cap(headers[:]) != 8 || headers[0].Digest != "old-first" || headers[7].Digest != "old-last" {
			t.Fatal("append reached growth without its full prospective scan/control owner")
		}
		return host.checkGrowth(n)
	}
	models := owner.extraModels(t, headers[:])
	if calls != 1 || len(models) != 9 || cap(models) != 18 || uint64(cap(models))*256 != 4608 || &models[0] == &headers[0] || models[0].Digest != "old-first" || models[7].Digest != "old-last" || models[8].Digest != "extra" {
		t.Fatal("extra negative changed its nine copied headers or actual growth capacity")
	}
	if owner.history != growthOwner || budget.used != oldOwner+growthOwner || budget.high != 7072 || owner.count != 8 {
		t.Fatal("extra copy lost its separate old/new backing and control ownership")
	}
	clear(models[:cap(models)])
	if budget.used != 7072 || headers[0].Digest != "old-first" || headers[7].Digest != "old-last" {
		t.Fatal("temporary copy cleanup credited history or aliased its old backing")
	}
	owner.close()
	if budget.used != oldOwner || budget.high != 7072 {
		t.Fatal("extra copy final close released another owner's old backing")
	}
}

func TestFitColdFieldHistoryKnownAnswers(t *testing.T) {
	// rounded 136-byte histories: 144+288+576+1152+2304+4864 = 9328
	for _, row := range [...][2]uint64{{0, 0}, {1, 144}, {2, 432}, {3, 1008}, {4, 1008}, {5, 2160}, {8, 2160}, {9, 4464}, {16, 4464}, {17, 9328}, {35, 9328}} {
		a := &outputArithmetic{}
		if fitV2ColdFieldHistory(row[0], a) != row[1] || a.err != nil {
			t.Fatal("selected field append history differs from the hand-summed allocator classes")
		}
	}
	a := &outputArithmetic{}
	if outputRoundObject(1024, a) != 1152 || outputRoundBytes(1137, a) != 1152 || outputRoundObject(32*136, a) != 4864 || a.err != nil {
		t.Fatal("selected scan header or allocator class changed")
	}
	if fitV2ColdFieldHistory(36, a) != 0 || reasonOf(a.err) != ReasonUnsupported {
		t.Fatal("unsupported field count used the admitted layout")
	}
}

func TestFitColdMetadataKnownAnswers(t *testing.T) {
	for _, row := range []struct {
		typ         reflect.Type
		stop        bool
		cache, want uint64
	}{
		{reflect.TypeFor[Plan](), true, 262144, 638368},
		{reflect.TypeFor[FrozenModel](), true, 16384, 42820},
		{reflect.TypeFor[[]FrozenModel](), true, 98304, 124740},
		{reflect.TypeFor[MailboxTraining](), false, 196608, 289556},
		{reflect.TypeFor[FrozenModel](), false, 196608, 315992},
		{reflect.TypeFor[[]FrozenModel](), false, 196608, 315992},
	} {
		a := &outputArithmetic{}
		if a.add(fitV2ColdFields(row.typ, row.stop, a), row.cache) != row.want || a.err != nil {
			t.Fatal("selected field/cache family differs from its independent source total")
		}
	}
	// one nested alias: 42820+289556; eight aliases: 124740+8*289556
	for _, row := range []struct {
		value           any
		metadata, pairs uint64
	}{{FrozenModel{}, 332376, 2}, {make([]FrozenModel, 8), 2441188, 9}} {
		a := &outputArithmetic{}
		metadata, pairs := fitV2ColdMarshalMetadata(reflect.ValueOf(row.value), a)
		if a.err != nil || metadata != row.metadata || pairs != row.pairs {
			t.Fatal("outer marshal lost an independently charged nested alias")
		}
	}
	if !fitV2ColdMetadataProfile() {
		t.Fatal("compiled metadata graph differs from the admitted source profile")
	}
	for _, value := range []any{uint64(1), make([]FrozenModel, 7)} {
		a := &outputArithmetic{}
		fitV2ColdMarshalMetadata(reflect.ValueOf(value), a)
		if reasonOf(a.err) != ReasonUnsupported {
			t.Fatal("unsupported root or custom-marshal multiplicity used the frozen profile")
		}
	}
	a := &outputArithmetic{}
	fitV2ColdFields(reflect.TypeFor[struct {
		Value int `json:"value,string"`
	}](), false, a)
	if reasonOf(a.err) != ReasonUnsupported {
		t.Fatal("unsupported field option used the admitted field formula")
	}
}

func TestFitColdCacheAndPoolKnownAnswers(t *testing.T) {
	// T(N)+T(F)+1024*(N+F)+21760+1792+34304 = 3632*(N+F)+58176
	for _, row := range [...][4]uint64{{33, 11, 217984, 262144}, {3, 0, 11056, 16384}, {4, 0, 14688, 98304}, {21, 11, 174400, 196608}, {22, 11, 178032, 196608}, {23, 11, 181664, 196608}} {
		a := &outputArithmetic{}
		got := fitV2ColdCacheBudget(row[0], row[1], a)
		if a.err != nil || got != row[2] || got > row[3] {
			t.Fatal("cold trie/module/name-registry history exceeds its independently checked row")
		}
	}
	if fitV2FrozenPoolPairs != 131 || fitV2ParentPoolPairs != 133 || fitV2ProcessPoolPuts != 266 {
		t.Fatal("frozen and complete parent codec inventories were conflated")
	}
	a := &outputArithmetic{}
	// list 2*133*1152=306432; queue 266*48+425600+42560=480928
	if fitV2ColdPoolHistory(a) != 787360 || outputCumulativeSlice(2128, 16, 266, a) != 468160 || 2*outputRoundObject(8192, a) != 18944 || a.err != nil {
		t.Fatal("codec-caused whole list/queue history differs from the manual epoch-independent bound")
	}
	// 3391488+1323008+364496+65536+393216+65536+65536 = 5668816
	if fitV2ColdControlHistory(a) != 5668816 || a.err != nil {
		t.Fatal("named catalog/validation/helper/caller controls changed")
	}
	early, err := fitV2ColdEarlyBudget()
	if err != nil || early != 7340032 || fitV2ControlReservation != 6291456 || fitV2PoolReservation != 1048576 {
		t.Fatal("early controls and pool history lost their original prospective reservations")
	}
	a = &outputArithmetic{}
	fitV2ColdCacheBudget(math.MaxUint64, 1, a)
	if reasonOf(a.err) != ReasonLimit {
		t.Fatal("overflowing cache history did not refuse")
	}
}

func TestFitColdDecoderKnownAnswers(t *testing.T) {
	// first capacity >=floor(4L/3)+1, summing 64,128,256 without reuse
	for _, row := range [...][2]uint64{{0, 64}, {47, 64}, {48, 192}, {95, 192}, {96, 448}} {
		a := &outputArithmetic{}
		if fitJSONDecoderHistory(row[0], a) != row[1] || a.err != nil {
			t.Fatal("EOF-safe selected decoder growth changed")
		}
	}
	a := &outputArithmetic{}
	if fitJSONUnquoteHistory(6, 3, a) != 8 || fitJSONUnquoteHistory(4, 9, a) != 273 || a.err != nil {
		t.Fatal("unusual-string initial or cumulative append history changed")
	}
	for _, typ := range []reflect.Type{nil, reflect.TypeFor[int](), reflect.TypeFor[struct{}](), reflect.TypeFor[struct{ dec int }](), reflect.TypeFor[struct{ wrong *int }](), reflect.TypeFor[struct{ dec *[312]byte }]()} {
		if fitV2ColdDecoderType(typ) {
			t.Fatal("unsupported backend descriptor reached the v2 formula")
		}
	}
	if fitV2ColdProfile() && !fitV2ColdDecoderType(reflect.TypeFor[json.Decoder]()) {
		t.Fatal("supported compatibility layout lacks the selected backend descriptor")
	}
}

func TestFitColdConstructorDenials(t *testing.T) {
	const base, oldHigh, early = uint64(17), uint64(41), uint64(7340032)
	for _, row := range []struct {
		name               string
		reason             Reason
		hosts, allocations int
	}{
		{"nil-budget", ReasonContract, 0, 0},
		{"nil-hook", ReasonContract, 0, 0},
		{"nil-profile", ReasonContract, 0, 0},
		{"profile", ReasonUnsupported, 0, 0},
		{"one-byte-short", ReasonLimit, 0, 0},
		{"host-unsupported", ReasonUnsupported, 1, 0},
		{"host-refused", ReasonLimit, 1, 0},
		{"backend", ReasonUnsupported, 1, 0},
		{"initial-budget", ReasonLimit, 1, 0},
		{"initial-host", ReasonLimit, 2, 0},
		{"nil-owner", ReasonContract, 2, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			var hosts, allocations, initialized, profiles, backends int
			var attempts [2]uint64
			budget := &memoryBudget{used: base, high: oldHigh, limit: controllerArenaBytes}
			budget.beforeAllocation = func(n uint64) error {
				if hosts >= len(attempts) {
					t.Fatal("denial continued to another allocation")
				}
				attempts[hosts] = n
				hosts++
				if row.name == "host-unsupported" {
					return fail(ReasonUnsupported)
				}
				if row.name == "host-refused" || row.name == "initial-host" && hosts == 2 {
					return fail(ReasonLimit)
				}
				return nil
			}
			profile := func() bool {
				profiles++
				if budget.used != base {
					t.Fatal("cheap profile guard followed a managed reservation")
				}
				return row.name != "profile"
			}
			backend := func() bool {
				backends++
				if hosts != 1 || budget.used != base+early {
					t.Fatal("backend traversal preceded early managed and fresh host admission")
				}
				return row.name != "backend"
			}
			allocate := func() *fitFrozenOwner { allocations++; return nil }
			initialize := func(*testing.T, *fitFrozenOwner, jcrypto.Suite) error { initialized++; return nil }
			argument := budget
			switch row.name {
			case "nil-budget":
				argument = nil
			case "nil-hook":
				budget.beforeAllocation = nil
			case "nil-profile":
				profile = nil
			case "one-byte-short":
				budget.limit = base + early - 1
			case "initial-budget":
				budget.limit = base + early
			}
			owner, err := newFitFrozenOwnerWithConstructors(t, argument, jcrypto.SuiteC25519, profile, backend, allocate, initialize)
			if owner != nil || reasonOf(err) != row.reason || hosts != row.hosts || allocations != row.allocations || initialized != 0 || budget.used != base {
				t.Fatal("constructor denial reached allocation or failed to return exactly its reservations")
			}
			wantHigh := oldHigh
			if hosts > 0 {
				wantHigh = base + early
			}
			if hosts == 2 {
				wantHigh += attempts[1]
			}
			if budget.high != wantHigh || hosts > 0 && attempts[0] != early || hosts == 2 && attempts[1] == 0 {
				t.Fatal("denial erased a high-water charge or changed the early reservation")
			}
			if hosts == 0 && backends != 0 || profiles == 0 && backends != 0 || row.name == "host-unsupported" && backends != 0 || row.name == "host-refused" && backends != 0 {
				t.Fatal("schema inspection preceded profile, managed admission or the fresh host check")
			}
		})
	}
}

func TestFitColdConstructorOwnershipAndErasure(t *testing.T) {
	for _, partial := range []bool{true, false} {
		name := "accepted"
		if partial {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			const base = uint64(29)
			host := &hostCapacity{}
			hosts, allocations := 0, 0
			budget := &memoryBudget{used: base, high: base, limit: controllerArenaBytes}
			budget.beforeAllocation = func(n uint64) error { hosts++; return host.checkGrowth(n) }
			var alias *fitFrozenOwner
			var model *metrics.Discriminant
			var witness *MailboxFitWitness
			var weights, center []float64
			var kept, unused, witnessKept, witnessUnused []int
			allocate := func() *fitFrozenOwner {
				allocations++
				if hosts != 2 || budget.used <= base+7340032 {
					t.Fatal("owner allocated before both real fresh host admissions")
				}
				alias = allocateFitFrozenOwner()
				return alias
			}
			initialize := func(t *testing.T, owner *fitFrozenOwner, suite jcrypto.Suite) error {
				if owner != alias || owner.budget != budget || owner.history != budget.used-base {
					t.Fatal("pending reservations were not transferred to the actual owner")
				}
				if err := initializeFitFrozenOwner(t, owner, suite); err != nil {
					return err
				}
				owner.admit(t, 32768)
				weights, center = make([]float64, 8), make([]float64, 8)
				kept, unused, witnessKept, witnessUnused = make([]int, 8), make([]int, 8), make([]int, 8), make([]int, 8)
				for i := range weights {
					weights[i], center[i], kept[i], unused[i], witnessKept[i], witnessUnused[i] = 7, 9, 1, 2, 3, 4
				}
				model = &metrics.Discriminant{Weights: weights[:1], Center: center[:2], Kept: kept[:1], Unused: unused[:0], Normalizer: 5}
				witness = &MailboxFitWitness{FeatureVersion: "retained", Count: 3, Kept: witnessKept[:1], Unused: witnessUnused[:0]}
				witness.Cross[17][17], witness.Scatter[17][17] = 11, 13
				m := FrozenModel{Configuration: "retained", Population: "request", Digest: "retained", Training: MailboxTraining{Releasable: true, Model: model, Witness: witness}}
				owner.take(t, &m)
				if !reflect.DeepEqual(m, FrozenModel{}) || owner.models[0].Training.Model != model || owner.models[0].Training.Witness != witness || owner.count != 1 || owner.poolPairs != 4 {
					t.Fatal("real take cloned a model, retained its source header or changed constructor operations")
				}
				if partial {
					return fail(ReasonIncomplete)
				}
				return nil
			}
			owner, err := newFitFrozenOwnerWithConstructors(t, budget, jcrypto.SuiteC25519, fitV2ColdProfile, fitV2ColdBackendProfile, allocate, initialize)
			if allocations != 1 || alias == nil || hosts < 3 {
				t.Fatal("real admitted constructor did not reach its owned partial graph")
			}
			if partial {
				if owner != nil || reasonOf(err) != ReasonIncomplete {
					t.Fatal("partial initialization lost its failure")
				}
			} else {
				if err != nil || owner != alias || budget.used != base+owner.history || owner.history == 0 {
					t.Fatal("successful construction lost its retained history")
				}
				owner.close()
			}
			if budget.used != base || alias.budget != nil || alias.history != 0 || alias.count != 0 || alias.poolPairs != 0 || !reflect.DeepEqual(alias.plan, Plan{}) || !reflect.DeepEqual(alias.models, [8]FrozenModel{}) || alias.refs != [8]ModelReference{} {
				t.Fatal("last-consumer close retained an owner or released another live reservation")
			}
			for i := range weights {
				if weights[i] != 0 || center[i] != 0 || kept[i] != 0 || unused[i] != 0 || witnessKept[i] != 0 || witnessUnused[i] != 0 {
					t.Fatal("owner cleanup missed a retained alias or unused slice capacity")
				}
			}
			if !reflect.DeepEqual(*model, metrics.Discriminant{}) || !reflect.DeepEqual(*witness, MailboxFitWitness{}) {
				t.Fatal("owner cleanup retained the model or fixed witness body")
			}
			high := budget.high
			if budget.reserve(5) != nil {
				t.Fatal("idempotence sentinel could not reserve")
			}
			alias.close()
			if budget.used != base+5 || budget.high != high {
				t.Fatal("idempotent close released a second owner's reservation")
			}
			budget.release(5)
		})
	}
}
