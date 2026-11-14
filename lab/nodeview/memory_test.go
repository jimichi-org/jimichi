package nodeview

import (
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/jimichi-org/jimichi/conversation"
	"github.com/jimichi-org/jimichi/e2e"
)

func TestMailboxControlPinnedLayoutsAndOwnership(t *testing.T) {
	var settings Settings
	var public publicConfig
	var input evaluationInput
	var views viewSet
	for _, pair := range [][2]uintptr{
		{unsafe.Sizeof(settings), 192}, {unsafe.Sizeof(public), 312}, {unsafe.Sizeof(input), 680}, {unsafe.Sizeof(views), 24},
		{unsafe.Sizeof(privateTruth{}), 248}, {unsafe.Sizeof(privateCapture{}), 320}, {unsafe.Sizeof(workloadPlan{}), 112}, {unsafe.Sizeof(clientTruthCapacity{}), 56}, {unsafe.Sizeof(arenaRef{}), 16}, {unsafe.Sizeof(ReasonNone), 16},
		{unsafe.Offsetof(settings.ControlProfile), 0}, {unsafe.Offsetof(settings.RateNS), 8}, {unsafe.Offsetof(settings.Window), 56}, {unsafe.Offsetof(settings.Dispatch), 152}, {unsafe.Offsetof(settings.CoverPuts), 160}, {unsafe.Offsetof(settings.Workload), 168}, {unsafe.Offsetof(settings.DurationNS), 184},
		{unsafe.Offsetof(views.nodes), 0}, {unsafe.Offsetof(public.roster), 0}, {unsafe.Offsetof(public.suite), 10}, {unsafe.Offsetof(public.n), 16}, {unsafe.Offsetof(public.h), 24}, {unsafe.Offsetof(public.controlled), 32}, {unsafe.Offsetof(public.settings), 56}, {unsafe.Offsetof(public.binNS), 248}, {unsafe.Offsetof(public.windowsNS), 256}, {unsafe.Offsetof(public.population), 280}, {unsafe.Offsetof(public.epochNS), 296}, {unsafe.Offsetof(public.cutoffNS), 304},
		{unsafe.Offsetof(input.queueFalsePairs), 0}, {unsafe.Offsetof(input.budget), 8}, {unsafe.Offsetof(input.resultCharge), 16}, {unsafe.Offsetof(input.nkEndpoints), 24}, {unsafe.Offsetof(input.views), 32}, {unsafe.Offsetof(input.truth), 56}, {unsafe.Offsetof(input.plans), 304}, {unsafe.Offsetof(input.public), 328}, {unsafe.Offsetof(input.portToRoster), 640}, {unsafe.Offsetof(input.fragmentSource), 648}, {unsafe.Offsetof(input.established), 672},
		{unsafe.Sizeof(e2e.Card{}), 64}, {unsafe.Sizeof(conversation.Stats{}), 240}, {unsafe.Sizeof(time.Time{}), 24},
	} {
		if pair[0] != pair[1] {
			t.Fatal("mailbox control target layout or aggregate copy changed")
		}
	}
	components := uintptr(32) + unsafe.Sizeof(viewSet{}) + unsafe.Sizeof(privateTruth{}) + unsafe.Sizeof([]workloadPlan{}) + unsafe.Sizeof(publicConfig{}) + unsafe.Sizeof(map[uint16]int{}) + unsafe.Sizeof(fragmentSourceIndex{}) + unsafe.Sizeof(map[uint16]bool{})
	if components != 680 || components != unsafe.Sizeof(input) {
		t.Fatal("additional shallow evaluationInput position is not exactly 680 bytes")
	}
	locals := uintptr(2)*unsafe.Sizeof(time.Time{}) + 128 + 64 + 2*unsafe.Sizeof(workloadPlan{}) + unsafe.Sizeof(actualMessage{}) + 2*unsafe.Sizeof(arenaRef{}) + 4*unsafe.Sizeof([]byte{}) + 64 + 128 + 208
	staticErrors := unsafe.Sizeof(mailboxControlContractError) + unsafe.Sizeof(mailboxControlLabelError) + unsafe.Sizeof(mailboxControlIncompleteError) + 3*unsafe.Sizeof(failure{})
	if locals != 1024 || locals+unsafe.Sizeof(input) != 1704 || 6160+locals+unsafe.Sizeof(input) != 7864 || staticErrors != 96 || 6160+locals+unsafe.Sizeof(input)+staticErrors != 7960 || 7960 >= 16384 {
		t.Fatal("named controller controls exceeded their unchanged envelope")
	}
	participant := unsafe.Sizeof(privateCapture{}) + unsafe.Sizeof(workloadPlan{}) + unsafe.Sizeof(e2e.Card{}) + 64 + 8 + 8 + 2*unsafe.Sizeof(e2e.Card{}) + 64
	if participant != 768 || 32*64 != 2048 || 2048 > 8192 {
		t.Fatal("single owned Static clone or participant control-page bound changed")
	}
}

func TestMailboxControlErrorCachesPreserveFailureTypeAndOwnership(t *testing.T) {
	owner := unsafe.Sizeof(mailboxControlContractError) + unsafe.Sizeof(mailboxControlLabelError) + unsafe.Sizeof(mailboxControlIncompleteError) + 3*unsafe.Sizeof(failure{})
	if unsafe.Sizeof(error(nil)) != 16 || unsafe.Sizeof(ReasonNone) != 16 || unsafe.Sizeof(failure{}) != 16 || unsafe.Alignof(mailboxControlContractError) != 8 || unsafe.Alignof(failure{}) != 8 || owner != 96 {
		t.Fatal("process-static failure owner layout or alignment changed")
	}
	if 1024+680+owner != 1800 || 6160+1024+680+owner != 7960 || 16384-(6160+1024+680+owner) != 8424 {
		t.Fatal("static errors lost their explicit controller control-envelope charge")
	}
	if 768+owner != 864 || 1472+owner != 1568 || 1472+owner >= 2048 || 2048 > 8192 {
		t.Fatal("client static owner exceeded its unchanged conservative controls scope")
	}
	if 1853247+owner != 1853343 || 2097152-(1853247+owner) != 243809 || 1615075+owner != 1615171 || 8388608-(1615075+owner) != 6773437 {
		t.Fatal("scorer or fitter static owner lost its distinct fixed scope")
	}
	certificate, err := fitCertificateBytes()
	if err != nil || certificate != 81920 || 1615075+uint64(owner)+certificate != 1697091 || 8388608-(1615075+uint64(owner)+certificate) != 6691517 {
		t.Fatal("certificate omitted the current fitter baseline or its new fixed owner")
	}
	if 38*owner != 3648 || 22*owner != 2112 || 2*owner != 192 || 5*owner != 480 {
		t.Fatal("simultaneous process-static owners were omitted or duplicated")
	}
	cached := [3]error{mailboxControlContractError, mailboxControlLabelError, mailboxControlIncompleteError}
	want := [3]Reason{ReasonContract, ReasonLabel, ReasonIncomplete}
	var words [3][2]unsafe.Pointer
	for i, value := range cached {
		actual, ok := value.(failure)
		var target failure
		if value == nil || !ok || actual.reason != want[i] || reasonOf(value) != want[i] || !errors.As(value, &target) || target.reason != want[i] || value.Error() != "nodeview: "+string(want[i]) {
			t.Fatal("cached error changed its exact failure type or existing consumer behavior")
		}
		words[i] = *(*[2]unsafe.Pointer)(unsafe.Pointer(&value))
		if words[i][0] == nil || words[i][1] == nil {
			t.Fatal("cached interface omitted its existing itab or concrete backing")
		}
		for earlier := 0; earlier < i; earlier++ {
			if words[earlier][0] != words[i][0] || words[earlier][1] == words[i][1] {
				t.Fatal("fixed reasons changed type identity or shared one concrete reason owner")
			}
		}
	}
	labelInput, incompleteInput := boundaryReceiptInput(t), boundaryReceiptInput(t)
	labelInput.truth.messages[0].side = 2
	for range 3 {
		_, contract := peerReadinessRole(e2e.Card{}, e2e.Card{})
		returned := [3]error{contract, checkBoundaryPeerReceipts(labelInput, 2), checkBoundaryPeerReceipts(incompleteInput, 2)}
		for i, value := range returned {
			if *(*[2]unsafe.Pointer)(unsafe.Pointer(&value)) != words[i] || reasonOf(value) != want[i] {
				t.Fatal("helper reconstructed, replaced or changed a cached fixed error")
			}
		}
	}
	after := [3]error{mailboxControlContractError, mailboxControlLabelError, mailboxControlIncompleteError}
	for i, value := range after {
		if value != cached[i] || *(*[2]unsafe.Pointer)(unsafe.Pointer(&value)) != words[i] {
			t.Fatal("helper reassigned immutable process-static error state")
		}
	}
}

func TestMemoryBudgetChecksBeforeAllocation(t *testing.T) {
	b := &memoryBudget{limit: 32}
	if e := b.reserve(12); e != nil {
		t.Fatal(e)
	}
	if e := b.reserve(20); e != nil {
		t.Fatal(e)
	}
	if b.high != 32 {
		t.Fatal("exact boundary lost")
	}
	if e := b.reserve(1); e == nil || b.used != 32 {
		t.Fatal("overflow allocated or mutated state")
	}
	b.release(20)
	if e := b.reserve(20); e != nil {
		t.Fatal("released reservation not reusable")
	}
}

func TestAppendCapacityChargesTransientBacking(t *testing.T) {
	b := &memoryBudget{limit: 24}
	a, e := appendPrivate([]uint64(nil), 7, b)
	if e != nil {
		t.Fatal(e)
	}
	a, e = appendPrivate(a, 8, b)
	if e != nil || len(a) != 2 || a[0] != 7 || a[1] != 8 || b.high != 24 || b.used != 16 {
		t.Fatal("backing charge incorrect")
	}
	if _, e = appendPrivate(a, 9, b); e == nil {
		t.Fatal("old plus new backing exceeded cap")
	}
}

func TestAllocationHookRejectsGrowthWithoutChangingLiveBacking(t *testing.T) {
	values := []uint64{7, 8}
	b := &memoryBudget{limit: 40, used: 16}
	calls := 0
	b.beforeAllocation = func(n uint64) error {
		calls++
		b.mu.Lock()
		defer b.mu.Unlock()
		if n != 24 || b.used != 40 {
			t.Fatal("hook did not observe the old/new reservation")
		}
		return fail(ReasonLimit)
	}
	next, err := appendPrivate(values, 9, b)
	if reasonOf(err) != ReasonLimit || calls != 1 || b.used != 16 || len(next) != 2 || &next[0] != &values[0] || values[0] != 7 || values[1] != 8 {
		t.Fatal("rejected host admission changed or released live storage")
	}
}

func TestOwnershipReservationDoesNotInvokeAllocationHook(t *testing.T) {
	b := &memoryBudget{limit: 16}
	calls := 0
	b.beforeAllocation = func(uint64) error {
		calls++
		return fail(ReasonLimit)
	}
	if err := b.reserve(16); err != nil || calls != 0 || b.used != 16 {
		t.Fatal("ownership transfer was confused with an allocation")
	}
	if err := b.checkAllocation(0); err != nil || calls != 0 {
		t.Fatal("zero allocation invoked a host probe")
	}
	b.release(16)
}

func TestScratchHostRejectionRollsBackReservation(t *testing.T) {
	b := &memoryBudget{limit: 32, used: 8}
	b.beforeAllocation = func(n uint64) error {
		if n != 24 {
			t.Fatal("wrong prospective scratch cost")
		}
		return fail(ReasonUnsupported)
	}
	if release, err := scratchReservation(b, 24); reasonOf(err) != ReasonUnsupported || release != nil || b.used != 8 {
		t.Fatal("rejected scratch retained its reservation")
	}
}
