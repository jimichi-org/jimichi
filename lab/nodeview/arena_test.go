package nodeview

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func logicalChunkArena(t *testing.T, maximum, chunk, allocated int, budget *memoryBudget) *lockedArena {
	t.Helper()
	a := &lockedArena{maximum: maximum, chunk: chunk, allocated: allocated, budget: budget}
	for i := 0; i < allocated; i += chunk {
		b, err := secmem.New(min(chunk, allocated-i))
		if err != nil {
			t.Fatal(err)
		}
		a.chunks[i/chunk] = b
	}
	a.buffer = a.chunks[0]
	t.Cleanup(a.close)
	return a
}

func TestArenaChunkAddressingKeepsExistingReferences(t *testing.T) {
	budget := &memoryBudget{limit: 72, used: 72, high: 72}
	a := logicalChunkArena(t, 64, 32, 64, budget)
	first := bytes.Repeat([]byte{7}, 24)
	r1, ok := a.copy(first)
	if !ok {
		t.Fatal("first chunk copy failed")
	}
	borrowed := a.bytes(r1)
	r2, ok := a.copy(bytes.Repeat([]byte{9}, 16))
	if !ok || r2.offset != 32 || a.used != 48 || a.live != 40 || a.high != 48 || len(a.free) != 1 || a.free[0] != (freeSpan{24, 8}) {
		t.Fatal("chunk boundary did not retain its occupied padding")
	}
	if !a.valid(r1) || !a.valid(r2) || !bytes.Equal(borrowed, first) || !bytes.Equal(a.bytes(r1), first) || a.valid(arenaRef{31, 2}) {
		t.Fatal("growth changed an existing reference or allowed a split reference")
	}
	a.erase(&r1)
	if !bytes.Equal(borrowed, make([]byte, 24)) {
		t.Fatal("erased first-chunk contents survived")
	}
	r3, ok := a.copy(bytes.Repeat([]byte{5}, 32))
	if !ok || r3.offset != 0 || a.used != 48 || a.high != 48 {
		t.Fatal("first-chunk free space was not reusable")
	}
	if !bytes.Equal(a.bytes(r2), bytes.Repeat([]byte{9}, 16)) {
		t.Fatal("free-space reuse moved another chunk's reference")
	}
}

func TestArenaFreeSpansNeverMergeAcrossChunks(t *testing.T) {
	a := logicalChunkArena(t, 64, 32, 64, &memoryBudget{limit: 64, used: 64})
	r1, _ := a.copy(bytes.Repeat([]byte{1}, 32))
	r2, _ := a.copy(bytes.Repeat([]byte{2}, 32))
	if _, ok := a.copy([]byte{3}); ok {
		t.Fatal("arena exceeded its unchanged maximum")
	}
	a.erase(&r1)
	a.erase(&r2)
	if len(a.free) != 2 || a.free[0] != (freeSpan{0, 32}) || a.free[1] != (freeSpan{32, 32}) || a.live != 0 || a.high != 64 {
		t.Fatal("noncontiguous chunks became one free span")
	}
	if _, ok := a.copy(make([]byte, 40)); ok {
		t.Fatal("one reference crossed noncontiguous storage")
	}
	for i := range 2 {
		r, ok := a.copy(bytes.Repeat([]byte{byte(7 + i)}, 32))
		if !ok || r.offset != 32*i {
			t.Fatal("full chunk capacity was lost after erasure")
		}
	}
}

func TestArenaGrowthRejectsBeforeChangingOwnedState(t *testing.T) {
	budget := &memoryBudget{limit: 63, used: 32, high: 32}
	a := logicalChunkArena(t, 64, 32, 32, budget)
	r, ok := a.copy(bytes.Repeat([]byte{4}, 28))
	if !ok {
		t.Fatal("first copy failed")
	}
	borrowed := a.bytes(r)
	free := append([]freeSpan(nil), a.free...)
	if _, ok := a.copy(make([]byte, 8)); ok || a.used != 28 || a.live != 28 || a.high != 28 || a.allocated != 32 || a.chunks[1] != nil || budget.used != 32 || budget.high != 32 || !reflect.DeepEqual(a.free, free) {
		t.Fatal("rejected growth allocated, changed extent or released a live charge")
	}
	if !bytes.Equal(borrowed, bytes.Repeat([]byte{4}, 28)) || !a.valid(r) {
		t.Fatal("rejected growth invalidated prior raw data")
	}
}

func TestArenaCloseReleasesEachCommittedChunkOnce(t *testing.T) {
	budget := &memoryBudget{limit: 72, used: 72}
	a := logicalChunkArena(t, 64, 32, 64, budget)
	first, second := a.chunks[0], a.chunks[1]
	r1, _ := a.copy(make([]byte, 32))
	r2, _ := a.copy(make([]byte, 1))
	a.close()
	if first.Len() != 0 || second.Len() != 0 || a.buffer != nil || a.allocated != 0 || budget.used != 8 || a.valid(r1) || a.valid(r2) {
		t.Fatal("close retained backing or lost another owner's allowance")
	}
	a.close()
	if budget.used != 8 {
		t.Fatal("second close released another owner's reservation")
	}
	if _, ok := a.copy([]byte{1}); ok {
		t.Fatal("closed arena accepted raw data")
	}
}

func TestBudgetedArenaRejectsUnreservedInitialChunk(t *testing.T) {
	budget := &memoryBudget{limit: 31}
	if a, err := newBudgetedArena(64, 32, budget); reasonOf(err) != ReasonLimit || a != nil || budget.used != 0 || budget.high != 0 {
		t.Fatal("initial allocation preceded its reservation")
	}
	for _, pair := range [][2]int{{0, 32}, {64, 0}, {32, 64}, {288, 32}} {
		if a, err := newBudgetedArena(pair[0], pair[1], budget); err == nil || a != nil || budget.used != 0 {
			t.Fatal("invalid chunk layout changed the budget")
		}
	}
}

func TestBudgetedArenaHostRejectionRollsBackBeforeMapping(t *testing.T) {
	budget := &memoryBudget{limit: 64}
	calls := 0
	budget.beforeAllocation = func(n uint64) error {
		calls++
		if n != 32 || budget.used != 32 {
			t.Fatal("initial chunk was not reserved before its host check")
		}
		return fail(ReasonLimit)
	}
	if a, err := newBudgetedArena(64, 32, budget); reasonOf(err) != ReasonLimit || a != nil || calls != 1 || budget.used != 0 {
		t.Fatal("host rejection created or retained an initial mapping")
	}
	a := logicalChunkArena(t, 64, 32, 32, budget)
	budget.used = 32
	r, _ := a.copy(bytes.Repeat([]byte{4}, 28))
	budget.beforeAllocation = func(n uint64) error {
		calls++
		if n != 32 || budget.used != 64 {
			t.Fatal("second chunk was not reserved before its host check")
		}
		return fail(ReasonLimit)
	}
	if _, ok := a.copy(make([]byte, 8)); ok || calls != 2 || budget.used != 32 || a.allocated != 32 || a.chunks[1] != nil || a.used != 28 || !bytes.Equal(a.bytes(r), bytes.Repeat([]byte{4}, 28)) {
		t.Fatal("host rejection changed existing raw storage")
	}
}

func TestCommittedArenaRemovesFixedUnusedBacking(t *testing.T) {
	// 114166272+22565504=136731776 exceeds 128 MiB by 2514048 bytes
	// one committed 32 MiB chunk instead of an upfront 64 MiB saves 33554432
	const parent, scorer = 114166272, 22565504
	old := &memoryBudget{limit: controllerArenaBytes, used: parent}
	if old.reserve(scorer) == nil {
		t.Fatal("in-cap profile counterexample unexpectedly fit its old reservation")
	}
	current := &memoryBudget{limit: controllerArenaBytes, used: parent - 32<<20}
	if err := current.reserve(scorer); err != nil || current.used != 103177344 || current.limit-current.used != 31040384 {
		t.Fatal("committed-only accounting lost its exact headroom")
	}
	// Seven 8 MiB chunks leave the final 8 MiB unallocated: 136731776-8388608
	current = &memoryBudget{limit: controllerArenaBytes, used: parent - 8<<20}
	if err := current.reserve(scorer); err != nil || current.used != 128343168 || current.limit-current.used != 5874560 {
		t.Fatal("finer committed chunks lost their exact headroom")
	}
}

func TestArenaEightChunksKeepFullMaximumAndSeparateSpans(t *testing.T) {
	budget := &memoryBudget{limit: 72, used: 72}
	a := logicalChunkArena(t, 64, 8, 64, budget)
	var refs [8]arenaRef
	var borrowed [8][]byte
	for i := range refs {
		var ok bool
		refs[i], ok = a.copy(bytes.Repeat([]byte{byte(i + 1)}, 8))
		if !ok || refs[i].offset != 8*i || !a.valid(refs[i]) {
			t.Fatal("eight-chunk maximum did not preserve its addresses")
		}
		borrowed[i] = a.bytes(refs[i])
	}
	if a.used != 64 || a.live != 64 || a.high != 64 || a.valid(arenaRef{7, 2}) || a.valid(arenaRef{63, 2}) {
		t.Fatal("chunk boundaries or complete capacity changed")
	}
	if _, ok := a.copy([]byte{9}); ok {
		t.Fatal("ninth allocation exceeded the same maximum")
	}
	for i := range refs {
		if !bytes.Equal(borrowed[i], bytes.Repeat([]byte{byte(i + 1)}, 8)) {
			t.Fatal("later chunks moved an earlier backing")
		}
		a.erase(&refs[i])
		if !bytes.Equal(borrowed[i], make([]byte, 8)) {
			t.Fatal("chunk erasure left owned bytes")
		}
	}
	if len(a.free) != 8 {
		t.Fatal("free spans coalesced across separate chunks")
	}
	for i := range refs {
		r, ok := a.copy(make([]byte, 8))
		if !ok || r.offset != 8*i {
			t.Fatal("erasure reduced reusable total capacity")
		}
	}
	a.close()
	if budget.used != 8 {
		t.Fatal("eight-chunk release changed the fixed allowance")
	}
}

func TestArenaLastChunkAdmissionFailurePreservesEarlierChunks(t *testing.T) {
	budget := &memoryBudget{limit: 63, used: 56, high: 56}
	a := logicalChunkArena(t, 64, 8, 56, budget)
	var refs [7]arenaRef
	for i := range refs {
		refs[i], _ = a.copy(bytes.Repeat([]byte{byte(i + 1)}, 8))
	}
	if _, ok := a.copy(make([]byte, 8)); ok || a.chunks[7] != nil || a.used != 56 || a.allocated != 56 || budget.used != 56 || budget.high != 56 {
		t.Fatal("rejected final chunk changed earlier storage or reservations")
	}
	for i, r := range refs {
		if !a.valid(r) || !bytes.Equal(a.bytes(r), bytes.Repeat([]byte{byte(i + 1)}, 8)) {
			t.Fatal("last-chunk failure invalidated an earlier reference")
		}
	}
}
