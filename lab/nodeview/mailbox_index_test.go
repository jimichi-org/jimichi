package nodeview

import (
	"math"
	"slices"
	"testing"
	"unsafe"
)

func TestMailboxPreparedFetchKeysStayInactiveUntilObserved(t *testing.T) {
	put := mailboxObservation{Circuit: 2, Order: 0, CallNS: 20_000_000, ReturnNS: 20_000_000, Complete: true, HasPut: true, PutQueue: math.MaxUint32, RecordAlias: math.MaxUint32, RecordKind: 3}
	fetch := mailboxObservation{Circuit: math.MaxUint32, Order: math.MaxUint32, CallNS: 30_000_000, ReturnNS: 30_000_000, Complete: true, FetchQueue: math.MaxUint32}
	x, err := newPreparedMailboxExtractor(35_000_000, []mailboxObservation{put, fetch}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer x.wipe()
	key := mailboxFetchKey{math.MaxUint32, math.MaxUint32}
	at, found := x.fetches.find(key)
	if !found || x.fetches[at].initialized || x.fetchEntries != 0 || len(x.circuits) != 0 {
		t.Fatal("future fetch keys became active request history")
	}
	row, err := x.observe(put)
	if err != nil || row[16] != 0 || row[15] != 0 {
		t.Fatal("a future positive-time fetch primed an earlier put at zero")
	}
	if _, err := x.observe(fetch); err != nil {
		t.Fatal(err)
	}
	if !x.fetches[at].initialized || x.fetches[at].hasPrevious || x.fetches[at].latest != fetch.CallNS || x.fetchEntries != 1 {
		t.Fatal("first observed fetch invented a previous zero timestamp")
	}
	put.CallNS, put.ReturnNS = 40_000_000, 40_000_000
	row, err = x.observe(put)
	// the first actual 30ms fetch precedes the 40ms put by one 10ms bucket
	if err != nil || row[16] != 1 || row[15] != 1 {
		t.Fatal("an activated sparse fetch key lost its actual time")
	}
}

func TestMailboxFetchIndexExactCapacityAndFullWipe(t *testing.T) {
	if unsafe.Sizeof(mailboxFetchEntry{}) != 32 || unsafe.Sizeof(encodedMailboxRow{}) != 36 || unsafe.Sizeof(mailboxExtractor{}) != 64 {
		t.Fatal("mailbox working owners no longer match their accepted amd64 layout")
	}
	observations := []mailboxObservation{{FetchQueue: math.MaxUint32, Circuit: 7}, {}, {FetchQueue: math.MaxUint32, Circuit: 7}, {FetchQueue: 1, Circuit: math.MaxUint32}}
	before := slices.Clone(observations)
	index, err := makeMailboxFetchIndex(observations, nil)
	if err != nil || len(index) != 3 || cap(index) != len(observations) || !slices.Equal(observations, before) {
		t.Fatal("fetch-key preparation changed borrowed rows or its exact backing capacity")
	}
	for _, key := range []mailboxFetchKey{{}, {1, math.MaxUint32}, {math.MaxUint32, 7}} {
		at, found := index.find(key)
		if !found || index[at].initialized || index[at].hasPrevious {
			t.Fatal("zero or sparse fetch key was missing or preinitialized")
		}
	}
	backing := index[:cap(index)]
	for i := range backing {
		backing[i].latest, backing[i].initialized = 12345, true
	}
	index.wipe()
	for _, entry := range backing {
		if entry != (mailboxFetchEntry{}) {
			t.Fatal("fetch-key cleanup retained a deduplicated backing tail")
		}
	}
}

func TestMailboxStandaloneFetchGrowthWipesOnlyOldOwnedBacking(t *testing.T) {
	x := newMailboxExtractor(35_000_000)
	defer x.wipe()
	first := mailboxObservation{Circuit: 1, CallNS: 10_000_000, ReturnNS: 10_000_000, Complete: true, FetchQueue: 9}
	if _, err := x.observe(first); err != nil {
		t.Fatal(err)
	}
	old := x.fetches[:cap(x.fetches)]
	second := mailboxObservation{Circuit: 2, CallNS: 20_000_000, ReturnNS: 20_000_000, Complete: true, FetchQueue: math.MaxUint32}
	if _, err := x.observe(second); err != nil {
		t.Fatal(err)
	}
	for _, entry := range old {
		if entry != (mailboxFetchEntry{}) {
			t.Fatal("standalone fetch growth abandoned its old mutable history")
		}
	}
	if x.fetches.latestOther(9, 2, 30_000_000) != 10_000_000 || x.fetches.latestOther(math.MaxUint32, 1, 30_000_000) != 20_000_000 {
		t.Fatal("standalone sorted growth erased still-owned history")
	}
	current, circuits := x.fetches[:cap(x.fetches)], x.circuits
	x.wipe()
	if len(circuits) != 0 || x.fetches != nil || x.circuits != nil || x.observations != 0 || x.fetchEntries != 0 {
		t.Fatal("extractor cleanup retained its history owners")
	}
	for _, entry := range current {
		if entry != (mailboxFetchEntry{}) {
			t.Fatal("extractor cleanup did not clear the full fetch capacity")
		}
	}
}

func TestMailboxPreparedEqualTimeFetchUsesActualPreviousOnly(t *testing.T) {
	for _, earlier := range []bool{false, true} {
		var observations []mailboxObservation
		if earlier {
			observations = append(observations, mailboxObservation{Circuit: 1, Order: 0, Complete: true, CallNS: 10_000_000, ReturnNS: 10_000_000, FetchQueue: 9})
		}
		for _, order := range []uint32{1, 2} {
			observations = append(observations, mailboxObservation{Circuit: 1, Order: order, Complete: true, CallNS: 20_000_000, ReturnNS: 20_000_000, FetchQueue: 9})
		}
		observations = append(observations, mailboxObservation{Circuit: 2, Order: 3, Complete: true, CallNS: 20_000_000, ReturnNS: 20_000_000, HasPut: true, PutQueue: 9, RecordAlias: 1, RecordKind: 3})
		rows, err := extractMailboxRows(observations, 35_000_000)
		if err != nil {
			t.Fatal(err)
		}
		last := rows[len(rows)-1]
		if earlier && (last[16] != 1 || last[15] != 1) || !earlier && (last[16] != 0 || last[15] != 0) {
			t.Fatal("same-time fetch replaced actual previous time or manufactured zero history")
		}
		clear(rows)
	}
}

func TestMailboxOrderMembershipKeepsOriginalClockFailurePrecedence(t *testing.T) {
	for _, duplicateFirst := range []bool{false, true} {
		observations := []mailboxObservation{
			{Circuit: 1, Order: 0, Complete: true, CallNS: 10, ReturnNS: 9},
			{Circuit: 1, Order: math.MaxUint32, Complete: true, CallNS: 20, ReturnNS: 20},
			{Circuit: 1, Order: math.MaxUint32, Complete: true, CallNS: 30, ReturnNS: 30},
		}
		want := ReasonClock
		if duplicateFirst {
			observations[0].ReturnNS = observations[0].CallNS
			observations[1].Order, observations[1].ReturnNS = observations[0].Order, observations[1].CallNS-1
			want = ReasonContract
		}
		before := slices.Clone(observations)
		rows := make([]encodedMailboxRow, len(observations), 5)
		for i := range rows[:cap(rows)] {
			rows[:cap(rows)][i][0] = 99
		}
		if err := extractMailboxRowsInto(rows, observations, 35_000_000); reasonOf(err) != want {
			t.Fatalf("original-order failure changed: %v, want %s", err, want)
		}
		for _, row := range rows[:cap(rows)] {
			if row != (encodedMailboxRow{}) {
				t.Fatal("error path retained a partial output row or backing tail")
			}
		}
		if !slices.Equal(observations, before) {
			t.Fatal("membership preparation changed borrowed observation order")
		}
	}
}

func TestMailboxBudgetedPhysicalRejectionPreservesBorrowedAndChargedOwners(t *testing.T) {
	observations := []mailboxObservation{{Circuit: 1, Order: 0, CallNS: 10, ReturnNS: 10, Complete: true, FetchQueue: 9}, {Circuit: math.MaxUint32, Order: math.MaxUint32, CallNS: 20, ReturnNS: 20, Complete: true}}
	before := slices.Clone(observations)
	// row36R, permutation8R, fetch32R, pinned map10968+extractor64, membership8R
	wantAllocations := []uint64{72, 16, 64, 11032, 16}
	for reject := 1; reject <= len(wantAllocations); reject++ {
		var allocations []uint64
		budget := &memoryBudget{used: 1 << 20, high: 1 << 20, limit: 1 << 20}
		budget.beforeAllocation = func(n uint64) error {
			allocations = append(allocations, n)
			if len(allocations) == reject {
				return fail(ReasonClock)
			}
			return nil
		}
		rows, err := extractMailboxRowsBudgeted(observations, 35_000_000, budget)
		if reasonOf(err) != ReasonClock || rows != nil || !slices.Equal(allocations, wantAllocations[:reject]) || budget.used != 1<<20 || budget.high != 1<<20 || !slices.Equal(observations, before) {
			t.Fatal("physical rejection allocated later owners, hid its cause or changed existing ownership")
		}
	}
	for reject := 1; reject <= 4; reject++ {
		rows := make([]encodedMailboxRow, len(observations), 5)
		for i := range rows[:cap(rows)] {
			rows[:cap(rows)][i][0] = 99
		}
		calls := 0
		budget := &memoryBudget{beforeAllocation: func(uint64) error {
			calls++
			if calls == reject {
				return fail(ReasonLimit)
			}
			return nil
		}}
		if err := extractMailboxRowsIntoBudgeted(rows, observations, 35_000_000, budget); reasonOf(err) != ReasonLimit {
			t.Fatal("failed prepared extraction lost physical rejection")
		}
		for _, row := range rows[:cap(rows)] {
			if row != (encodedMailboxRow{}) {
				t.Fatal("physical failure retained caller-owned partial row backing")
			}
		}
	}
}

func TestBoundedMailboxRowsForwardsPhysicalBudget(t *testing.T) {
	borrowed := []mailboxObservation{{Circuit: 1, Order: 0, Complete: true, FetchQueue: math.MaxUint32}}
	calls := 0
	budget := &memoryBudget{used: 99, high: 99, limit: 99, beforeAllocation: func(n uint64) error {
		calls++
		if n != 36 {
			t.Fatal("bounded extraction bypassed its first row allocation check")
		}
		return fail(ReasonClock)
	}}
	rows, err := boundedMailboxRows(nodeView{position: 4, mailbox: borrowed, budget: budget}, 35_000_000)
	if rows != nil || reasonOf(err) != ReasonClock || calls != 1 || budget.used != 99 || borrowed[0].FetchQueue != math.MaxUint32 {
		t.Fatal("bounded extraction discarded its real parent physical budget")
	}
}

func TestMailboxBatchRetainsFullObservationAndFetchPairBound(t *testing.T) {
	observations := make([]mailboxObservation, 65536)
	for i := range observations {
		observations[i] = mailboxObservation{Circuit: math.MaxUint32 - uint32(i%128), Order: math.MaxUint32 - uint32(i), CallNS: int64(i), ReturnNS: int64(i), Complete: true, FetchQueue: math.MaxUint32 - uint32(i)}
	}
	rows, err := extractMailboxRows(observations, 35_000_000)
	if err != nil || len(rows) != len(observations) || rows[0][7] != 0 || rows[len(rows)-1][7] != 1 {
		t.Fatal("exact fetch storage imposed a smaller observation, pair or sparse-circuit bound")
	}
	clear(rows)
	clear(observations)
}

func TestMailboxPreparedFutureCircuitsDoNotConsumeActiveCircuitLimit(t *testing.T) {
	observations := make([]mailboxObservation, 129)
	for i := range observations {
		observations[i] = mailboxObservation{Circuit: uint32(i + 1), Order: uint32(i), CallNS: int64(i), ReturnNS: int64(i), Complete: true, FetchQueue: math.MaxUint32}
	}
	x, err := newPreparedMailboxExtractor(35_000_000, observations, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer x.wipe()
	for i, observation := range observations {
		row, err := x.observe(observation)
		row.wipe()
		if i < 128 && err != nil || i == 128 && reasonOf(err) != ReasonLimit {
			t.Fatal("future prepared circuits changed the actual 128-circuit limit or its failure point")
		}
	}
	if len(x.circuits) != 128 || x.fetchEntries != 128 || x.observations != 128 {
		t.Fatal("rejected circuit became active history")
	}
}
