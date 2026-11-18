package nodeview

import (
	"math"
	"sync"
	"unsafe"
)

type memoryBudget struct {
	mu                sync.Mutex
	used, high, limit uint64
	beforeAllocation  func(uint64) error
}

func (b *memoryBudget) checkAllocation(n uint64) error {
	if b == nil || n == 0 || b.beforeAllocation == nil {
		return nil
	}
	return b.beforeAllocation(n)
}

func (b *memoryBudget) reserve(n uint64) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used > b.limit || n > b.limit-b.used {
		return attachBound(fail(ReasonLimit), boundDetail{boundBudget, boundBytes, b.used, n, b.limit, b.high})
	}
	b.used += n
	b.high = max(b.high, b.used)
	return nil
}
func (b *memoryBudget) release(n uint64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.used {
		b.used = 0
	} else {
		b.used -= n
	}
}

func appendCapacity[T any](values []T, n int, b *memoryBudget) ([]T, error) {
	if n < 0 || n > math.MaxInt-len(values) {
		return values, fail(ReasonLimit)
	}
	need := len(values) + n
	if need <= cap(values) {
		return values, nil
	}
	var zero T
	size := uint64(unsafe.Sizeof(zero))
	if size != 0 && uint64(need) > math.MaxUint64/size {
		return values, fail(ReasonLimit)
	}
	bytes := uint64(need) * size
	if e := b.reserve(bytes); e != nil {
		return values, e
	}
	if e := b.checkAllocation(bytes); e != nil {
		b.release(bytes)
		return values, e
	}
	next := make([]T, len(values), need)
	copy(next, values)
	clear(values)
	b.release(uint64(cap(values)) * size)
	return next, nil
}

func appendPrivate[T any](values []T, value T, b *memoryBudget) ([]T, error) {
	next, e := appendCapacity(values, 1, b)
	if e != nil {
		return values, e
	}
	return append(next, value), nil
}

func scorerMemoryEstimate(views viewSet, layout *predictionLayout, frozen frozenTraining) (uint64, error) {
	if layout == nil || layout.total > 491520 {
		return 0, fail(ReasonLimit)
	}
	total := uint64(2<<20) + uint64(layout.total)*uint64(8*unsafe.Sizeof(pairValue{}))
	var largestMailbox uint64
	for _, node := range views.nodes {
		total += uint64(len(node.cells)) * uint64(2*unsafe.Sizeof(cellSample{}))
		total += uint64(len(node.mailbox)) * uint64(2*unsafe.Sizeof(mailboxObservation{}))
		total += uint64(len(node.setups))*uint64(2*unsafe.Sizeof(setupView{})) + uint64(len(node.connections))*uint64(2*unsafe.Sizeof(connectionView{}))
		total += uint64(len(node.releases)) * uint64(2*unsafe.Sizeof(releaseView{}))
		largestMailbox = max(largestMailbox, uint64(len(node.mailbox)))
	}
	if frozen.request != nil || frozen.record != nil {
		total += largestMailbox * (18*8 + 24 + 18*2 + 32 + 384)
	} else {
		total += largestMailbox * 18 * 2
	}
	total += uint64(layout.total+63) / 64 * 8
	return total, nil
}

func predictionBackingBytes(p predictions) uint64 {
	total := uint64(cap(p.methods))*uint64(unsafe.Sizeof(predictedMethod{})) + uint64(cap(p.seen))*8
	for _, m := range p.methods {
		total += uint64(cap(m.values))*uint64(unsafe.Sizeof(pairValue{})) + uint64(cap(m.matches))*16
	}
	if p.layout != nil {
		total += uint64(unsafe.Sizeof(*p.layout))
		for _, pop := range p.layout.mail {
			total += uint64(cap(pop)) * 24
			for _, rows := range pop {
				total += uint64(cap(rows)) * 8
			}
		}
	}
	return total
}

func scratchReservation(b *memoryBudget, n uint64) (func(), error) {
	if e := b.reserve(n); e != nil {
		return nil, e
	}
	if e := b.checkAllocation(n); e != nil {
		b.release(n)
		return nil, e
	}
	return func() { b.release(n) }, nil
}

func metricScratchBytes(scores, groups, maxGroup int) (uint64, error) {
	if scores < 0 || scores > maxSelectedCells || groups < 0 || groups > 128 || maxGroup < 0 || maxGroup > scores {
		return 0, fail(ReasonLimit)
	}
	k, ok := checkedProduct(groups, maxGroup, 128*maxSelectedCells)
	if !ok {
		return 0, fail(ReasonLimit)
	}
	return uint64(scores)*512 + uint64(k)*192 + 2<<20, nil
}

func releaseCapacity[T any](values []T, b *memoryBudget) {
	if b == nil {
		return
	}
	var zero T
	b.release(uint64(cap(values)) * uint64(unsafe.Sizeof(zero)))
}
