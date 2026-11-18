package nodeview

import (
	"math"
	"runtime"
	"sync"
	"unsafe"
)

type clientTruthCapacity struct {
	rawDenied
	messages, setups, seals, requests, recordBytes uint64
	wireBytes, frames                              uint64
}

const clientPacketBytes = maxFrameBytes - 30

func clientTruthArrayCaps() [4]int {
	return [4]int{
		min(maxMessages, maxIPCMessages, clientArenaBytes/165),
		min(maxContexts, maxIPCMessages, clientArenaBytes/45),
		min(maxTruthRecords, clientArenaBytes/399),
		min(maxTruthRecords, clientArenaBytes/12, maxIPCMessages*128),
	}
}

func nextClientTruth(c clientTruthCapacity, kind uint8, recordBytes int) (clientTruthCapacity, error) {
	if kind < 1 || kind > 4 || recordBytes != 0 && (kind != 4 || recordBytes != 392) {
		return c, fail(ReasonContract)
	}
	if c.messages > maxMessages || c.setups > maxContexts || c.seals > maxTruthRecords || c.requests > maxTruthRecords || c.recordBytes > 392*c.requests || c.recordBytes%392 != 0 {
		return c, fail(ReasonContract)
	}
	next := c
	switch kind {
	case 1:
		next.messages++
	case 2:
		next.setups++
	case 3:
		next.seals++
	case 4:
		next.requests++
		next.recordBytes += uint64(recordBytes)
	}
	if next.messages > maxMessages || next.setups > maxContexts || next.seals > maxTruthRecords || next.requests > maxTruthRecords {
		return c, fail(ReasonLimit)
	}
	size, e := clientTruthSize(next)
	if e != nil {
		return c, e
	}
	if size.bytes > clientArenaBytes || size.frames > maxIPCMessages {
		return c, fail(ReasonLimit)
	}
	next.wireBytes, next.frames = size.bytes, size.frames
	return next, nil
}

func clientTruthSize(c clientTruthCapacity) (streamSize, error) {
	var size streamSize
	for _, row := range [4][3]uint64{{c.messages, 132, 1}, {c.setups, 12, 1}, {c.seals, 399, 128}, {c.requests, 12, 128}} {
		if e := size.add(row[0], row[1], row[2]); e != nil {
			return size, e
		}
	}
	if c.recordBytes > math.MaxUint64-size.bytes {
		return size, fail(ReasonLimit)
	}
	size.bytes += c.recordBytes
	return size, nil
}

func roundClientBacking(n uint64) (uint64, error) {
	if n > math.MaxUint64-8191 {
		return 0, fail(ReasonLimit)
	}
	return (n + 8191) / 8192 * 8192, nil
}

func clientTruthBackingBytes() (uint64, error) {
	var truth privateTruth
	var capture privateCapture
	var plan workloadPlan
	if runtime.Version() != "go1.27.4" || runtime.GOARCH != "amd64" || unsafe.Sizeof(int(0)) != 8 || unsafe.Sizeof(ReasonNone) != 16 || unsafe.Sizeof(sync.Mutex{}) != 8 || unsafe.Sizeof(arenaRef{}) != 16 || unsafe.Sizeof(clientTruthCapacity{}) != 56 || unsafe.Sizeof(truth) != 248 || unsafe.Sizeof(capture) != 320 || unsafe.Sizeof(plan) != 112 || unsafe.Offsetof(truth.capacity) != 160 || unsafe.Offsetof(truth.client) != 216 || unsafe.Offsetof(truth.clientPacket) != 224 || unsafe.Offsetof(capture.err) != 296 || unsafe.Offsetof(capture.frozen) != 312 || unsafe.Offsetof(plan.sourceLimit) != 104 {
		return 0, fail(ReasonUnsupported)
	}
	caps := clientTruthArrayCaps()
	widths := [4]uint64{uint64(unsafe.Sizeof(actualMessage{})), uint64(unsafe.Sizeof(actualSetup{})), uint64(unsafe.Sizeof(actualSeal{})), uint64(unsafe.Sizeof(actualRequest{}))}
	if widths != [4]uint64{32, 24, 32, 40} {
		return 0, fail(ReasonUnsupported)
	}
	var total uint64
	for i, capacity := range caps {
		physical, e := roundClientBacking(uint64(capacity) * widths[i])
		if e != nil || physical > math.MaxUint64-total {
			return 0, fail(ReasonLimit)
		}
		total += physical
	}
	packet, e := roundClientBacking(clientPacketBytes)
	if e != nil {
		return 0, e
	}
	control, e := roundClientBacking(uint64(unsafe.Sizeof(capture) + unsafe.Sizeof(plan)))
	if e != nil || packet > math.MaxUint64-total || control > math.MaxUint64-total-packet {
		return 0, fail(ReasonLimit)
	}
	return total + packet + control, nil
}

func clientTruthStartupBytes() (uint64, error) {
	n, e := clientTruthBackingBytes()
	if e != nil {
		return 0, e
	}
	// the locked payload, inherited free-span backing and arena/map startup controls coexist with T
	return n + clientArenaBytes + 1024*uint64(unsafe.Sizeof(freeSpan{})) + 3*8192, nil
}

func (t *privateTruth) nextClient(kind uint8, recordBytes, copyBytes int) (clientTruthCapacity, error) {
	if !t.client {
		return t.capacity, nil
	}
	if t.capacity.messages != uint64(len(t.messages)) || t.capacity.setups != uint64(len(t.setups)) || t.capacity.seals != uint64(len(t.seals)) || t.capacity.requests != uint64(len(t.requests)) {
		return t.capacity, fail(ReasonContract)
	}
	next, e := nextClientTruth(t.capacity, kind, recordBytes)
	if e != nil {
		return t.capacity, e
	}
	var length, capacity int
	switch kind {
	case 1:
		length, capacity = len(t.messages), cap(t.messages)
	case 2:
		length, capacity = len(t.setups), cap(t.setups)
	case 3:
		length, capacity = len(t.seals), cap(t.seals)
	case 4:
		length, capacity = len(t.requests), cap(t.requests)
	}
	if length >= capacity {
		return t.capacity, fail(ReasonLimit)
	}
	if copyBytes < 0 || t.arena == nil || t.arena.buffer == nil {
		return t.capacity, fail(ReasonLimit)
	}
	if copyBytes > 0 {
		if t.arena.maximum != 0 || len(t.arena.free) != 0 {
			return t.capacity, fail(ReasonContract)
		}
		if copyBytes > t.arena.buffer.Len()-t.arena.used {
			return t.capacity, fail(ReasonLimit)
		}
	}
	return next, nil
}

func (p *privateCapture) latch(reason Reason) {
	p.err = preferredRuntimeReason(p.err, reason)
}

func (p *privateCapture) sourceMessage(ref arenaRef) (int, error) {
	if p.err != ReasonNone {
		return -1, fail(p.err)
	}
	if p.frozen || !p.truth.arena.valid(ref) || ref.size != payloadBytes {
		p.latch(ReasonContract)
		return -1, fail(p.err)
	}
	next, e := p.truth.nextClient(1, 0, 0)
	if e != nil {
		p.latch(reasonOf(e))
		return -1, e
	}
	p.truth.messages = append(p.truth.messages, actualMessage{side: p.side, body: ref})
	p.truth.capacity = next
	return len(p.truth.messages) - 1, nil
}
