package keymem

import (
	"errors"
	"io"
	"math"
	"runtime"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

const (
	heapHeader      = "go1.7 heap dump\n"
	heapStreamLimit = uint64(128 << 20)
	heapRecordLimit = uint64(1_000_000)
	heapFieldLimit  = uint64(1_000_000)
	heapStringLimit = uint64(1 << 20)
	heapStackLimit  = uint64(100_000)
	heapScratchSize = 64 << 10
)

type parseResult struct {
	Complete          bool
	StreamBytes       uint64
	ObjectRecords     uint64
	ObjectBytes       uint64
	UnscoredBlobBytes uint64
	Matches           [3]uint64
	PositiveOK        bool
	NegativeOK        bool
}

type heapDecoder struct {
	reader   io.Reader
	scratch  *secmem.Buffer
	position int
	end      int
	pending  error
	consumed uint64
	result   parseResult
	matchers [5]streamMatcher
	marker   uint64
	positive bool
	params   bool
	memstats bool
	data     bool
	bss      bool
}

func parseHeap(r io.Reader, patterns [5]*secmem.Buffer, markerAddress uint64) (result parseResult, err error) {
	if secmem.CurrentPolicy() != secmem.Protected {
		return result, errProtectionUnavailable
	}
	if markerAddress > math.MaxUint64-32 {
		return result, errParseInvalid
	}
	d := heapDecoder{reader: r, marker: markerAddress}
	for i, pattern := range patterns {
		if pattern == nil || pattern.Len() != 32 {
			return result, errParseInvalid
		}
		if runtime.GOOS == "linux" && !pattern.Locked() {
			return result, errProtectionUnavailable
		}
		d.matchers[i], err = newStreamMatcher(pattern)
		if err != nil {
			return result, err
		}
	}
	d.scratch, err = secmem.New(heapScratchSize)
	if err != nil {
		if errors.Is(err, secmem.ErrNotLocked) {
			return result, errProtectionUnavailable
		}
		return result, errAllocationFailed
	}
	defer func() {
		secmem.Zero(d.scratch.Bytes())
		d.scratch.Release()
		result = d.result
		if err != nil {
			result.Matches = [3]uint64{}
		}
	}()
	if runtime.GOOS == "linux" && !d.scratch.Locked() {
		return result, errProtectionUnavailable
	}
	for i := range len(heapHeader) {
		var b byte
		b, err = d.byte()
		if err != nil {
			return result, err
		}
		if b != heapHeader[i] {
			return result, errParseInvalid
		}
	}
	for records := uint64(0); ; records++ {
		if records == heapRecordLimit {
			return result, errCaptureLimit
		}
		var tag uint64
		tag, err = d.uint()
		if err != nil {
			return result, err
		}
		if records == 0 && tag != 6 {
			return result, errParseInvalid
		}
		if tag == 0 {
			if !d.params || !d.memstats || !d.data || !d.bss {
				return result, errParseInvalid
			}
			if err = d.terminalEOF(); err != nil {
				return result, err
			}
			d.result.Complete = true
			d.result.PositiveOK = d.positive
			d.result.NegativeOK = d.matchers[4].count == 0
			if !d.result.PositiveOK || !d.result.NegativeOK {
				return result, errControlFailed
			}
			for i := range d.result.Matches {
				d.result.Matches[i] = d.matchers[i].count
			}
			return result, nil
		}
		if err = d.record(tag); err != nil {
			return result, err
		}
	}
}

func (d *heapDecoder) fill() error {
	if d.position < d.end {
		return nil
	}
	if d.pending != nil {
		return d.pending
	}
	secmem.Zero(d.scratch.Bytes())
	want := uint64(heapScratchSize)
	if remaining := heapStreamLimit - d.result.StreamBytes + 1; want > remaining {
		want = remaining
	}
	for attempts := 0; attempts < 100; attempts++ {
		n, err := d.reader.Read(d.scratch.Bytes()[:int(want)])
		if n < 0 || n > int(want) {
			return errControllerFailed
		}
		d.result.StreamBytes += uint64(n)
		if d.result.StreamBytes > heapStreamLimit {
			return errCaptureLimit
		}
		d.position, d.end, d.pending = 0, n, err
		if n > 0 {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return errControllerFailed
}

func (d *heapDecoder) byte() (byte, error) {
	if err := d.fill(); err != nil {
		return 0, heapReadError(err)
	}
	b := d.scratch.Bytes()[d.position]
	d.position++
	d.consumed++
	return b, nil
}

func heapReadError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errCaptureIncomplete
	}
	if errors.Is(err, errCaptureLimit) || errors.Is(err, errControllerFailed) {
		return err
	}
	return errControllerFailed
}

func (d *heapDecoder) terminalEOF() error {
	err := d.fill()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errParseInvalid
	}
	return heapReadError(err)
}

func (d *heapDecoder) uint() (uint64, error) {
	var value uint64
	for i := 0; i < 10; i++ {
		b, err := d.byte()
		if err != nil {
			return 0, err
		}
		if i == 9 && b > 1 {
			return 0, errParseInvalid
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			if i > 0 && b == 0 {
				return 0, errParseInvalid
			}
			return value, nil
		}
	}
	return 0, errParseInvalid
}

func (d *heapDecoder) uints(count int) error {
	for range count {
		if _, err := d.uint(); err != nil {
			return err
		}
	}
	return nil
}

func (d *heapDecoder) bool() (uint64, error) {
	v, err := d.uint()
	if err != nil {
		return 0, err
	}
	if v > 1 {
		return 0, errParseInvalid
	}
	return v, nil
}

func (d *heapDecoder) length(limit uint64) (uint64, error) {
	n, err := d.uint()
	if err != nil {
		return 0, err
	}
	if n > limit || n > heapStreamLimit-d.consumed {
		return 0, errCaptureLimit
	}
	return n, nil
}

func (d *heapDecoder) fields() error {
	for count := uint64(0); ; count++ {
		kind, err := d.uint()
		if err != nil {
			return err
		}
		if kind == 0 {
			return nil
		}
		if kind > 3 {
			return errParseInvalid
		}
		if count == heapFieldLimit {
			return errCaptureLimit
		}
		if err := d.uints(1); err != nil {
			return err
		}
	}
}

func (d *heapDecoder) blob(scored bool, address uint64) error {
	n, err := d.length(heapStreamLimit)
	if err != nil {
		return err
	}
	if address > math.MaxUint64-n {
		return errParseInvalid
	}
	if scored {
		d.result.ObjectRecords++
		d.result.ObjectBytes += n
		for i := range d.matchers {
			d.matchers[i].reset()
		}
	} else {
		d.result.UnscoredBlobBytes += n
	}
	for offset := uint64(0); offset < n; {
		if err := d.fill(); err != nil {
			return heapReadError(err)
		}
		count := uint64(d.end - d.position)
		if count > n-offset {
			count = n - offset
		}
		if scored {
			chunk := d.scratch.Bytes()[d.position : d.position+int(count)]
			for i := range d.matchers {
				wanted := uint64(math.MaxUint64)
				if i == 3 && d.marker >= address && d.marker-address <= n && n-(d.marker-address) >= 32 {
					wanted = d.marker - address
				}
				if d.matchers[i].consume(chunk, offset, wanted) && i == 3 {
					d.positive = true
				}
			}
		}
		d.position += int(count)
		d.consumed += count
		offset += count
	}
	return nil
}

func (d *heapDecoder) string(expected string) error {
	n, err := d.length(heapStringLimit)
	if err != nil {
		return err
	}
	if expected != "" && n != uint64(len(expected)) {
		return errParseInvalid
	}
	d.result.UnscoredBlobBytes += n
	for offset := uint64(0); offset < n; {
		if err := d.fill(); err != nil {
			return heapReadError(err)
		}
		count := uint64(d.end - d.position)
		if count > n-offset {
			count = n - offset
		}
		if expected != "" {
			chunk := d.scratch.Bytes()[d.position : d.position+int(count)]
			for i, b := range chunk {
				if b != expected[offset+uint64(i)] {
					return errParseInvalid
				}
			}
		}
		d.position += int(count)
		d.consumed += count
		offset += count
	}
	return nil
}

func (d *heapDecoder) record(tag uint64) error {
	switch tag {
	case 1, 12, 13:
		if tag == 12 {
			if d.data {
				return errParseInvalid
			}
			d.data = true
		}
		if tag == 13 {
			if d.bss {
				return errParseInvalid
			}
			d.bss = true
		}
		address, err := d.uint()
		if err != nil {
			return err
		}
		if err := d.blob(tag == 1, address); err != nil {
			return err
		}
		return d.fields()
	case 2:
		if err := d.string(""); err != nil {
			return err
		}
		return d.uints(1)
	case 3:
		if err := d.uints(2); err != nil {
			return err
		}
		if err := d.string(""); err != nil {
			return err
		}
		_, err := d.bool()
		return err
	case 4:
		for i := 0; i < 8; i++ {
			if i == 5 || i == 6 {
				if _, err := d.bool(); err != nil {
					return err
				}
			} else if err := d.uints(1); err != nil {
				return err
			}
		}
		if err := d.string(""); err != nil {
			return err
		}
		return d.uints(4)
	case 5:
		if err := d.uints(3); err != nil {
			return err
		}
		if err := d.blob(false, 0); err != nil {
			return err
		}
		if err := d.uints(3); err != nil {
			return err
		}
		if err := d.string(""); err != nil {
			return err
		}
		return d.fields()
	case 6:
		if d.params {
			return errParseInvalid
		}
		d.params = true
		big, err := d.bool()
		if err != nil {
			return err
		}
		ptr, err := d.uint()
		if err != nil {
			return err
		}
		if big != 0 || ptr != 8 {
			return errParseInvalid
		}
		if err := d.uints(2); err != nil {
			return err
		}
		if err := d.string("amd64"); err != nil {
			return err
		}
		if err := d.string("go1.27.3"); err != nil {
			return err
		}
		return d.uints(1)
	case 7, 11:
		return d.uints(5)
	case 8, 17:
		return d.uints(2)
	case 9:
		return d.uints(3)
	case 10:
		if d.memstats {
			return errParseInvalid
		}
		d.memstats = true
		return d.uints(281)
	case 14:
		return d.uints(7)
	case 15:
		return d.uints(6)
	case 16:
		if err := d.uints(2); err != nil {
			return err
		}
		stack, err := d.uint()
		if err != nil {
			return err
		}
		if stack > heapStackLimit {
			return errCaptureLimit
		}
		for range stack {
			if err := d.string(""); err != nil {
				return err
			}
			if err := d.string(""); err != nil {
				return err
			}
			if err := d.uints(1); err != nil {
				return err
			}
		}
		return d.uints(2)
	default:
		return errParseInvalid
	}
}
