package nodeview

import (
	"encoding/binary"
	"math"
	"sort"
	"unsafe"

	"github.com/jimichi-org/jimichi/lab/metrics"
	"github.com/jimichi-org/jimichi/mailbox"
)

const MailboxFeatureVersion = "mailbox18-release-v2"

const mailboxFeatureCount = 18

var errMailboxObservation = fail(ReasonContract)
var errMailboxClock = fail(ReasonClock)
var errMailboxLimit = fail(ReasonLimit)
var errPrivateMailbox = ErrRawSerialization

type mailboxObservation struct {
	record                            arenaRef
	Circuit, Order                    uint32
	CallNS, ReturnNS                  int64
	Complete                          bool
	Tag                               uint16
	PutQueue, FetchQueue, RecordAlias uint32
	HasPut                            bool
	RecordKind                        byte
	RecordNumber                      uint32
	ReplyStatus                       byte
}

func (mailboxObservation) MarshalJSON() ([]byte, error) { return nil, errPrivateMailbox }
func (mailboxObservation) String() string               { return "nodeview: private" }
func (mailboxObservation) GoString() string             { return "nodeview: private" }
func (o *mailboxObservation) wipe()                     { *o = mailboxObservation{} }

type rawMailboxFeatures struct {
	HasPut, PriorData, Repeat, PriorRequest, PriorPut, PriorOtherFetch bool
	Kind                                                               byte
	RecordNumber, Delta                                                uint32
	RequestGapNS, PutGapNS, OtherFetchNS, DeliverNS                    int64
	PreviousPutResult                                                  byte
}

func (rawMailboxFeatures) MarshalJSON() ([]byte, error) { return nil, errPrivateMailbox }
func (rawMailboxFeatures) String() string               { return "nodeview: private" }
func (rawMailboxFeatures) GoString() string             { return "nodeview: private" }
func (f *rawMailboxFeatures) wipe()                     { *f = rawMailboxFeatures{} }

type encodedMailboxRow [mailboxFeatureCount]int16

func (encodedMailboxRow) MarshalJSON() ([]byte, error) { return nil, errPrivateMailbox }
func (encodedMailboxRow) String() string               { return "nodeview: private" }
func (encodedMailboxRow) GoString() string             { return "nodeview: private" }
func (r *encodedMailboxRow) wipe()                     { clear(r[:]) }

func mailboxRecordHeader(record []byte) (kind byte, number uint32, err error) {
	if len(record) != mailbox.RecordSize || record[0] < 1 || record[0] > 3 {
		return 0, 0, errMailboxObservation
	}
	if record[0] == 3 {
		number = binary.BigEndian.Uint32(record[1:5])
	}
	return record[0], number, nil
}

func floorMailbox(n, d int64) int64 {
	q, r := n/d, n%d
	if r < 0 {
		q--
	}
	return q
}

func encodeMailboxFeatures(raw rawMailboxFeatures, periodNS int64) (encodedMailboxRow, error) {
	var out encodedMailboxRow
	if periodNS <= 0 || raw.RequestGapNS < 0 || raw.PutGapNS < 0 || raw.OtherFetchNS < 0 || raw.DeliverNS < 0 {
		return out, errMailboxClock
	}
	if !raw.HasPut && (raw.Kind != 0 || raw.RecordNumber != 0 || raw.Repeat || raw.PriorOtherFetch) || raw.HasPut && (raw.Kind < 1 || raw.Kind > 3) {
		return out, errMailboxObservation
	}
	set := func(i int, value bool) {
		if value {
			out[i] = 1
		}
	}
	set(0, raw.HasPut)
	out[1] = int16(raw.Kind)
	if raw.HasPut && raw.Kind == 3 {
		out[2] = int16(min(uint32(4095), raw.RecordNumber/256))
		if raw.PriorData {
			out[3] = int16(min(uint32(4095), raw.Delta/256))
		}
		set(4, raw.PriorData)
	}
	set(5, raw.Repeat)
	if raw.PriorRequest {
		out[6] = int16(min(int64(4095), raw.RequestGapNS/5_000_000))
		rem := raw.RequestGapNS % periodNS
		residual := rem
		if rem > periodNS-rem {
			residual -= periodNS
		}
		bucket := floorMailbox(residual, 1_000_000)
		if bucket < -4095 || bucket > 4095 {
			return encodedMailboxRow{}, errMailboxObservation
		}
		out[10] = int16(bucket)
	}
	set(7, raw.PriorRequest)
	if raw.PriorPut {
		out[8] = int16(min(int64(4095), raw.PutGapNS/5_000_000))
	}
	set(9, raw.PriorPut)
	switch raw.PreviousPutResult {
	case mailbox.PutNone:
	case mailbox.PutStored:
		out[11] = 1
	case mailbox.PutFull:
		out[12] = 1
	case mailbox.PutRefused:
		out[13] = 1
	case mailbox.StatusBad:
		out[14] = 1
	default:
		return encodedMailboxRow{}, errMailboxObservation
	}
	if raw.PriorOtherFetch {
		out[15] = int16(min(int64(30_000_000_000), raw.OtherFetchNS) / 10_000_000)
	}
	set(16, raw.PriorOtherFetch)
	out[17] = int16(min(int64(4095), raw.DeliverNS/10_000))
	return out, nil
}

type mailboxCircuitHistory struct {
	requestNS, putNS            int64
	hasRequest, hasPut, hasData bool
	number, recordAlias         uint32
	previousPutResult           byte
}

type mailboxExtractor struct {
	periodNS                   int64
	circuits                   map[uint32]mailboxCircuitHistory
	fetches                    mailboxFetchIndex
	prepared                   bool
	fetchEntries, observations int
}

func newMailboxExtractor(periodNS int64) *mailboxExtractor {
	return &mailboxExtractor{periodNS: periodNS, circuits: make(map[uint32]mailboxCircuitHistory, 128)}
}

func (x *mailboxExtractor) wipe() {
	if x == nil {
		return
	}
	x.fetches.wipe()
	x.fetches = nil
	clear(x.circuits)
	x.circuits = nil
	x.periodNS, x.fetchEntries, x.observations = 0, 0, 0
	x.prepared = false
}

func (x *mailboxExtractor) observe(o mailboxObservation) (encodedMailboxRow, error) {
	if x == nil || x.periodNS <= 0 || !o.Complete || o.Circuit == 0 || o.HasPut != (o.PutQueue != 0) || o.HasPut != (o.RecordAlias != 0) || !o.HasPut && (o.RecordKind != 0 || o.RecordNumber != 0) {
		return encodedMailboxRow{}, errMailboxObservation
	}
	if o.ReplyStatus&0x78 != 0 || o.ReplyStatus&mailbox.StatusBad != 0 && o.ReplyStatus != mailbox.StatusBad {
		return encodedMailboxRow{}, errMailboxObservation
	}
	if o.CallNS < 0 || o.ReturnNS < o.CallNS {
		return encodedMailboxRow{}, errMailboxClock
	}
	if x.observations >= 65536 || len(x.circuits) >= 128 && !mailboxHasCircuit(x.circuits, o.Circuit) {
		return encodedMailboxRow{}, errMailboxLimit
	}
	h := x.circuits[o.Circuit]
	if h.hasRequest && o.CallNS < h.requestNS {
		return encodedMailboxRow{}, errMailboxClock
	}
	raw := rawMailboxFeatures{HasPut: o.HasPut, Kind: o.RecordKind, RecordNumber: o.RecordNumber, PriorRequest: h.hasRequest, PriorPut: h.hasPut, PreviousPutResult: h.previousPutResult, DeliverNS: o.ReturnNS - o.CallNS}
	defer raw.wipe()
	if h.hasRequest {
		raw.RequestGapNS = o.CallNS - h.requestNS
	}
	if h.hasPut {
		raw.PutGapNS = o.CallNS - h.putNS
	}
	if o.HasPut {
		raw.Repeat = h.hasPut && o.RecordAlias == h.recordAlias
		if o.RecordKind == 3 && h.hasData {
			raw.PriorData, raw.Delta = true, o.RecordNumber-h.number
		}
		latest := x.fetches.latestOther(o.PutQueue, o.Circuit, o.CallNS)
		if latest >= 0 {
			raw.PriorOtherFetch, raw.OtherFetchNS = true, o.CallNS-latest
		}
	}
	row, err := encodeMailboxFeatures(raw, x.periodNS)
	defer row.wipe()
	if err != nil {
		return encodedMailboxRow{}, err
	}
	if o.FetchQueue != 0 {
		key := mailboxFetchKey{o.FetchQueue, o.Circuit}
		at, exists := x.fetches.find(key)
		if !exists || !x.fetches[at].initialized {
			if x.fetchEntries >= 65536 {
				return encodedMailboxRow{}, errMailboxLimit
			}
			if !exists {
				if x.prepared {
					return encodedMailboxRow{}, errMailboxObservation
				}
				x.fetches, at = x.fetches.insert(key)
			}
			x.fetchEntries++
		}
		fetch := &x.fetches[at]
		if !fetch.initialized {
			fetch.latest, fetch.initialized = o.CallNS, true
		} else if o.CallNS > fetch.latest {
			fetch.previous, fetch.hasPrevious, fetch.latest = fetch.latest, true, o.CallNS
		} else if o.CallNS < fetch.latest {
			return encodedMailboxRow{}, errMailboxClock
		}
	}
	h.requestNS, h.hasRequest = o.CallNS, true
	if o.HasPut {
		h.putNS, h.hasPut, h.recordAlias = o.CallNS, true, o.RecordAlias
		if o.RecordKind == 3 {
			h.number, h.hasData = o.RecordNumber, true
		}
		if o.ReplyStatus&mailbox.StatusBad != 0 {
			h.previousPutResult = mailbox.StatusBad
		} else {
			h.previousPutResult = o.ReplyStatus & mailbox.PutMask
		}
	}
	x.circuits[o.Circuit] = h
	x.observations++
	return row, nil
}

func mailboxHasCircuit(m map[uint32]mailboxCircuitHistory, c uint32) bool {
	_, exists := m[c]
	return exists
}

func extractMailboxRows(observations []mailboxObservation, periodNS int64) ([]encodedMailboxRow, error) {
	return extractMailboxRowsBudgeted(observations, periodNS, nil)
}

func extractMailboxRowsBudgeted(observations []mailboxObservation, periodNS int64, budget *memoryBudget) ([]encodedMailboxRow, error) {
	if len(observations) > 65536 {
		return nil, errMailboxLimit
	}
	if err := budget.checkAllocation(uint64(len(observations)) * uint64(unsafe.Sizeof(encodedMailboxRow{}))); err != nil {
		return nil, err
	}
	rows := make([]encodedMailboxRow, len(observations))
	if err := extractMailboxRowsIntoBudgeted(rows, observations, periodNS, budget); err != nil {
		return nil, err
	}
	return rows, nil
}

func extractMailboxRowsInto(rows []encodedMailboxRow, observations []mailboxObservation, periodNS int64) (err error) {
	return extractMailboxRowsIntoBudgeted(rows, observations, periodNS, nil)
}

func extractMailboxRowsIntoBudgeted(rows []encodedMailboxRow, observations []mailboxObservation, periodNS int64, budget *memoryBudget) (err error) {
	defer func() {
		if err != nil {
			clear(rows[:cap(rows)])
		}
	}()
	if len(rows) != len(observations) {
		return errMailboxObservation
	}
	if len(observations) > 65536 {
		return errMailboxLimit
	}
	if err := budget.checkAllocation(uint64(len(observations)) * uint64(unsafe.Sizeof(int(0)))); err != nil {
		return err
	}
	order := make([]int, len(observations))
	defer clear(order[:cap(order)])
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := observations[order[i]], observations[order[j]]
		if a.CallNS != b.CallNS {
			return a.CallNS < b.CallNS
		}
		return a.Order < b.Order
	})
	x, err := newPreparedMailboxExtractor(periodNS, observations, budget)
	if err != nil {
		return err
	}
	defer x.wipe()
	seenOrder, err := makeUint32Membership(len(observations), func(i int) uint32 { return observations[i].Order }, budget)
	if err != nil {
		return err
	}
	defer seenOrder.wipe()
	for _, i := range order {
		o := observations[i]
		if previous, found := seenOrder.mark(o.Order); !found || previous {
			return errMailboxObservation
		}
		row, observeErr := x.observe(o)
		if observeErr != nil {
			row.wipe()
			return observeErr
		}
		rows[i] = row
		row.wipe()
	}
	return nil
}

type MailboxPutBaseline struct {
	Positive      int      `json:"positive"`
	Negative      int      `json:"negative"`
	NegativeNoPut int      `json:"negative_no_put"`
	Unknown       int      `json:"unknown"`
	Q             *float64 `json:"q,omitempty"`
	AUC           *float64 `json:"auc,omitempty"`
	Reason        string   `json:"reason,omitempty"`
}

func mailboxPutBaseline(puts, truth, known []bool) MailboxPutBaseline {
	var out MailboxPutBaseline
	if len(puts) != len(truth) || len(known) != len(truth) {
		out.Reason = "label_mismatch"
		return out
	}
	scores := make([]metrics.Score, len(puts))
	defer clear(scores)
	for i := range puts {
		if !known[i] {
			out.Unknown++
			continue
		}
		if truth[i] {
			out.Positive++
		} else {
			out.Negative++
			if !puts[i] {
				out.NegativeNoPut++
			}
		}
		scores[i].True = truth[i]
		if puts[i] {
			scores[i].Value = 1
		}
	}
	if out.Unknown != 0 {
		out.Reason = "label_mismatch"
		return out
	}
	if out.Positive == 0 || out.Negative == 0 {
		out.Reason = "missing_class"
		return out
	}
	for i := range puts {
		if truth[i] && !puts[i] {
			out.Reason = "label_mismatch"
			return out
		}
	}
	q, auc := float64(out.NegativeNoPut)/float64(out.Negative), metrics.AUC(scores)
	if math.IsNaN(auc) || math.Abs(auc-(.5+q/2)) > 1e-15 {
		out.Reason = "label_mismatch"
		return out
	}
	out.Q, out.AUC = &q, &auc
	return out
}
