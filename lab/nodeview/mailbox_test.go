package nodeview

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/jimichi-org/jimichi/mailbox"
)

func TestMailboxEncodingKnownAnswers(t *testing.T) {
	// 91/256 and 92/256 are zero; 12ms/5ms and 13ms/5ms are two
	for _, number := range []uint32{91, 92} {
		for _, gap := range []int64{12_000_000, 13_000_000} {
			raw := rawMailboxFeatures{HasPut: true, Kind: 3, RecordNumber: number, PriorRequest: true, RequestGapNS: gap, DeliverNS: 11_000}
			row, err := encodeMailboxFeatures(raw, 35_000_000)
			if err != nil || row[2] != 0 || row[6] != 2 || row[17] != 1 {
				t.Fatal("coarse categories changed")
			}
		}
	}
	// nearest 35ms leaves -1ns, and mathematical floor(-1ns/1ms) is -1
	row, err := encodeMailboxFeatures(rawMailboxFeatures{PriorRequest: true, RequestGapNS: 34_999_999, DeliverNS: 19_000}, 35_000_000)
	if err != nil || row[10] != -1 || row[17] != 1 {
		t.Fatal("negative residual did not use floor")
	}
	// the 17.5ms tie chooses the lower multiple zero, leaving positive 17.5ms
	row, err = encodeMailboxFeatures(rawMailboxFeatures{PriorRequest: true, RequestGapNS: 17_500_000}, 35_000_000)
	if err != nil || row[10] != 17 {
		t.Fatal("nearest-period tie changed")
	}
	// absent and measured zero gaps share category zero but have different presence bits
	absent, _ := encodeMailboxFeatures(rawMailboxFeatures{}, 35_000_000)
	zero, _ := encodeMailboxFeatures(rawMailboxFeatures{PriorRequest: true, PriorPut: true, HasPut: true, Kind: 3, PriorOtherFetch: true}, 35_000_000)
	if absent[6] != zero[6] || absent[7] != 0 || zero[7] != 1 || zero[9] != 1 || zero[16] != 1 {
		t.Fatal("missing categories collapsed")
	}
	// saturation caps the uint32 buckets and duration buckets, and clips queue gaps at 30s
	row, err = encodeMailboxFeatures(rawMailboxFeatures{HasPut: true, Kind: 3, RecordNumber: math.MaxUint32, Delta: math.MaxUint32, PriorData: true, PriorRequest: true, RequestGapNS: math.MaxInt64, PriorPut: true, PutGapNS: math.MaxInt64, PriorOtherFetch: true, OtherFetchNS: math.MaxInt64, DeliverNS: math.MaxInt64}, 35_000_000)
	if err != nil || row[2] != 4095 || row[3] != 4095 || row[6] != 4095 || row[8] != 4095 || row[15] != 3000 || row[17] != 4095 {
		t.Fatal("saturation changed")
	}
	for _, raw := range []rawMailboxFeatures{{DeliverNS: -1}, {RequestGapNS: -1}, {PutGapNS: -1}, {OtherFetchNS: -1}} {
		if _, err := encodeMailboxFeatures(raw, 35_000_000); !errors.Is(err, errMailboxClock) {
			t.Fatal("negative time accepted")
		}
	}
}

func TestMailboxExtractorKnownAnswers(t *testing.T) {
	x := newMailboxExtractor(35_000_000)
	defer x.wipe()
	first := mailboxObservation{Circuit: 1, Order: 1, CallNS: 10_000_000, ReturnNS: 10_019_000, Complete: true, FetchQueue: 9}
	row, err := x.observe(first)
	if err != nil || row[7] != 0 || row[17] != 1 {
		t.Fatal("first request changed")
	}
	put := mailboxObservation{Circuit: 2, Order: 2, CallNS: 20_000_000, ReturnNS: 20_011_000, Complete: true, HasPut: true, PutQueue: 9, RecordAlias: 1, RecordKind: 3, RecordNumber: math.MaxUint32, ReplyStatus: mailbox.PutStored}
	row, err = x.observe(put)
	if err != nil || row[16] != 1 || row[15] != 1 || row[4] != 0 {
		t.Fatal("other-circuit fetch missing")
	}
	put.Order++
	put.CallNS += 35_000_000
	put.ReturnNS += 35_000_000
	put.RecordNumber = 0
	put.RecordAlias = 2
	put.ReplyStatus = mailbox.PutFull
	row, err = x.observe(put)
	// uint32(0 - (2^32-1)) is one, so its coarse delta is zero with prior-data present
	if err != nil || row[3] != 0 || row[4] != 1 || row[7] != 1 || row[6] != 7 || row[11] != 1 || row[12] != 0 {
		t.Fatal("prior record or status changed")
	}
	put.Order++
	put.CallNS += 35_000_000
	put.ReturnNS += 35_000_000
	row, err = x.observe(put)
	if err != nil || row[5] != 1 || row[12] != 1 {
		t.Fatal("sticky equality lost")
	}
	if _, err = x.observe(mailboxObservation{Circuit: 3, Complete: false}); !errors.Is(err, errMailboxObservation) {
		t.Fatal("incomplete duration accepted")
	}
}

func TestMailboxBatchPreservesAllFeatureColumnsAndInputOrder(t *testing.T) {
	observations := []mailboxObservation{
		{Circuit: 1, Order: 17, CallNS: 10_000_000, ReturnNS: 10_000_000, Complete: true, FetchQueue: 9},
		{Circuit: 2, Order: 0, CallNS: 20_000_000, ReturnNS: 20_000_000, Complete: true, HasPut: true, PutQueue: 9, RecordAlias: math.MaxUint32, RecordKind: 3, RecordNumber: 256, ReplyStatus: mailbox.PutStored},
		{Circuit: 1, Order: math.MaxUint32, CallNS: 30_000_000, ReturnNS: 30_000_000, Complete: true, FetchQueue: 9},
		{Circuit: 2, Order: 18, CallNS: 55_000_000, ReturnNS: 55_000_000, Complete: true, HasPut: true, PutQueue: 9, FetchQueue: math.MaxUint32, RecordAlias: 8, RecordKind: 3, RecordNumber: 512, ReplyStatus: mailbox.PutFull},
		{Circuit: 2, Order: 19, CallNS: 90_000_000, ReturnNS: 90_000_000, Complete: true, HasPut: true, PutQueue: 9, FetchQueue: math.MaxUint32, RecordAlias: 8, RecordKind: 3, RecordNumber: 512},
	}
	// 35ms gaps give seven 5ms buckets; the 20ms gap leaves a -15ms residual
	want := []encodedMailboxRow{
		{},
		{1, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0},
		{0, 0, 0, 0, 0, 0, 4, 1, 0, 0, -15, 0, 0, 0, 0, 0, 0, 0},
		{1, 3, 2, 1, 1, 0, 7, 1, 7, 1, 0, 1, 0, 0, 0, 2, 1, 0},
		{1, 3, 2, 0, 1, 1, 7, 1, 7, 1, 0, 0, 1, 0, 0, 6, 1, 0},
	}
	x := newMailboxExtractor(35_000_000)
	defer x.wipe()
	for i, o := range observations {
		row, err := x.observe(o)
		if err != nil || row != want[i] {
			t.Fatalf("standalone feature row %d changed", i)
		}
		row.wipe()
	}
	input := []mailboxObservation{observations[4], observations[0], observations[3], observations[2], observations[1]}
	before := slices.Clone(input)
	rows, err := extractMailboxRows(input, 35_000_000)
	if err != nil || !slices.Equal(rows, []encodedMailboxRow{want[4], want[0], want[3], want[2], want[1]}) || !slices.Equal(input, before) {
		t.Fatal("prepared extraction changed the full feature vector or original destination order")
	}
	clear(rows)
	clear(want)
}

func TestMailboxExtractionOrderAndLimits(t *testing.T) {
	observations := []mailboxObservation{{Circuit: 1, Order: 1, CallNS: 0, ReturnNS: 0, Complete: true}, {Circuit: 1, Order: 2, CallNS: 35_000_000, ReturnNS: 35_000_000, Complete: true}}
	a, err := extractMailboxRows(observations, 35_000_000)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(observations)
	b, err := extractMailboxRows(observations, 35_000_000)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(b)
	if !slices.Equal(a, b) {
		t.Fatal("array order changed features")
	}
	observations[1].Order = observations[0].Order
	if _, err = extractMailboxRows(observations, 35_000_000); !errors.Is(err, errMailboxObservation) {
		t.Fatal("duplicate callback generation accepted")
	}
	x := newMailboxExtractor(35_000_000)
	defer x.wipe()
	x.observations = 65535
	if _, err = x.observe(mailboxObservation{Circuit: 1, Complete: true}); err != nil {
		t.Fatal("cap record rejected")
	}
	if _, err = x.observe(mailboxObservation{Circuit: 1, Complete: true}); !errors.Is(err, errMailboxLimit) {
		t.Fatal("overflow accepted")
	}
}

func TestMailboxSameTimestampFetchPreservesEarlierFetch(t *testing.T) {
	x := newMailboxExtractor(35_000_000)
	defer x.wipe()
	for _, when := range []int64{10_000_000, 20_000_000, 20_000_000} {
		if _, err := x.observe(mailboxObservation{Circuit: 1, Complete: true, CallNS: when, ReturnNS: when, FetchQueue: 9}); err != nil {
			t.Fatal(err)
		}
	}
	row, err := x.observe(mailboxObservation{Circuit: 2, Complete: true, CallNS: 20_000_000, ReturnNS: 20_000_000, HasPut: true, PutQueue: 9, RecordAlias: 1, RecordKind: 3})
	// the simultaneous fetch is not earlier; the prior 10ms fetch still gives a 10ms gap
	if err != nil || row[16] != 1 || row[15] != 1 {
		t.Fatal("equal-time fetch hid an earlier fetch")
	}
}

func TestMailboxExtractionErasesFullBackingOnFailure(t *testing.T) {
	first := mailboxObservation{Circuit: 1, Order: 1, Complete: true, CallNS: 10_000_000, ReturnNS: 10_010_000, HasPut: true, PutQueue: 9, RecordAlias: 1, RecordKind: 3, RecordNumber: 12345}
	for _, failure := range []string{"duplicate-order", "clock", "row-count"} {
		t.Run(failure, func(t *testing.T) {
			second := first
			second.Order, second.CallNS, second.ReturnNS = 2, 20_000_000, 20_010_000
			observations := []mailboxObservation{first, second}
			rows := make([]encodedMailboxRow, 2, 5)
			for i := range rows[:cap(rows)] {
				for j := range rows[:cap(rows)][i] {
					rows[:cap(rows)][i][j] = 123
				}
			}
			switch failure {
			case "duplicate-order":
				observations[1].Order = first.Order
			case "clock":
				observations[1].ReturnNS = observations[1].CallNS - 1
			case "row-count":
				rows = rows[:1]
			}
			before := append([]mailboxObservation(nil), observations...)
			if err := extractMailboxRowsInto(rows, observations, 35_000_000); err == nil {
				t.Fatal("invalid extraction accepted")
			}
			for _, row := range rows[:cap(rows)] {
				if row != (encodedMailboxRow{}) {
					t.Fatal("failed extraction retained an encoded row")
				}
			}
			if !slices.Equal(observations, before) {
				t.Fatal("extraction mutated observations")
			}
			if failure != "row-count" {
				if returned, err := extractMailboxRows(observations, 35_000_000); err == nil || returned != nil {
					t.Fatal("failed wrapper returned partial rows")
				}
			}
		})
	}
}

func TestMailboxExtractionKeepsSuccessfulRows(t *testing.T) {
	observations := []mailboxObservation{{Circuit: 1, Order: 1, Complete: true, CallNS: 10_000_000, ReturnNS: 10_010_000, HasPut: true, PutQueue: 9, RecordAlias: 1, RecordKind: 3, RecordNumber: 12345}}
	rows, err := extractMailboxRows(observations, 35_000_000)
	if err != nil || len(rows) != 1 || rows[0][0] != 1 || rows[0][1] != 3 || rows[0][2] != 48 {
		t.Fatal("successful extraction erased or changed its result")
	}
	for i := range rows {
		rows[i].wipe()
	}
}

func TestMailboxHeaderAndPrivateTypes(t *testing.T) {
	record := make([]byte, 392)
	record[0] = 3
	binary.BigEndian.PutUint32(record[1:5], 123456789)
	kind, number, err := mailboxRecordHeader(record)
	if err != nil || kind != 3 || number != 123456789 {
		t.Fatal("public record header changed")
	}
	if _, _, err = mailboxRecordHeader(record[:391]); err == nil {
		t.Fatal("short record accepted")
	}
	record[0] = 0
	if _, _, err = mailboxRecordHeader(record); err == nil {
		t.Fatal("invalid kind accepted")
	}
	for _, raw := range []any{mailboxObservation{RecordNumber: 123456789}, rawMailboxFeatures{RecordNumber: 123456789}, encodedMailboxRow{91}, encodedTrainingRow{}} {
		if _, err := json.Marshal(raw); err == nil {
			t.Fatal("private row serialized")
		}
		if strings.Contains(fmt.Sprintf("%v %#v", raw, raw), "123456789") {
			t.Fatal("private row formatted")
		}
	}
}

func TestMailboxPutBaselineKnownAnswers(t *testing.T) {
	// two negatives include one no-put: q=1/2, and two wins plus two ties give AUC=3/4
	puts, truth := []bool{true, true, true, false}, []bool{true, false, true, false}
	out := mailboxPutBaseline(puts, truth, []bool{true, true, true, true})
	if out.Reason != "" || out.Q == nil || *out.Q != .5 || out.AUC == nil || *out.AUC != .75 {
		t.Fatal("put baseline changed")
	}
	puts[3] = true
	out = mailboxPutBaseline(puts, truth, []bool{true, true, true, true})
	if out.AUC == nil || *out.AUC != .5 {
		t.Fatal("all-put baseline changed")
	}
	out = mailboxPutBaseline(puts, truth, []bool{true, false, true, true})
	if out.Q != nil || out.AUC != nil || out.Reason != "label_mismatch" {
		t.Fatal("unknown label became negative")
	}
	if out.Negative != 1 || out.Unknown != 1 {
		t.Fatal("unknown truth entered the negative denominator")
	}
}
