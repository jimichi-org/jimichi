package nodeview

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func mailboxTrainingFixture() []encodedTrainingRow {
	rows := make([]encodedTrainingRow, 128)
	for i := range rows {
		rows[i].Conversation = uint16(i % 4)
		rows[i].OriginalSeal = true
		if i >= 64 {
			rows[i].Positive = true
			rows[i].Values[0] = 1
			rows[i].Values[1] = 3
		}
	}
	return rows
}

func TestMailboxTrainingReleaseKnownAnswer(t *testing.T) {
	// 64 zeros and 64 ones have mean 1/2, scatter 32, d=1, w=1/32 and normalizer=1/32
	out := trainMailbox(mailboxTrainingFixture(), MailboxFeatureVersion, true, true)
	if !out.Releasable || out.Model == nil || out.Witness == nil || out.Reason != "" || !out.Support.RAMConformance || !out.Support.Stable {
		t.Fatalf("release failed: %s", out.Reason)
	}
	w := out.Witness
	if w.Count != 128 || w.ClassCount != [2]int{64, 64} || w.Sum[0] != 64 || w.Cross[0][0] != 64 || w.Minimum[0] != 0 || w.Maximum[0] != 1 || w.Scatter[0][0] != 32 {
		t.Fatal("encoded witness changed")
	}
	if len(w.Kept) != 1 || w.Kept[0] != 0 || len(w.Unused) != 17 {
		t.Fatal("column predicates changed")
	}
	scores := out.Model.Scores([][]float64{make([]float64, 18), {1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}})
	if len(scores) != 2 || math.Abs(scores[0]+.5) > 1e-15 || math.Abs(scores[1]-.5) > 1e-15 {
		t.Fatal("frozen orientation changed")
	}
	b, err := json.Marshal(out)
	if err != nil || !strings.Contains(string(b), "class_sum") || strings.Contains(string(b), "Conversation") {
		t.Fatal("release witness schema changed")
	}
}

func TestMailboxTrainingSuppressesSparseAndPartial(t *testing.T) {
	cases := []struct {
		rows          []encodedTrainingRow
		version       string
		clean, joined bool
	}{
		{mailboxTrainingFixture()[:1], MailboxFeatureVersion, true, true},
		{mailboxTrainingFixture(), MailboxFeatureVersion, false, true},
		{mailboxTrainingFixture(), MailboxFeatureVersion, true, false},
		{mailboxTrainingFixture(), "raw-v1", true, true},
	}
	three := mailboxTrainingFixture()
	for i := range three {
		three[i].Conversation = uint16(i % 3)
	}
	cases = append(cases, struct {
		rows          []encodedTrainingRow
		version       string
		clean, joined bool
	}{three, MailboxFeatureVersion, true, true})
	dominant := mailboxTrainingFixture()
	for i := range 33 {
		dominant[i].Conversation = 42
	}
	cases = append(cases, struct {
		rows          []encodedTrainingRow
		version       string
		clean, joined bool
	}{dominant, MailboxFeatureVersion, true, true})
	for _, c := range cases {
		out := trainMailbox(c.rows, c.version, c.clean, c.joined)
		if out.Releasable || out.Model != nil || out.Witness != nil || out.Reason == "" {
			t.Fatal("sparse or partial model released")
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"weights", "Weights", "class_sum", "cross", "minimum", "maximum", "digest"} {
			if strings.Contains(string(b), field) {
				t.Fatal("suppressed model disclosed fitting material")
			}
		}
	}
}

func TestMailboxEncodedMomentsDoNotReplaceExtrema(t *testing.T) {
	// [0,0,3,3] and [0,1,1,4] both sum to 6, sum squares to 18 and scatter to 9
	a, b := make([]encodedTrainingRow, 4), make([]encodedTrainingRow, 4)
	for i, v := range []int16{0, 0, 3, 3} {
		a[i].Values[17] = v
	}
	for i, v := range []int16{0, 1, 1, 4} {
		b[i].Values[17] = v
	}
	x, y := mailboxMoments(a), mailboxMoments(b)
	if x.Sum != y.Sum || x.Cross != y.Cross || x.Minimum[17] != 0 || y.Minimum[17] != 0 || x.Maximum[17] != 3 || y.Maximum[17] != 4 {
		t.Fatal("extrema were inferred from moments")
	}
	// at C=3e9 the range 3 satisfies relative tolerance, whereas range 4 does not
	if !mailboxSame(3e9, 3e9+3) || mailboxSame(3e9, 3e9+4) {
		t.Fatal("generic varying counterexample changed")
	}
	for lo := int16(-4095); lo < 4095; lo++ {
		if mailboxSame(float64(lo), float64(lo+1)) {
			t.Fatal("distinct encoded integers treated as constant")
		}
	}
}

func TestMailboxFitMomentsIndependentReplay(t *testing.T) {
	rows := mailboxTrainingFixture()
	for i := range rows {
		rows[i].Values[17] = int16(i % 7)
		if rows[i].Positive {
			rows[i].Values[17] += 2
		}
	}
	out := trainMailbox(rows, MailboxFeatureVersion, true, true)
	if !out.Releasable || !out.Support.RAMConformance {
		t.Fatalf("independent replay failed: %s", out.Reason)
	}
	w := out.Witness
	for i := range 18 {
		for j := range i + 1 {
			if w.Minimum[i] == w.Maximum[i] || w.Minimum[j] == w.Maximum[j] {
				continue
			}
			exact := exactMailboxScatter(w.Sum[i], w.Sum[j], w.Cross[i][j], w.Count)
			if math.Abs(exact-w.Scatter[i][j]) > 1e-9 {
				t.Fatal("scatter disagrees with integer moments")
			}
		}
	}
}
