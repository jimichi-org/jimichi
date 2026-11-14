package nodeview

import (
	"encoding/json"
	"math"
	"slices"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

type encodedTrainingRow struct {
	Values       encodedMailboxRow
	Positive     bool
	Conversation uint16
	OriginalSeal bool
}

func (encodedTrainingRow) MarshalJSON() ([]byte, error) { return nil, errPrivateMailbox }
func (encodedTrainingRow) String() string               { return "nodeview: private" }
func (encodedTrainingRow) GoString() string             { return "nodeview: private" }
func (r *encodedTrainingRow) wipe()                     { *r = encodedTrainingRow{} }

type MailboxTrainingSupport struct {
	Rows                [2]int `json:"rows"`
	Conversations       [2]int `json:"conversations"`
	LargestConversation [2]int `json:"largest_conversation"`
	OriginalSeals       [2]int `json:"original_seals"`
	CompleteClean       bool   `json:"complete_clean"`
	LabelsJoined        bool   `json:"labels_joined"`
	RAMConformance      bool   `json:"ram_conformance"`
	Stable              bool   `json:"stable"`
}

type MailboxFitWitness struct {
	FeatureVersion string                                            `json:"feature_version"`
	Count          int                                               `json:"count"`
	ClassCount     [2]int                                            `json:"class_count"`
	ClassSum       [2][mailboxFeatureCount]int64                     `json:"class_sum"`
	Sum            [mailboxFeatureCount]int64                        `json:"sum"`
	Cross          [mailboxFeatureCount][mailboxFeatureCount]int64   `json:"cross"`
	Minimum        [mailboxFeatureCount]int16                        `json:"minimum"`
	Maximum        [mailboxFeatureCount]int16                        `json:"maximum"`
	Scatter        [mailboxFeatureCount][mailboxFeatureCount]float64 `json:"scatter"`
	Scale          [mailboxFeatureCount]float64                      `json:"scale"`
	Cholesky       [mailboxFeatureCount][mailboxFeatureCount]float64 `json:"cholesky"`
	Kept           []int                                             `json:"kept"`
	Unused         []int                                             `json:"unused"`
}

type MailboxTraining struct {
	FeatureVersion string                 `json:"feature_version"`
	Releasable     bool                   `json:"releasable"`
	Reason         string                 `json:"reason,omitempty"`
	Support        MailboxTrainingSupport `json:"support"`
	Model          *metrics.Discriminant  `json:"model,omitempty"`
	Witness        *MailboxFitWitness     `json:"witness,omitempty"`
}

func (t MailboxTraining) MarshalJSON() ([]byte, error) {
	if !validateMailboxTraining(t) {
		return nil, ErrRawSerialization
	}
	type released MailboxTraining
	return json.Marshal(released(t))
}

func validateMailboxTraining(t MailboxTraining) bool {
	if t.FeatureVersion != MailboxFeatureVersion {
		return false
	}
	for c := range 2 {
		if t.Support.Rows[c] < 0 || t.Support.Conversations[c] < 0 || t.Support.Conversations[c] > t.Support.Rows[c] || t.Support.LargestConversation[c] < 0 || t.Support.LargestConversation[c] > t.Support.Rows[c] || t.Support.OriginalSeals[c] < 0 || t.Support.OriginalSeals[c] > t.Support.Rows[c] {
			return false
		}
	}
	if !t.Releasable {
		if t.Model != nil || t.Witness != nil {
			return false
		}
		switch t.Reason {
		case "training_support", "observation_contract", "training_degenerate", "fit_conformance", "fit_audit_sensitive":
			return true
		default:
			return false
		}
	}
	if t.Reason != "" || t.Model == nil || t.Witness == nil || !t.Support.CompleteClean || !t.Support.LabelsJoined || !t.Support.RAMConformance || !t.Support.Stable {
		return false
	}
	w := t.Witness
	if w.FeatureVersion != MailboxFeatureVersion || w.Count != t.Support.Rows[0]+t.Support.Rows[1] || w.Count > 131072 || w.ClassCount != t.Support.Rows || len(t.Model.Weights) != mailboxFeatureCount || len(t.Model.Center) != mailboxFeatureCount || !slices.Equal(t.Model.Kept, w.Kept) || !slices.Equal(t.Model.Unused, w.Unused) {
		return false
	}
	for c := range 2 {
		if t.Support.Rows[c] < 64 || t.Support.Conversations[c] < 4 || 2*t.Support.LargestConversation[c] > t.Support.Rows[c] {
			return false
		}
	}
	for i := range mailboxFeatureCount {
		if w.Minimum[i] < -4095 || w.Maximum[i] > 4095 || w.Minimum[i] > w.Maximum[i] || w.Sum[i] != w.ClassSum[0][i]+w.ClassSum[1][i] || w.Sum[i] < int64(w.Minimum[i])*int64(w.Count) || w.Sum[i] > int64(w.Maximum[i])*int64(w.Count) || math.IsNaN(w.Scale[i]) || math.IsInf(w.Scale[i], 0) {
			return false
		}
		for c := range 2 {
			if w.ClassSum[c][i] < -4095*int64(w.ClassCount[c]) || w.ClassSum[c][i] > 4095*int64(w.ClassCount[c]) {
				return false
			}
		}
		for j := range mailboxFeatureCount {
			if w.Cross[i][j] != w.Cross[j][i] || w.Cross[i][j] < -4095*4095*int64(w.Count) || w.Cross[i][j] > 4095*4095*int64(w.Count) || math.IsNaN(w.Scatter[i][j]) || math.IsInf(w.Scatter[i][j], 0) || math.IsNaN(w.Cholesky[i][j]) || math.IsInf(w.Cholesky[i][j], 0) {
				return false
			}
		}
	}
	return t.Model.Scores([][]float64{make([]float64, mailboxFeatureCount)}) != nil
}

func validEncodedMailboxRow(row encodedMailboxRow) bool {
	for j, v := range row {
		switch j {
		case 0, 4, 5, 7, 9, 11, 12, 13, 14, 16:
			if v < 0 || v > 1 {
				return false
			}
		case 1:
			if v < 0 || v > 3 {
				return false
			}
		case 10:
			if v < -4095 || v > 4095 {
				return false
			}
		case 15:
			if v < 0 || v > 3000 {
				return false
			}
		default:
			if v < 0 || v > 4095 {
				return false
			}
		}
	}
	if row[0] == 0 && (row[1] != 0 || row[2] != 0 || row[3] != 0 || row[4] != 0 || row[5] != 0 || row[15] != 0 || row[16] != 0) {
		return false
	}
	if row[0] != 0 && row[1] == 0 {
		return false
	}
	if row[1] != 3 && (row[2] != 0 || row[3] != 0 || row[4] != 0) {
		return false
	}
	if row[4] == 0 && row[3] != 0 || row[7] == 0 && (row[6] != 0 || row[10] != 0) || row[9] == 0 && row[8] != 0 || row[16] == 0 && row[15] != 0 {
		return false
	}
	return row[11]+row[12]+row[13]+row[14] <= 1
}

type mailboxReplayWork struct{ y, v []float64 }

func (w *mailboxReplayWork) close() {
	clear(w.y[:cap(w.y)])
	clear(w.v[:cap(w.v)])
	w.y, w.v = nil, nil
}

type mailboxFitOwner struct {
	replayWork                    mailboxReplayWork
	histogram                     *[2][1 << 16]uint32
	train                         [][]float64
	truth                         []bool
	backing                       []float64
	model, replayed               metrics.Discriminant
	witness                       *MailboxFitWitness
	scores                        [2][]float64
	output                        MailboxTraining
	stable, replayOK, transferred bool
}

func (o *mailboxFitOwner) close() {
	if o == nil {
		return
	}
	if o.histogram != nil {
		clear(o.histogram[0][:])
		clear(o.histogram[1][:])
		o.histogram = nil
	}
	clear(o.backing[:cap(o.backing)])
	clear(o.truth[:cap(o.truth)])
	clear(o.train[:cap(o.train)])
	for i := range o.scores {
		clear(o.scores[i][:cap(o.scores[i])])
		o.scores[i] = nil
	}
	o.replayWork.close()
	wipeMailboxModel(&o.replayed)
	if !o.transferred {
		wipeMailboxModel(&o.model)
		wipeMailboxWitness(o.witness)
	}
	o.train, o.truth, o.backing, o.witness = nil, nil, nil, nil
	o.output = MailboxTraining{}
	o.stable, o.replayOK = false, false
}

func trainMailbox(rows []encodedTrainingRow, featureVersion string, completeClean, labelsJoined bool, s *fitCertificateScratch) MailboxTraining {
	owner := mailboxFitOwner{}
	defer owner.close()
	prepareMailboxTraining(&owner, rows, featureVersion, completeClean, labelsJoined, s)
	return finalizeMailboxTraining(&owner)
}

func prepareMailboxTraining(o *mailboxFitOwner, rows []encodedTrainingRow, featureVersion string, completeClean, labelsJoined bool, s *fitCertificateScratch) {
	o.output = MailboxTraining{FeatureVersion: MailboxFeatureVersion, Support: MailboxTrainingSupport{CompleteClean: completeClean, LabelsJoined: labelsJoined}}
	fail := func(reason string) { o.output.Reason = reason }
	if !s.reset() {
		fail("fit_conformance")
		return
	}
	if featureVersion != MailboxFeatureVersion || len(rows) > 131072 {
		fail("training_support")
		return
	}
	o.histogram = new([2][1 << 16]uint32)
	conversations := o.histogram
	for _, row := range rows {
		if !validEncodedMailboxRow(row.Values) {
			fail("observation_contract")
			return
		}
		class := 0
		if row.Positive {
			class = 1
		}
		o.output.Support.Rows[class]++
		conversations[class][row.Conversation]++
		if row.OriginalSeal {
			o.output.Support.OriginalSeals[class]++
		}
	}
	for c := range 2 {
		for i := range conversations[c] {
			n := conversations[c][i]
			if n != 0 {
				o.output.Support.Conversations[c]++
			}
			o.output.Support.LargestConversation[c] = max(o.output.Support.LargestConversation[c], int(n))
		}
	}
	if !completeClean || !labelsJoined || len(rows) == 0 {
		fail("training_support")
		return
	}
	for c := range 2 {
		if o.output.Support.Rows[c] < 64 || o.output.Support.Conversations[c] < 4 || 2*o.output.Support.LargestConversation[c] > o.output.Support.Rows[c] {
			fail("training_support")
			return
		}
	}
	o.train = make([][]float64, len(rows))
	o.truth = make([]bool, len(rows))
	o.backing = make([]float64, len(rows)*mailboxFeatureCount)
	train, truth, backing := o.train, o.truth, o.backing
	for i, row := range rows {
		train[i] = backing[i*mailboxFeatureCount : (i+1)*mailboxFeatureCount]
		for j, v := range row.Values {
			train[i][j] = float64(v)
		}
		truth[i] = row.Positive
	}
	var ok bool
	o.model, ok = metrics.FitDiscriminant(o.train, o.truth)
	if !ok {
		o.output.Reason = "training_degenerate"
		return
	}
	witness := mailboxMoments(rows)
	o.witness = &witness
	o.replayed, o.stable, o.replayOK = checkMailboxFitWork(o.train, o.truth, o.witness, s, &o.replayWork)
	if !o.replayOK || !sameMailboxModel(o.model, o.replayed) {
		o.output.Reason = "fit_conformance"
		return
	}
	o.scores[0] = o.model.Scores(o.train)
	o.scores[1] = o.replayed.Scores(o.train)
}

func finalizeMailboxTraining(o *mailboxFitOwner) MailboxTraining {
	defer o.close()
	out := o.output
	if out.Reason != "" {
		return out
	}
	if !o.replayOK || !sameMailboxModel(o.model, o.replayed) || len(o.scores[0]) != len(o.train) || len(o.scores[1]) != len(o.train) {
		out.Reason = "fit_conformance"
		return out
	}
	for i := range o.scores[0] {
		if math.Float64bits(o.scores[0][i]) != math.Float64bits(o.scores[1][i]) {
			out.Reason = "fit_conformance"
			return out
		}
	}
	out.Support.RAMConformance = true
	if !o.stable {
		out.Reason = "fit_audit_sensitive"
		return out
	}
	out.Support.Stable, out.Releasable = true, true
	out.Model, out.Witness = &o.model, o.witness
	o.transferred = true
	return out
}

func mailboxMoments(rows []encodedTrainingRow) MailboxFitWitness {
	w := MailboxFitWitness{FeatureVersion: MailboxFeatureVersion, Count: len(rows)}
	if len(rows) == 0 {
		return w
	}
	w.Minimum, w.Maximum = rows[0].Values, rows[0].Values
	for _, row := range rows {
		c := 0
		if row.Positive {
			c = 1
		}
		w.ClassCount[c]++
		for i, v := range row.Values {
			x := int64(v)
			w.Minimum[i], w.Maximum[i] = min(w.Minimum[i], v), max(w.Maximum[i], v)
			w.Sum[i] += x
			w.ClassSum[c][i] += x
			for j, vj := range row.Values {
				w.Cross[i][j] += x * int64(vj)
			}
		}
	}
	return w
}

func mailboxSame(a, b float64) bool {
	if a == b {
		return true
	}
	if math.IsInf(a, 0) || math.IsInf(b, 0) {
		return false
	}
	return math.Abs(a-b) <= 1e-9*math.Max(math.Abs(a), math.Abs(b))
}

func sameMailboxModel(a, b metrics.Discriminant) bool {
	if !slices.Equal(a.Kept, b.Kept) || !slices.Equal(a.Unused, b.Unused) || math.Float64bits(a.Normalizer) != math.Float64bits(b.Normalizer) || len(a.Weights) != len(b.Weights) || len(a.Center) != len(b.Center) {
		return false
	}
	for j := range a.Weights {
		if math.Float64bits(a.Weights[j]) != math.Float64bits(b.Weights[j]) || math.Float64bits(a.Center[j]) != math.Float64bits(b.Center[j]) {
			return false
		}
	}
	return true
}

func wipeMailboxModel(m *metrics.Discriminant) {
	if m == nil {
		return
	}
	clear(m.Weights[:cap(m.Weights)])
	clear(m.Center[:cap(m.Center)])
	clear(m.Kept[:cap(m.Kept)])
	clear(m.Unused[:cap(m.Unused)])
	*m = metrics.Discriminant{}
}

func wipeMailboxWitness(w *MailboxFitWitness) {
	if w == nil {
		return
	}
	clear(w.Kept[:cap(w.Kept)])
	clear(w.Unused[:cap(w.Unused)])
	*w = MailboxFitWitness{}
}

func wipeMailboxTraining(t *MailboxTraining) {
	if t == nil {
		return
	}
	wipeMailboxModel(t.Model)
	wipeMailboxWitness(t.Witness)
	*t = MailboxTraining{}
}

func checkMailboxFit(train [][]float64, truth []bool, witness *MailboxFitWitness, s *fitCertificateScratch) (metrics.Discriminant, bool, bool) {
	work := mailboxReplayWork{}
	defer work.close()
	return checkMailboxFitWork(train, truth, witness, s, &work)
}

func checkMailboxFitWork(train [][]float64, truth []bool, witness *MailboxFitWitness, s *fitCertificateScratch, work *mailboxReplayWork) (result metrics.Discriminant, stable, ok bool) {
	const width = mailboxFeatureCount
	if !fitReady(s) || s.flags[2] != 1 || s.flags[3] != 0 {
		return
	}
	defer func() {
		s.flags[3] = 0
		if !ok {
			wipeMailboxModel(&result)
		}
	}()
	if !prepareMailboxFacts(train, truth, witness, s) {
		return
	}
	for i := range width {
		if witness.Scale[i] != 0 {
			return
		}
		for j := range width {
			if witness.Scatter[i][j] != 0 || witness.Cholesky[i][j] != 0 {
				return
			}
		}
	}
	if len(witness.Kept) != 0 || len(witness.Unused) != 0 {
		return
	}
	var varying [width]bool
	for j := range width {
		varying[j] = witness.Minimum[j] != witness.Maximum[j]
	}
	for _, row := range train {
		for i := range width {
			if !varying[i] {
				continue
			}
			di := row[i] - s.means[0][i]
			for j := range i + 1 {
				if varying[j] {
					witness.Scatter[i][j] += di * (row[j] - s.means[0][j])
				}
			}
		}
	}
	for j := range width {
		if !varying[j] {
			continue
		}
		witness.Scale[j] = math.Sqrt(witness.Scatter[j][j])
		if !(witness.Scatter[j][j] >= 0x1p-1022) || math.IsInf(witness.Scale[j], 0) {
			return
		}
	}
	var kept []int
	defer func() {
		if !ok {
			clear(kept[:cap(kept)])
		}
	}()
	for i := range width {
		if !varying[i] {
			continue
		}
		pivot := witness.Scatter[i][i] / witness.Scale[i] / witness.Scale[i]
		for p, j := range kept {
			c := witness.Scatter[i][j] / witness.Scale[i] / witness.Scale[j]
			for r := range p {
				c -= witness.Cholesky[i][r] * witness.Cholesky[j][r]
			}
			witness.Cholesky[i][p] = c / witness.Cholesky[j][p]
			pivot -= witness.Cholesky[i][p] * witness.Cholesky[i][p]
		}
		if pivot <= 1e-9 {
			continue
		}
		witness.Cholesky[i][len(kept)] = math.Sqrt(pivot)
		previous := kept
		kept = append(kept, i)
		if cap(previous) != cap(kept) {
			clear(previous[:cap(previous)])
		}
	}
	if !slices.ContainsFunc(kept, func(j int) bool { return !mailboxSame(s.means[2][j], s.means[1][j]) }) {
		return
	}
	work.y = make([]float64, len(kept))
	y := work.y
	for p, j := range kept {
		v := (s.means[2][j] - s.means[1][j]) / witness.Scale[j]
		for r := range p {
			v -= witness.Cholesky[j][r] * y[r]
		}
		y[p] = v / witness.Cholesky[j][p]
	}
	result.Weights, result.Center = make([]float64, width), make([]float64, width)
	work.v = make([]float64, len(kept))
	v := work.v
	for p := len(kept) - 1; p >= 0; p-- {
		j := kept[p]
		x := y[p]
		for r := p + 1; r < len(kept); r++ {
			x -= witness.Cholesky[kept[r]][p] * v[r]
		}
		v[p] = x / witness.Cholesky[j][p]
		result.Weights[j] = v[p] / witness.Scale[j]
	}
	wd := 0.0
	for _, x := range y {
		wd += x * x
	}
	if !(wd > 0) || math.IsInf(wd, 0) {
		return
	}
	for j := range width {
		result.Center[j] = (s.means[2][j] + s.means[1][j]) / 2
		if !slices.Contains(kept, j) {
			previous := witness.Unused
			witness.Unused = append(witness.Unused, j)
			if cap(previous) != cap(witness.Unused) {
				clear(previous[:cap(previous)])
			}
		}
	}
	witness.Kept = slices.Clone(kept)
	for i := range width {
		for j := range i {
			witness.Scatter[j][i] = witness.Scatter[i][j]
		}
	}
	result.Normalizer, result.Kept, result.Unused = wd, kept, slices.Clone(witness.Unused)
	status := certifyMailboxFit(train, truth, witness, s)
	if status == fitProofInvalid {
		return result, false, false
	}
	return result, status == fitProofStable, true
}
