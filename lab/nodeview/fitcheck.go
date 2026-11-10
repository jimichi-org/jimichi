package nodeview

import (
	"encoding/json"
	"math"
	"math/big"
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

func trainMailbox(rows []encodedTrainingRow, featureVersion string, completeClean, labelsJoined bool) MailboxTraining {
	out := MailboxTraining{FeatureVersion: MailboxFeatureVersion, Support: MailboxTrainingSupport{CompleteClean: completeClean, LabelsJoined: labelsJoined}}
	fail := func(reason string) MailboxTraining { out.Reason = reason; return out }
	if featureVersion != MailboxFeatureVersion || len(rows) > 131072 {
		return fail("training_support")
	}
	conversations := new([2][1 << 16]uint32)
	defer clear(conversations[0][:])
	defer clear(conversations[1][:])
	for _, row := range rows {
		if !validEncodedMailboxRow(row.Values) {
			return fail("observation_contract")
		}
		class := 0
		if row.Positive {
			class = 1
		}
		out.Support.Rows[class]++
		conversations[class][row.Conversation]++
		if row.OriginalSeal {
			out.Support.OriginalSeals[class]++
		}
	}
	for c := range 2 {
		for i := range conversations[c] {
			n := conversations[c][i]
			if n != 0 {
				out.Support.Conversations[c]++
			}
			out.Support.LargestConversation[c] = max(out.Support.LargestConversation[c], int(n))
		}
	}
	if !completeClean || !labelsJoined || len(rows) == 0 {
		return fail("training_support")
	}
	for c := range 2 {
		if out.Support.Rows[c] < 64 || out.Support.Conversations[c] < 4 || 2*out.Support.LargestConversation[c] > out.Support.Rows[c] {
			return fail("training_support")
		}
	}
	train := make([][]float64, len(rows))
	truth := make([]bool, len(rows))
	backing := make([]float64, len(rows)*mailboxFeatureCount)
	defer clear(backing)
	defer clear(truth)
	for i, row := range rows {
		train[i] = backing[i*mailboxFeatureCount : (i+1)*mailboxFeatureCount]
		for j, v := range row.Values {
			train[i][j] = float64(v)
		}
		truth[i] = row.Positive
	}
	model, ok := metrics.FitDiscriminant(train, truth)
	if !ok {
		return fail("training_degenerate")
	}
	witness := mailboxMoments(rows)
	replayed, stable, ok := checkMailboxFit(train, truth, &witness)
	if !ok || !sameMailboxModel(model, replayed) {
		return fail("fit_conformance")
	}
	a, b := model.Scores(train), replayed.Scores(train)
	if len(a) != len(rows) || len(b) != len(rows) {
		return fail("fit_conformance")
	}
	for i := range a {
		if math.Float64bits(a[i]) != math.Float64bits(b[i]) {
			clear(a)
			clear(b)
			return fail("fit_conformance")
		}
	}
	clear(a)
	clear(b)
	out.Support.RAMConformance = true
	if !stable {
		return fail("fit_audit_sensitive")
	}
	out.Support.Stable, out.Releasable = true, true
	out.Model, out.Witness = &model, &witness
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

type fitInterval struct{ lo, hi float64 }

func outwardFit(lo, hi float64) fitInterval {
	return fitInterval{math.Nextafter(lo, math.Inf(-1)), math.Nextafter(hi, math.Inf(1))}
}
func pointFit(v float64) fitInterval      { return fitInterval{v, v} }
func addFit(a, b fitInterval) fitInterval { return outwardFit(a.lo+b.lo, a.hi+b.hi) }
func subFit(a, b fitInterval) fitInterval { return outwardFit(a.lo-b.hi, a.hi-b.lo) }
func mulFit(a, b fitInterval) fitInterval {
	p := [4]float64{a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi}
	return outwardFit(slices.Min(p[:]), slices.Max(p[:]))
}
func squareFit(a fitInterval) fitInterval {
	b := absFit(a)
	return outwardFit(b.lo*b.lo, b.hi*b.hi)
}
func divFit(a, b fitInterval) fitInterval {
	if b.lo <= 0 && b.hi >= 0 {
		return fitInterval{math.Inf(-1), math.Inf(1)}
	}
	return mulFit(a, outwardFit(1/b.hi, 1/b.lo))
}
func sqrtFit(a fitInterval) fitInterval {
	if a.lo < 0 {
		return fitInterval{math.NaN(), math.NaN()}
	}
	return outwardFit(math.Sqrt(a.lo), math.Sqrt(a.hi))
}
func finiteFit(a fitInterval) bool {
	return !math.IsNaN(a.lo) && !math.IsNaN(a.hi) && !math.IsInf(a.lo, 0) && !math.IsInf(a.hi, 0)
}
func absFit(a fitInterval) fitInterval {
	hi := math.Max(math.Abs(a.lo), math.Abs(a.hi))
	lo := math.Min(math.Abs(a.lo), math.Abs(a.hi))
	if a.lo <= 0 && a.hi >= 0 {
		lo = 0
	}
	return fitInterval{lo, hi}
}

func exactMailboxScatter(sumI, sumJ, cross int64, n int) float64 {
	r := new(big.Rat).SetInt64(cross)
	product := new(big.Int).Mul(big.NewInt(sumI), big.NewInt(sumJ))
	r.Sub(r, new(big.Rat).SetFrac(product, big.NewInt(int64(n))))
	v, _ := r.Float64()
	return v
}

func checkMailboxFit(train [][]float64, truth []bool, witness *MailboxFitWitness) (metrics.Discriminant, bool, bool) {
	const width = mailboxFeatureCount
	var empty metrics.Discriminant
	if len(train) == 0 || len(train) != len(truth) || witness == nil {
		return empty, false, false
	}
	n := len(train)
	stable := true
	mu, mu0, mu1 := make([]float64, width), make([]float64, width), make([]float64, width)
	for i, row := range train {
		if len(row) != width {
			return empty, false, false
		}
		for j, v := range row {
			mu[j] += v
			if truth[i] {
				mu1[j] += v
			} else {
				mu0[j] += v
			}
		}
	}
	for j := range width {
		mu[j] /= float64(n)
		mu0[j] /= float64(witness.ClassCount[0])
		mu1[j] /= float64(witness.ClassCount[1])
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
			di := row[i] - mu[i]
			for j := range i + 1 {
				if varying[j] {
					witness.Scatter[i][j] += di * (row[j] - mu[j])
				}
			}
		}
	}
	var scatterInterval [width][width]fitInterval
	u := math.Ldexp(1, -53)
	k := float64(n + 4)
	gamma := k * u / (1 - k*u)
	var scaleInterval [width]fitInterval
	for i := range width {
		if !varying[i] {
			continue
		}
		di := math.Max(1, math.Max(math.Abs(float64(witness.Minimum[i])-mu[i]), math.Abs(float64(witness.Maximum[i])-mu[i])))
		for j := range i + 1 {
			if !varying[j] {
				continue
			}
			dj := math.Max(1, math.Max(math.Abs(float64(witness.Minimum[j])-mu[j]), math.Abs(float64(witness.Maximum[j])-mu[j])))
			exact := exactMailboxScatter(witness.Sum[i], witness.Sum[j], witness.Cross[i][j], n)
			bound := 8 * gamma * float64(n) * di * dj
			iv := outwardFit(exact-bound, exact+bound)
			if witness.Scatter[i][j] < iv.lo || witness.Scatter[i][j] > iv.hi {
				return empty, false, false
			}
			scatterInterval[i][j] = iv
		}
		witness.Scale[i] = math.Sqrt(witness.Scatter[i][i])
		if witness.Scatter[i][i] < 0x1p-1022 || math.IsInf(witness.Scale[i], 0) {
			return empty, false, false
		}
		if scatterInterval[i][i].lo < 0x1p-1022 {
			stable = false
		} else {
			scaleInterval[i] = sqrtFit(scatterInterval[i][i])
		}
	}
	var cholInterval [width][width]fitInterval
	var kept []int
	for i := range width {
		if !varying[i] {
			continue
		}
		pivot := witness.Scatter[i][i] / witness.Scale[i] / witness.Scale[i]
		pi := divFit(divFit(scatterInterval[i][i], scaleInterval[i]), scaleInterval[i])
		for p, j := range kept {
			c := witness.Scatter[i][j] / witness.Scale[i] / witness.Scale[j]
			ci := divFit(divFit(scatterInterval[i][j], scaleInterval[i]), scaleInterval[j])
			for r := range p {
				c -= witness.Cholesky[i][r] * witness.Cholesky[j][r]
				ci = subFit(ci, mulFit(cholInterval[i][r], cholInterval[j][r]))
			}
			witness.Cholesky[i][p] = c / witness.Cholesky[j][p]
			cholInterval[i][p] = divFit(ci, cholInterval[j][p])
			pivot -= witness.Cholesky[i][p] * witness.Cholesky[i][p]
			pi = subFit(pi, mulFit(cholInterval[i][p], cholInterval[i][p]))
		}
		if !finiteFit(pi) || pi.lo <= 1e-9 && pi.hi >= 1e-9 {
			stable = false
		}
		if pivot <= 1e-9 {
			continue
		}
		witness.Cholesky[i][len(kept)] = math.Sqrt(pivot)
		if pi.lo > 0 {
			cholInterval[i][len(kept)] = sqrtFit(pi)
		} else {
			stable = false
		}
		kept = append(kept, i)
	}
	if !slices.ContainsFunc(kept, func(j int) bool { return !mailboxSame(mu1[j], mu0[j]) }) {
		return empty, false, false
	}
	for _, j := range kept {
		if witness.ClassSum[1][j]*int64(witness.ClassCount[0]) == witness.ClassSum[0][j]*int64(witness.ClassCount[1]) {
			continue
		}
		a := divFit(pointFit(float64(witness.ClassSum[1][j])), pointFit(float64(witness.ClassCount[1])))
		b := divFit(pointFit(float64(witness.ClassSum[0][j])), pointFit(float64(witness.ClassCount[0])))
		d := absFit(subFit(a, b))
		aa, bb := absFit(a), absFit(b)
		tol := mulFit(pointFit(1e-9), fitInterval{math.Max(aa.lo, bb.lo), math.Max(aa.hi, bb.hi)})
		if !(d.hi <= tol.lo || d.lo > tol.hi) {
			stable = false
		}
	}
	y := make([]float64, len(kept))
	yIntervals := make([]fitInterval, len(kept))
	for p, j := range kept {
		v := (mu1[j] - mu0[j]) / witness.Scale[j]
		difference := subFit(divFit(pointFit(float64(witness.ClassSum[1][j])), pointFit(float64(witness.ClassCount[1]))), divFit(pointFit(float64(witness.ClassSum[0][j])), pointFit(float64(witness.ClassCount[0]))))
		if witness.ClassSum[1][j]*int64(witness.ClassCount[0]) == witness.ClassSum[0][j]*int64(witness.ClassCount[1]) {
			difference = pointFit(0)
		}
		vi := divFit(difference, scaleInterval[j])
		for r := range p {
			v -= witness.Cholesky[j][r] * y[r]
			vi = subFit(vi, mulFit(cholInterval[j][r], yIntervals[r]))
		}
		y[p] = v / witness.Cholesky[j][p]
		yIntervals[p] = divFit(vi, cholInterval[j][p])
		if !finiteFit(yIntervals[p]) {
			stable = false
		}
	}
	weights, center := make([]float64, width), make([]float64, width)
	v := make([]float64, len(kept))
	vIntervals := make([]fitInterval, len(kept))
	for p := len(kept) - 1; p >= 0; p-- {
		j := kept[p]
		x := y[p]
		xi := yIntervals[p]
		for r := p + 1; r < len(kept); r++ {
			x -= witness.Cholesky[kept[r]][p] * v[r]
			xi = subFit(xi, mulFit(cholInterval[kept[r]][p], vIntervals[r]))
		}
		v[p] = x / witness.Cholesky[j][p]
		vIntervals[p] = divFit(xi, cholInterval[j][p])
		weights[j] = v[p] / witness.Scale[j]
		if !finiteFit(divFit(vIntervals[p], scaleInterval[j])) {
			stable = false
		}
	}
	wd := 0.0
	wdInterval := pointFit(0)
	for p, x := range y {
		wd += x * x
		wdInterval = addFit(wdInterval, squareFit(yIntervals[p]))
	}
	if !(wd > 0) || math.IsInf(wd, 0) {
		return empty, false, false
	}
	if !finiteFit(wdInterval) || wdInterval.lo <= 0 {
		stable = false
	}
	for j := range width {
		center[j] = (mu1[j] + mu0[j]) / 2
		if !slices.Contains(kept, j) {
			witness.Unused = append(witness.Unused, j)
		}
	}
	witness.Kept = slices.Clone(kept)
	for i := range width {
		for j := range i {
			witness.Scatter[j][i] = witness.Scatter[i][j]
		}
	}
	return metrics.Discriminant{Weights: weights, Center: center, Normalizer: wd, Kept: kept, Unused: slices.Clone(witness.Unused)}, stable, true
}
