package nodeview

import (
	"bytes"
	cryptorand "crypto/rand"
	"math"
	"math/big"
	"sort"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

func annotateMethod(m predictedMethod, in evaluationInput) ([]metrics.Score, map[int]int, int, error) {
	hint := 0
	if len(in.views.nodes) == 2 {
		hint = len(in.views.nodes[0].setups)
	}
	truth := make(map[int]int, hint)
	succeeded := false
	defer func() {
		if !succeeded {
			clear(truth)
		}
	}()
	groups := 0
	if m.method == "request" || m.method == "record" {
		groups = len(in.plans) / 2
		out := make([]metrics.Score, 0, len(m.values))
		defer func() {
			if !succeeded {
				clear(out)
			}
		}()
		for _, v := range m.values {
			if v.second >= len(in.views.nodes) || v.first >= len(in.views.nodes[v.second].mailbox) {
				return nil, nil, 0, fail(ReasonContract)
			}
			node := in.views.nodes[v.second]
			o := node.mailbox[v.first]
			positive, eligible, side, ok := mailboxLabel(node, o, in.truth)
			if !ok {
				return nil, nil, 0, fail(ReasonLabel)
			}
			if !eligible {
				continue
			}
			out = append(out, metrics.Score{Entry: int(side) / 2, Exit: len(out), Value: v.value, True: positive})
		}
		succeeded = true
		return out, truth, groups, nil
	}
	if len(in.views.nodes) != 2 {
		return nil, truth, 0, nil
	}
	first, second := in.views.nodes[0], in.views.nodes[1]
	groups = len(first.setups)
	for i, a := range first.setups {
		sideA, groupA, okA := setupOwner(in.truth, a.circuit, first.position)
		if !okA {
			return nil, nil, 0, fail(ReasonLabel)
		}
		for j, b := range second.setups {
			sideB, groupB, okB := setupOwner(in.truth, b.circuit, second.position)
			if !okB {
				return nil, nil, 0, fail(ReasonLabel)
			}
			if okB && sideA == sideB && groupA == groupB {
				if _, exists := truth[i]; exists {
					return nil, nil, 0, fail(ReasonContract)
				}
				truth[i] = j
			}
		}
	}
	out := make([]metrics.Score, len(m.values))
	defer func() {
		if !succeeded {
			clear(out)
		}
	}()
	for i, v := range m.values {
		if v.first < 0 || v.first >= len(first.setups) || v.second < 0 || v.second >= len(second.setups) {
			return nil, nil, 0, fail(ReasonContract)
		}
		j, ok := truth[v.first]
		out[i] = metrics.Score{Entry: v.first, Exit: v.second, Value: v.value, True: ok && j == v.second}
	}
	succeeded = true
	return out, truth, groups, nil
}

func mailboxLabel(node nodeView, o mailboxObservation, t privateTruth) (positive, eligible bool, side uint16, ok bool) {
	var circuit uint64
	found := 0
	for _, s := range node.setups {
		if s.hop == o.Circuit {
			circuit = s.circuit
			found++
		}
	}
	if found != 1 {
		return false, false, 0, false
	}
	var generation uint32
	side, generation, ok = setupOwner(t, circuit, node.position)
	if !ok {
		return false, false, 0, false
	}
	var request *actualRequest
	for i := range t.requests {
		q := &t.requests[i]
		if q.side != side || q.tag != o.Tag || q.generation != generation {
			continue
		}
		if q.record.size == 0 != (!o.HasPut) {
			continue
		}
		if o.HasPut && !bytes.Equal(t.arena.bytes(q.record), node.arena.bytes(o.record)) {
			continue
		}
		if request != nil {
			return false, false, side, false
		}
		request = q
	}
	if request == nil || !request.success {
		return false, false, side, false
	}
	eligible = request.eligibility == 2
	if !eligible {
		return false, false, side, true
	}
	if !o.HasPut {
		return false, true, side, true
	}
	if o.RecordKind != 3 {
		return false, false, side, true
	}
	positive, ok = matchRecordLabel(&t, node.arena.bytes(o.record))
	return positive, true, side, ok
}

func summarizeMethod(m predictedMethod, in evaluationInput, configuration string, repeat int, seed int64) (result MethodResult, audit RankAudit, resultErr error) {
	base, err := metricScratchBytes(len(m.values), 0, 0)
	if err != nil {
		return MethodResult{}, RankAudit{}, err
	}
	release, err := scratchReservation(in.budget, base)
	if err != nil {
		return MethodResult{}, RankAudit{}, err
	}
	defer release()
	defer func() {
		if resultErr != nil {
			wipeRankAudit(&audit)
		}
	}()
	scores, truth, groups, e := annotateMethod(m, in)
	defer clear(scores)
	defer func() { clear(truth) }()
	result = MethodResult{Method: m.method, WindowNS: m.windowNS, Candidates: len(scores), Partners: len(truth)}
	audit = RankAudit{Configuration: configuration, Repeat: repeat, Method: m.method, WindowNS: m.windowNS, Seed: seed}
	if e != nil {
		return result, audit, e
	}
	if len(scores) == 0 {
		audit.Groups = make([][]RankBucket, groups)
		result.AUC = Number{Reason: ReasonNoView}
		result.TopOne = Number{Reason: ReasonNoPartner}
		result.TPR = Number{Reason: ReasonNoView}
		return result, audit, holdRankResult(in, result, audit)
	}
	permutation, e := privatePermutation(groups)
	if e != nil {
		return result, audit, e
	}
	defer clear(permutation)
	anonymousTruth, err := anonymizeGroups(scores, truth, permutation)
	clear(truth)
	truth, e = anonymousTruth, err
	if e != nil {
		return result, audit, e
	}
	positive, negative := 0, 0
	for _, s := range scores {
		if s.True {
			positive++
		} else {
			negative++
		}
		if m.method != "request" && m.method != "record" && s.Value == -2 {
			result.Undefined++
		}
		if m.method != "request" && m.method != "record" && s.Value == -3 {
			result.Impossible++
		}
	}
	reason := ReasonNone
	if positive == 0 {
		reason = ReasonNoPositive
	} else if negative == 0 {
		reason = ReasonNoNegative
	}
	result.AUC = number(metrics.AUC(scores), reason)
	result.TPR = number(metrics.TPRAtFPR(scores, .01), reason)
	if m.method != "request" && m.method != "record" {
		kept, n := metrics.Partnered(scores, truth)
		result.TopOne = number(metrics.TopOneAccuracy(kept, n), ReasonNoPartner)
		clear(kept[:cap(kept)])
		links := metrics.BestMatches(scores, groups, 0)
		result.Made, result.Wrong = metrics.FalseLinks(links, truth)
		clear(links[:cap(links)])
		audit.Made, audit.Wrong = result.Made, result.Wrong
		audit.TopOne = make([][2]int, 0, len(truth))
		for i := range groups {
			if _, ok := truth[i]; !ok {
				continue
			}
			best := math.Inf(-1)
			for _, s := range scores {
				if s.Entry == i && s.Value > best {
					best = s.Value
				}
			}
			ties, hit := 0, 0
			for _, s := range scores {
				if s.Entry == i && s.Value == best {
					ties++
					if s.True {
						hit = 1
					}
				}
			}
			audit.TopOne = append(audit.TopOne, [2]int{ties, hit})
		}
	} else {
		result.TopOne = Number{Reason: ReasonNoPartner}
	}
	if groups < 0 || groups > 128 {
		return result, audit, fail(ReasonLimit)
	}
	counts := make([]int, groups)
	defer clear(counts)
	maxGroup := 0
	for _, s := range scores {
		if s.Entry < 0 || s.Entry >= groups {
			return result, audit, fail(ReasonContract)
		}
		counts[s.Entry]++
		maxGroup = max(maxGroup, counts[s.Entry])
	}
	peak, err := metricScratchBytes(len(scores), groups, maxGroup)
	if err != nil {
		return result, audit, err
	}
	bootstrapRelease, err := scratchReservation(in.budget, peak-uint64(len(scores))*512-(2<<20))
	if err != nil {
		return result, audit, err
	}
	interval := metrics.BootstrapAUC(scores, groups, 2000, seed)
	bootstrapRelease()
	result.BootstrapLow = number(interval.Low, ReasonIncomplete)
	result.BootstrapHigh = number(interval.High, ReasonIncomplete)
	audit.Groups = make([][]RankBucket, groups)
	for group, n := range counts {
		audit.Groups[group] = make([]RankBucket, 0, n)
	}
	order := append([]metrics.Score(nil), scores...)
	defer clear(order)
	sort.Slice(order, func(i, j int) bool { return order[i].Value < order[j].Value })
	rank := 0
	for at := 0; at < len(order); {
		end := at + 1
		for end < len(order) && order[end].Value == order[at].Value {
			end++
		}
		rank++
		counts := make([][2]int, groups)
		for _, s := range order[at:end] {
			class := 0
			if s.True {
				class = 1
			}
			counts[s.Entry][class]++
		}
		category := 0
		if order[at].Value > 0 {
			category = 1
		}
		if m.method != "request" && m.method != "record" && order[at].Value == -2 {
			category = -2
		} else if m.method != "request" && m.method != "record" && order[at].Value == -3 {
			category = -3
		}
		for g, a := range counts {
			if a[0]+a[1] > 0 {
				audit.Groups[g] = append(audit.Groups[g], RankBucket{rank, a[1], a[0], category})
			}
		}
		clear(counts)
		at = end
	}
	return result, audit, holdRankResult(in, result, audit)
}

func privatePermutation(n int) ([]int, error) {
	if n < 0 || n > maxSelectedCells {
		return nil, fail(ReasonLimit)
	}
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j, e := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(i+1)))
		if e != nil {
			clear(p)
			return nil, fail(ReasonIncomplete)
		}
		k := int(j.Int64())
		p[i], p[k] = p[k], p[i]
	}
	return p, nil
}

func anonymizeGroups(scores []metrics.Score, truth map[int]int, permutation []int) (map[int]int, error) {
	seen := make([]bool, len(permutation))
	defer clear(seen)
	for _, j := range permutation {
		if j < 0 || j >= len(seen) || seen[j] {
			return nil, fail(ReasonContract)
		}
		seen[j] = true
	}
	for i := range scores {
		entry := scores[i].Entry
		if entry < 0 || entry >= len(permutation) {
			return nil, fail(ReasonContract)
		}
		scores[i].Entry = permutation[entry]
	}
	out := make(map[int]int, len(truth))
	for i, j := range truth {
		if i < 0 || i >= len(permutation) {
			clear(out)
			return nil, fail(ReasonContract)
		}
		out[permutation[i]] = j
	}
	clear(permutation)
	return out, nil
}

func mailboxEvaluation(in evaluationInput) (q, auc, joined Number, rowsRequest, rowsRecord []encodedTrainingRow, err error) {
	q, auc, joined = Number{Reason: ReasonNoView}, Number{Reason: ReasonNoView}, Number{Reason: ReasonNoView}
	var putValues []float64
	var truths []bool
	negative, noPut := 0, 0
	var count int
	for _, node := range in.views.nodes {
		count += len(node.mailbox)
	}
	lease, e := scratchReservation(in.budget, uint64(count)*768+2<<20)
	if e != nil {
		return q, auc, joined, rowsRequest, rowsRecord, e
	}
	defer lease()
	defer func() { clear(putValues[:cap(putValues)]); clear(truths[:cap(truths)]) }()
	putValues = make([]float64, 0, count)
	truths = make([]bool, 0, count)
	rowsRequest = make([]encodedTrainingRow, 0, count)
	rowsRecord = make([]encodedTrainingRow, 0, count)
	var seenOriginal uint32Membership
	defer func() { seenOriginal.wipe() }()
	defer func() {
		if err != nil {
			for i := range rowsRequest {
				rowsRequest[i].wipe()
			}
			for i := range rowsRecord {
				rowsRecord[i].wipe()
			}
			rowsRequest, rowsRecord = nil, nil
			return
		}
		if e := in.resultCharge.hold(trainingBacking(rowsRequest) + trainingBacking(rowsRecord)); e != nil {
			for i := range rowsRequest {
				rowsRequest[i].wipe()
			}
			for i := range rowsRecord {
				rowsRecord[i].wipe()
			}
			rowsRequest, rowsRecord = nil, nil
			err = e
		}
	}()
	for _, node := range in.views.nodes {
		if len(node.mailbox) == 0 {
			continue
		}
		if node.position != 4 {
			return q, auc, joined, rowsRequest, rowsRecord, fail(ReasonContract)
		}
		inventory, e := queueInventory(node.mailbox, in.public.epochNS, in.public.cutoffNS)
		if e != nil {
			return q, auc, joined, rowsRequest, rowsRecord, e
		}
		queueResult, falsePairs, e := evaluateQueues(node, inventory, in.truth, len(in.plans)/2)
		clear(inventory)
		if e != nil {
			return q, auc, joined, rowsRequest, rowsRecord, e
		}
		joined = queueResult
		if in.queueFalsePairs != nil {
			*in.queueFalsePairs = falsePairs
		}
		var rows []encodedMailboxRow
		if in.public.settings.ControlProfile == 0 {
			rows, e = boundedMailboxRows(node, in.public.settings.RateNS)
		}
		if e != nil {
			return q, auc, joined, rowsRequest, rowsRecord, e
		}
		defer func(rows []encodedMailboxRow) {
			for i := range rows {
				rows[i].wipe()
			}
		}(rows)
		if in.public.settings.ControlProfile == 0 {
			seenOriginal, e = makeUint32Membership(len(node.mailbox), func(i int) uint32 { return node.mailbox[i].RecordAlias }, in.budget)
			if e != nil {
				return q, auc, joined, rowsRequest, rowsRecord, e
			}
		}
		for i, o := range node.mailbox {
			if o.CallNS < in.public.epochNS || o.CallNS >= in.public.cutoffNS {
				continue
			}
			positive, eligible, side, ok := mailboxLabel(node, o, in.truth)
			if !ok {
				return q, auc, joined, rowsRequest, rowsRecord, fail(ReasonLabel)
			}
			if !eligible {
				continue
			}
			v := 0.
			if o.HasPut {
				v = 1
			}
			putValues = append(putValues, v)
			truths = append(truths, positive)
			if !positive {
				negative++
				if !o.HasPut {
					noPut++
				}
			}
			if in.public.settings.ControlProfile == 0 {
				previous, found := seenOriginal.mark(o.RecordAlias)
				if !found {
					return q, auc, joined, rowsRequest, rowsRecord, fail(ReasonContract)
				}
				row := encodedTrainingRow{Values: rows[i], Positive: positive, Conversation: side / 2, OriginalSeal: o.HasPut && !previous}
				rowsRequest = append(rowsRequest, row)
				if o.HasPut && o.RecordKind == 3 {
					rowsRecord = append(rowsRecord, row)
				}
			}
		}
		for i := range rows {
			rows[i].wipe()
		}
		seenOriginal.wipe()
		seenOriginal = nil
	}
	if negative > 0 {
		q = number(float64(noPut)/float64(negative), ReasonNone)
	} else {
		q = Number{Reason: ReasonNoNegative}
	}
	if len(putValues) > 0 {
		scores := make([]metrics.Score, len(putValues))
		defer clear(scores)
		for i, v := range putValues {
			scores[i] = metrics.Score{Value: v, True: truths[i]}
		}
		auc = number(metrics.AUC(scores), ReasonMissingClass)
		if auc.Value != nil && q.Value != nil && math.Abs(*auc.Value-(.5+*q.Value/2)) > 1e-12 {
			return q, auc, joined, rowsRequest, rowsRecord, fail(ReasonLabel)
		}
	}
	return
}
