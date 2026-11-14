package nodeview

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strings"

	"github.com/jimichi-org/jimichi/lab/metrics"
)

// callers must first derive these inputs from five clean paired runs and validate
// the guarded frozen model contents; a public plan cannot prove erased observations
func CombinePilotPlans(ctx context.Context, collude, mailbox Plan) (Plan, Plan, error) {
	if ctx.Err() != nil {
		return Plan{}, Plan{}, fail(ReasonPlanning)
	}
	if collude.Set != Collude || mailbox.Set != Mailbox || collude.Phase != Pilot || mailbox.Phase != Pilot || collude.Suite != "c25519" || mailbox.Suite != "c25519" {
		return Plan{}, Plan{}, ErrInvalid
	}
	if collude.Digest == "" || mailbox.Digest == "" || collude.MainSeedCommitment != "" || mailbox.MainSeedCommitment != "" || ValidatePlan(collude) != nil || ValidatePlan(mailbox) != nil || collude.PilotReady || mailbox.PilotReady || collude.ModelReady || mailbox.ModelReady || len(collude.Samples) != 0 || len(mailbox.Samples) != 0 {
		return Plan{}, Plan{}, ErrInvalid
	}
	if !samePlanningContract(collude, mailbox) || !mailbox.TrainingReady || !validPlanningModels(mailbox.FrozenModels) || collude.TrainingReady && !reflect.DeepEqual(collude.FrozenModels, mailbox.FrozenModels) {
		return Plan{}, Plan{}, fail(ReasonPilot)
	}
	if !incidentPilotInputs(collude, 0, 9) || !incidentPilotInputs(mailbox, 9, 13) {
		return Plan{}, Plan{}, fail(ReasonPilot)
	}
	powers := append(clonePlanningPlan(collude).Powers, clonePlanningPlan(mailbox).Powers...)
	search := make([]PairedPowerPlan, len(powers))
	seeds := make(map[int64]bool, len(powers))
	for i, input := range powers {
		if seeds[input.Seed] {
			return Plan{}, Plan{}, fail(ReasonPilot)
		}
		seeds[input.Seed] = true
		calculation, err := PlanPairedPower(ctx, input.PilotX, input.PilotY, input.Seed)
		if err != nil {
			return Plan{}, Plan{}, err
		}
		point, err := PairedPowerAtN(ctx, input.PilotX, input.PilotY, input.Seed, calculation.SelectedN)
		if err != nil {
			return Plan{}, Plan{}, err
		}
		if !samePowerPoint(input, point) || input.N != calculation.SelectedN {
			return Plan{}, Plan{}, fail(ReasonPlanning)
		}
		search[i] = calculation
	}
	for _, part := range []struct {
		plan  Plan
		start int
	}{{collude, 0}, {mailbox, 9}} {
		if len(part.plan.PowerSearch) != 0 {
			if len(part.plan.PowerSearch) != len(part.plan.Powers) || !reflect.DeepEqual(part.plan.PowerSearch, search[part.start:part.start+len(part.plan.Powers)]) {
				return Plan{}, Plan{}, fail(ReasonPlanning)
			}
		}
	}
	counts := plannedIncidentCounts(search)
	for i := range powers {
		point, err := PairedPowerAtN(ctx, powers[i].PilotX, powers[i].PilotY, powers[i].Seed, counts[powers[i].ID])
		if err != nil {
			return Plan{}, Plan{}, err
		}
		if point.Power < nodePower {
			return Plan{}, Plan{}, fail(ReasonPower)
		}
		powers[i] = powerCalculation(powers[i], point)
	}
	left, right := clonePlanningPlan(collude), clonePlanningPlan(mailbox)
	for _, successor := range []*Plan{&left, &right} {
		successor.Powers = powers
		successor.PowerSearch = search
		successor.TrainingReady = true
		successor.FrozenModels = mailbox.FrozenModels
		successor.PilotReady = true
		for i := range successor.Configurations {
			if n, ok := configurationIncidentCount(successor.Configurations[i], counts); ok {
				successor.Configurations[i].Main = n
			}
		}
		*successor = clonePlanningPlan(*successor)
		if err := sealPlanningSuccessor(successor); err != nil {
			return Plan{}, Plan{}, err
		}
	}
	return left, right, nil
}

func PrepareModelPlan(ctx context.Context, p Plan) (Plan, error) {
	if ctx.Err() != nil {
		return Plan{}, fail(ReasonPlanning)
	}
	if p.Set != Compromise || p.Suite != "c25519" || p.Phase != Structural || p.Digest == "" || p.MainSeedCommitment != "" || ValidatePlan(p) != nil || p.PilotReady || p.TrainingReady || len(p.Powers) != 0 || len(p.PowerSearch) != 0 || len(p.FrozenModels) != 0 {
		return Plan{}, ErrInvalid
	}
	rows, err := PlanModelSlots(ctx)
	if err != nil {
		return Plan{}, err
	}
	out := clonePlanningPlan(p)
	out.Phase = Pilot
	if len(out.Configurations) < len(rows) {
		return Plan{}, fail(ReasonModelPower)
	}
	for i := range rows {
		if out.Configurations[i].ID != rows[i].Row {
			return Plan{}, fail(ReasonModelPower)
		}
		out.Configurations[i].Slots = rows[i].Slots
	}
	out.Samples, err = modelSampleCalculations(ctx, out, rows)
	if err != nil {
		return Plan{}, err
	}
	out.ModelReady = true
	if err := sealPlanningSuccessor(&out); err != nil {
		return Plan{}, err
	}
	return out, nil
}

// structural validation and actual source/model loading remain caller preconditions
func validateRegisteredPlanning(ctx context.Context, p Plan) error {
	if ctx.Err() != nil {
		return fail(ReasonPlanning)
	}
	if p.Suite != "c25519" {
		if p.ModelReady || p.PilotReady || len(p.Samples) != 0 || len(p.Powers) != 0 || len(p.PowerSearch) != 0 {
			return fail(ReasonUnsupported)
		}
		return nil
	}
	if p.Set == Compromise {
		if p.PilotReady || len(p.Powers) != 0 || len(p.PowerSearch) != 0 {
			return fail(ReasonPlanning)
		}
		if !p.ModelReady && p.Phase != Primary {
			if len(p.Samples) != 0 {
				return fail(ReasonModelPower)
			}
			return nil
		}
		rows, err := PlanModelSlots(ctx)
		if err != nil {
			return err
		}
		samples, err := modelSampleCalculations(ctx, p, rows)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(samples, p.Samples) {
			return fail(ReasonModelPower)
		}
		return nil
	}
	if p.ModelReady || len(p.Samples) != 0 {
		return fail(ReasonPlanning)
	}
	if !p.PilotReady && p.Phase != Primary {
		if len(p.PowerSearch) != 0 {
			return fail(ReasonPlanning)
		}
		if len(p.Powers) == 0 {
			return nil
		}
		start, end := 0, 9
		if p.Set == Mailbox {
			start, end = 9, 13
		}
		if !incidentPilotInputs(p, start, end) {
			return fail(ReasonPilot)
		}
		return nil
	}
	if len(p.Powers) != nodeFamilySize || len(p.PowerSearch) != nodeFamilySize || !p.TrainingReady || !validPlanningModels(p.FrozenModels) {
		return fail(ReasonPilot)
	}
	seeds := make(map[int64]bool, nodeFamilySize)
	search := make([]PairedPowerPlan, nodeFamilySize)
	for i, input := range p.Powers {
		if input.ID != differenceIDs()[i] || !validPilotValues(input) || seeds[input.Seed] {
			return fail(ReasonPilot)
		}
		seeds[input.Seed] = true
		calculation, err := PlanPairedPower(ctx, input.PilotX, input.PilotY, input.Seed)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(calculation, p.PowerSearch[i]) {
			return fail(ReasonPlanning)
		}
		search[i] = calculation
	}
	counts := plannedIncidentCounts(search)
	for i, input := range p.Powers {
		point, err := PairedPowerAtN(ctx, input.PilotX, input.PilotY, input.Seed, counts[input.ID])
		if err != nil {
			return err
		}
		if point.Power < nodePower || !samePowerPoint(input, point) {
			return fail(ReasonPower)
		}
		if p.PowerSearch[i].SelectedN > input.N {
			return fail(ReasonPlanning)
		}
	}
	for _, row := range p.Configurations {
		if row.Population == "boundary" || row.Settings.ControlProfile != 0 {
			if !planningBoundaryCoordinate(row) {
				return fail(ReasonPlanning)
			}
			continue
		}
		n := 30
		if incident, ok := configurationIncidentCount(row, counts); ok {
			n = incident
		}
		if row.Main != n {
			return fail(ReasonPlanning)
		}
	}
	return nil
}

func modelSampleCalculations(ctx context.Context, p Plan, minimum []ModelSamplePlan) ([]SampleCalculation, error) {
	expected := canonicalCoordinates(Compromise)
	if len(minimum) != 6 || len(p.Configurations) != len(expected) || len(p.Configurations) < len(minimum) {
		return nil, fail(ReasonModelPower)
	}
	for i := len(minimum); i < len(p.Configurations); i++ {
		if !reflect.DeepEqual(p.Configurations[i], expected[i]) {
			return nil, fail(ReasonModelPower)
		}
	}
	counts := make(map[string]int, len(minimum))
	for i, row := range p.Configurations[:len(minimum)] {
		if row.ID != minimum[i].Row || row.Slots < minimum[i].Slots || row.Slots > 1048576 || row.Slots%32 != 0 || row.ID == "M1" && row.Slots != 32 {
			return nil, fail(ReasonModelPower)
		}
		counts[row.ID] = row.Slots
	}
	out := make([]SampleCalculation, 0, nodeFamilySize)
	for _, claim := range ModelRegistry() {
		if ctx.Err() != nil {
			return nil, fail(ReasonPlanning)
		}
		n := counts[claim.Row]
		sd := math.Sqrt(claim.Variance)
		bound, ok := metrics.EquivalenceSize(sd, nodeDelta, nodeFamilySize, nodePower)
		if !ok || n < bound {
			return nil, fail(ReasonModelPower)
		}
		power := math.Max(0, math.Erf((nodeDelta/(sd/math.Sqrt(float64(n)))-math.Sqrt2*math.Erfinv(1-nodeAlpha/nodeFamilySize))/math.Sqrt2))
		if claim.Kind == "binary" {
			power, ok = ExactWilsonPower(n, claim.Mean, nodeDelta, 1-nodeAlpha/nodeFamilySize)
		}
		if !ok || !(power >= nodePower && power <= 1) {
			return nil, fail(ReasonModelPower)
		}
		out = append(out, SampleCalculation{ID: claim.ID, Slots: n, Expected: claim.Mean, SD: sd, Power: power})
	}
	return out, nil
}

func samePlanningContract(a, b Plan) bool {
	normalize := func(p Plan) Plan {
		p = clonePlanningPlan(p)
		p.Set, p.Phase = Collude, Structural
		p.Configurations = nil
		p.Digest, p.ParentDigest = "", ""
		p.MainSeedCommitment = ""
		p.Powers, p.PowerSearch, p.Samples, p.FrozenModels = nil, nil, nil, nil
		p.PilotReady, p.ModelReady, p.TrainingReady = false, false, false
		return p
	}
	return reflect.DeepEqual(normalize(a), normalize(b))
}

func incidentPilotInputs(p Plan, start, end int) bool {
	if len(p.Powers) != end-start {
		return false
	}
	for i, input := range p.Powers {
		if input.ID != differenceIDs()[start+i] || !validPilotValues(input) {
			return false
		}
	}
	for _, row := range p.Configurations {
		if row.Population == "boundary" || row.Settings.ControlProfile != 0 {
			if !planningBoundaryCoordinate(row) {
				return false
			}
			continue
		}
		if row.Main != 30 || row.Pilots != 5 {
			return false
		}
	}
	return true
}

func planningBoundaryCoordinate(row Coordinate) bool {
	if row.Population != "boundary" || row.Settings.ControlProfile == 0 {
		return false
	}
	for _, expected := range boundaryCoordinates() {
		if row.ID == expected.ID {
			return reflect.DeepEqual(row, expected)
		}
	}
	return false
}

func validPilotValues(input PowerCalculation) bool {
	if len(input.PilotX) != 5 || len(input.PilotY) != 5 {
		return false
	}
	for i, x := range input.PilotX {
		y := input.PilotY[i]
		if !(x >= 0 && x <= 1 && y >= 0 && y <= 1) {
			return false
		}
	}
	return true
}

func validPlanningModels(models []ModelReference) bool {
	if len(models) != 8 {
		return false
	}
	seen := make(map[string]bool, 8)
	for _, model := range models {
		key := model.Configuration + "/" + model.Population
		known := false
		for _, row := range canonicalCoordinates(Mailbox) {
			known = known || row.Population == "classifier" && row.ID == model.Configuration
		}
		if !known || seen[key] || model.Population != "request" && model.Population != "record" || !digestPattern.MatchString(model.Digest) {
			return false
		}
		seen[key] = true
	}
	return true
}

func plannedIncidentCounts(search []PairedPowerPlan) map[string]int {
	counts := make(map[string]int, nodeFamilySize)
	ids := differenceIDs()
	for i := range 9 {
		counts[ids[i]] = max(30, search[i].SelectedN)
	}
	for _, i := range []int{9, 11} {
		n := max(30, search[i].SelectedN, search[i+1].SelectedN)
		counts[ids[i]], counts[ids[i+1]] = n, n
	}
	return counts
}

func configurationIncidentCount(row Coordinate, counts map[string]int) (int, bool) {
	if row.Population == "link" {
		n, ok := counts[row.ID]
		return n, ok
	}
	if row.Population == "classifier" {
		period, _, ok := strings.Cut(row.ID, "-C")
		if ok {
			n, found := counts[period+"-request"]
			return n, found
		}
	}
	return 0, false
}

func samePowerPoint(input PowerCalculation, point PairedPowerPoint) bool {
	return input.N == point.N && input.Successes == point.Successes && input.Simulations == point.Simulations && input.Low == point.Low && input.High == point.High
}

func powerCalculation(input PowerCalculation, point PairedPowerPoint) PowerCalculation {
	input.N, input.Successes, input.Simulations, input.Low, input.High = point.N, point.Successes, point.Simulations, point.Low, point.High
	return input
}

func sealPlanningSuccessor(p *Plan) error {
	p.ParentDigest, p.Digest = p.Digest, ""
	b, err := json.Marshal(p)
	if err != nil {
		return ErrInvalid
	}
	p.Digest = publicHash(b)
	return nil
}

func clonePlanningPlan(p Plan) Plan {
	p.ModelFamily.IDs = append([]string(nil), p.ModelFamily.IDs...)
	p.DifferenceFamily.IDs = append([]string(nil), p.DifferenceFamily.IDs...)
	p.Configurations = append([]Coordinate(nil), p.Configurations...)
	for i := range p.Configurations {
		p.Configurations[i].Controlled = append([]int(nil), p.Configurations[i].Controlled...)
		p.Configurations[i].ForeignPositions = append([]int(nil), p.Configurations[i].ForeignPositions...)
	}
	p.WindowsNS = append([]int64(nil), p.WindowsNS...)
	p.FrozenModels = append([]ModelReference(nil), p.FrozenModels...)
	p.Samples = append([]SampleCalculation(nil), p.Samples...)
	p.Powers = append([]PowerCalculation(nil), p.Powers...)
	for i := range p.Powers {
		p.Powers[i].PilotX = append([]float64(nil), p.Powers[i].PilotX...)
		p.Powers[i].PilotY = append([]float64(nil), p.Powers[i].PilotY...)
	}
	p.PowerSearch = append([]PairedPowerPlan(nil), p.PowerSearch...)
	for i := range p.PowerSearch {
		p.PowerSearch[i].Search = append([]PairedPowerPoint(nil), p.PowerSearch[i].Search...)
	}
	return p
}
