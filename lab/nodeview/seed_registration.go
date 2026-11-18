package nodeview

import (
	"context"
	"encoding/binary"
)

func RegisterMainSeed(ctx context.Context, p Plan, seed int64) (Plan, error) {
	if ctx.Err() != nil {
		return Plan{}, fail(ReasonPlanning)
	}
	if p.Digest == "" || p.MainSeedCommitment != "" || p.Phase == Primary || ValidatePlan(p) != nil || !mainSeedReadyPlan(p) {
		return Plan{}, ErrInvalid
	}
	if err := validateRegisteredPlanning(ctx, p); err != nil {
		return Plan{}, err
	}
	commitment, err := mainSeedCommitment(p, seed)
	if err != nil {
		return Plan{}, err
	}
	out := clonePlanningPlan(p)
	out.MainSeedCommitment = commitment
	if err = sealPlanningSuccessor(&out); err != nil {
		return Plan{}, err
	}
	return out, nil
}

func mainSeedReadyPlan(p Plan) bool {
	if p.Suite == "gost" {
		if p.PilotReady || p.ModelReady || len(p.Samples) != 0 || len(p.Powers) != 0 || len(p.PowerSearch) != 0 {
			return false
		}
		if p.Set == Mailbox {
			return (p.Phase == Train || p.Phase == Primary) && p.TrainingReady && validPlanningModels(p.FrozenModels)
		}
		return (p.Set == Compromise || p.Set == Collude) && (p.Phase == Structural || p.Phase == Primary) && !p.TrainingReady && len(p.FrozenModels) == 0
	}
	if p.Suite != "c25519" || p.Phase != Pilot && p.Phase != Primary {
		return false
	}
	if p.Set == Compromise {
		return p.ModelReady && !p.PilotReady && !p.TrainingReady && len(p.FrozenModels) == 0
	}
	return (p.Set == Collude || p.Set == Mailbox) && p.PilotReady && p.TrainingReady && !p.ModelReady && len(p.Samples) == 0 && validPlanningModels(p.FrozenModels)
}

func mainSeedCommitment(p Plan, seed int64) (string, error) {
	input, err := mainSeedInput(p, seed)
	if err != nil {
		return "", err
	}
	return publicHash(input[:]), nil
}

func mainSeedInput(p Plan, seed int64) ([187]byte, error) {
	var input [187]byte
	if !revisionPattern.MatchString(p.Revision) || !revisionPattern.MatchString(p.Tree) || !digestPattern.MatchString(p.BinarySHA256) || p.SeedDomainVersion != 22 {
		return input, ErrInvalid
	}
	suiteID := byte(0)
	switch p.Suite {
	case "c25519":
		suiteID = 1
	case "gost":
		suiteID = 2
	default:
		return input, ErrInvalid
	}
	setID := byte(0)
	switch p.Set {
	case Compromise:
		setID = 1
	case Collude:
		setID = 2
	case Mailbox:
		setID = 3
	default:
		return input, ErrInvalid
	}
	at := copy(input[:], "jimichi-nodeview-main-seed-v1\x00")
	for _, field := range []string{p.Revision, p.Tree, p.BinarySHA256} {
		at += copy(input[at:], field)
	}
	input[at], input[at+1] = suiteID, setID
	binary.BigEndian.PutUint16(input[at+2:at+4], uint16(p.SeedDomainVersion))
	input[at+4] = 4
	binary.BigEndian.PutUint64(input[at+5:], uint64(seed))
	return input, nil
}
