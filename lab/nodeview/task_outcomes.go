package nodeview

import "github.com/jimichi-org/jimichi/lab"

func unavailableTask(c Config, task executionTask, reason Reason) RunResult {
	if reason == ReasonNone {
		reason = ReasonIncomplete
	}
	planned := max(len(task.routes), task.plannedSides)
	if task.membership {
		planned = 1
	}
	missing := Number{Reason: reason}
	return RunResult{Configuration: task.coordinate.ID, Repeat: task.repeat, Phase: c.Phase, Seed: nodeSeed(c, coordinateID(task.coordinate.ID), uint64(task.repeat), 0, lab.StreamNodeMain), Counts: Counts{Planned: uint64(planned), Missing: uint64(planned)}, Flags: []Reason{reason}, QueueJoined: missing, PutQ: missing, PutBaseline: missing, RequestLDA: missing, RecordLDA: missing}
}
