//go:build linux && amd64

package nodeview

import (
	"math"
	"unsafe"
)

func taskOutputBound(task executionTask, models bool) outputTaskBound {
	bound := outputTaskBound{}
	if len(task.coordinate.Controlled) == 2 {
		n := min(maxConnections, max(len(task.routes), task.plannedSides))
		if task.coordinate.Topology == "peer" {
			n = maxConnections
		}
		bound.First, bound.Second = n, n
	}
	if models && task.coordinate.Population == "classifier" {
		bound.MailboxRows = maxTruthRecords
		bound.MailboxGroups = min(maxClients/2, max(len(task.routes), task.plannedSides)/2)
	}
	return bound
}

func prepareOutputResources(c Config, p Plan, tasks []executionTask) (Config, error) {
	bounds := make([]outputTaskBound, len(tasks))
	for i, task := range tasks {
		bounds[i] = taskOutputBound(task, p.TrainingReady)
	}
	plan, e := plannedOutputMemory(p, bounds)
	clear(bounds)
	if e != nil {
		return c, e
	}
	available, e := availableHostMemory()
	if e != nil {
		return c, e
	}
	c.publicTaskBytes = uint64(cap(tasks)) * uint64(unsafe.Sizeof(executionTask{}))
	if e = checkOutputHost(plan, available, 320<<20); e != nil {
		return c, e
	}
	c.hostCapacity = &hostCapacity{available: available, output: plan}
	c.outputBudget = &memoryBudget{limit: plan.RetainedBytes, beforeAllocation: c.hostCapacity.checkGrowth}
	return c, nil
}

func preflightTaskDescriptors(c Config, p Plan) error {
	n, e := plannedTaskCount(c, p)
	if e != nil {
		return e
	}
	bytes := uint64(n) * uint64(unsafe.Sizeof(executionTask{})) * 4
	available, e := availableHostMemory()
	if e != nil {
		return e
	}
	if bytes > math.MaxUint64-(controllerArenaBytes+8<<20) || bytes+(controllerArenaBytes+8<<20) > available {
		return fail(ReasonLimit)
	}
	return nil
}

func (h *hostCapacity) checkObserved(f *fixture) error {
	if h == nil {
		return nil
	}
	for _, child := range f.children {
		if !child.reaped {
			return fail(ReasonChild)
		}
		h.maxProcess = max(h.maxProcess, child.maxRSS)
	}
	controller, e := selfRSS()
	if e != nil {
		return e
	}
	h.maxProcess = max(h.maxProcess, controller)
	return h.checkGrowth(0)
}

func currentHostGrowth(n uint64, probe func() (uint64, error)) error {
	available, e := probe()
	if e != nil {
		return e
	}
	if n > available {
		return attachBound(fail(ReasonLimit), boundDetail{origin: boundHostHeadroom, unit: boundBytes, need: n, limit: available})
	}
	return nil
}

func (h *hostCapacity) checkGrowth(n uint64) error {
	if h == nil {
		return nil
	}
	return currentHostGrowth(n, availableHostMemory)
}

func (h *hostCapacity) cohort(retained uint64, sides int) error {
	if retained > controllerArenaBytes || sides < 0 || sides > maxClients {
		return fail(ReasonLimit)
	}
	return h.checkGrowth(uint64(controllerArenaBytes) - retained + 5*relayArenaBytes + uint64(sides)*clientArenaBytes)
}
