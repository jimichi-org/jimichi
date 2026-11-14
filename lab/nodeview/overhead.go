package nodeview

import "math"

func (c *collector) recordLocked(start int64, call bool) {
	end := c.now()
	if start < 0 || end < start {
		c.observerValid = false
		c.fail(ReasonClock)
		return
	}
	elapsed := uint64(end - start)
	if math.MaxUint64-c.summary.CallbackNS < elapsed || call && c.summary.Calls == math.MaxUint64 {
		c.observerValid = false
		c.fail(ReasonLimit)
		return
	}
	c.summary.CallbackNS += elapsed
	if call {
		c.summary.Calls++
	}
}
func (c *collector) record(start int64, call bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recordLocked(start, call)
}
func (c *collector) inventory() {
	c.summary.ArenaHighWater = max(c.summary.ArenaHighWater, uint64(c.arena.high))
	c.summary.ConnectionsHighWater = max(c.summary.ConnectionsHighWater, uint64(len(c.view.connections)))
	c.summary.PendingHighWater = max(c.summary.PendingHighWater, uint64(c.pending()))
	c.summary.ContextsHighWater = max(c.summary.ContextsHighWater, uint64(len(c.keys)+len(c.view.setups)))
	c.summary.CellsHighWater = max(c.summary.CellsHighWater, uint64(len(c.view.cells)))
	if c.summary.ContextsHighWater > maxContexts || c.summary.PendingHighWater > maxPendingFrames {
		c.fail(ReasonLimit)
	}
}
