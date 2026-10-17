package lab

import "sync"

// which data cells of one flow carried a message, in the order its client
// sealed them; the scoring reads it, the observer never could
type Labels struct {
	mu    sync.Mutex
	cells []bool
	odd   bool
}

func NewLabels(cells ...bool) *Labels {
	return &Labels{cells: append([]bool(nil), cells...)}
}

// ok is false when the oracle saw what it cannot account for: a second AEAD
// on the exit's key, or a seal there without a data cell's associated data
// at the exit's position
func (l *Labels) Cells() (cells []bool, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]bool(nil), l.cells...), !l.odd
}

func (l *Labels) add(payload bool) {
	l.mu.Lock()
	l.cells = append(l.cells, payload)
	l.mu.Unlock()
}

func (l *Labels) markOdd() {
	l.mu.Lock()
	l.odd = true
	l.mu.Unlock()
}
