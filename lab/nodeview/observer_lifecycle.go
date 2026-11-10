package nodeview

import (
	"context"
	"sync"
)

type observerLifetime struct {
	once     sync.Once
	cancel   context.CancelFunc
	close    func()
	workDone <-chan error
	readDone <-chan struct{}
	result   error
}

func (l *observerLifetime) join() error {
	l.once.Do(func() {
		l.cancel()
		l.close()
		<-l.readDone
		l.result = <-l.workDone
	})
	return l.result
}
