//go:build linux && amd64

package nodeview

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/crypto/secmem"
)

func TestActorObserverJoinRetainsOwnedBuffersUntilBothCallbacksReturn(t *testing.T) {
	for _, failure := range []Reason{ReasonIPC, ReasonCancelled} {
		ctx, cancel := context.WithCancel(context.Background())
		arena, e := newArena(4096)
		if e != nil {
			t.Fatal(e)
		}
		fetch, e := secmem.New(32)
		if e != nil {
			arena.close()
			t.Fatal(e)
		}
		fetch.Bytes()[0] = 73
		ref, ok := arena.copy([]byte{17, 23, 31})
		if !ok {
			t.Fatal("owned arena initialization failed")
		}
		work, reads := make(chan error, 1), make(chan struct{})
		entered := make(chan struct{})
		var closes atomic.Int32
		lifetime := &observerLifetime{cancel: cancel, close: func() { closes.Add(1); close(entered) }, workDone: work, readDone: reads}
		t.Cleanup(func() {
			cancel()
			select {
			case <-reads:
			default:
				close(reads)
			}
			select {
			case work <- fail(ReasonCancelled):
			default:
			}
			_ = lifetime.join()
			fetch.Release()
			arena.close()
		})
		cleaned := make(chan error, 1)
		go func() {
			result := lifetime.join()
			fetch.Release()
			arena.close()
			cleaned <- result
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("observer cancellation did not begin")
		}
		if ctx.Err() == nil || closes.Load() != 1 || fetch.Len() == 0 || fetch.Bytes()[0] != 73 || !arena.valid(ref) {
			t.Fatal("observer cancellation released still-owned buffers")
		}
		select {
		case <-cleaned:
			t.Fatal("observer cleanup overtook held callbacks")
		default:
		}
		close(reads)
		select {
		case <-cleaned:
			t.Fatal("observer cleanup overtook the held workload result")
		default:
		}
		if fetch.Len() == 0 || arena.buffer == nil {
			t.Fatal("owned storage released before workload callback returned")
		}
		select {
		case work <- fail(failure):
		case <-time.After(5 * time.Second):
			t.Fatal("observer did not consume its workload result")
		}
		select {
		case result := <-cleaned:
			if reasonOf(result) != failure || fetch.Len() != 0 || arena.buffer != nil {
				t.Fatal("observer cleanup lost its result or retained buffers after join")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("observer did not finish after both callbacks returned")
		}
		if reasonOf(lifetime.join()) != failure || closes.Load() != 1 {
			t.Fatal("repeated observer join consumed a result or closed twice")
		}
	}
}
