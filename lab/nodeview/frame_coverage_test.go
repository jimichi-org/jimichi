package nodeview

import "testing"

func TestMeasuredCompleteIncomingFrameCannotDisappearFromP1(t *testing.T) {
	for _, callback := range []int64{99, 150, 200, 210} {
		c := providerIOCollector(t)
		c.begin(100, 200)
		var body [528]byte
		c.view.frames = append(c.view.frames, frameView{connection: 1, direction: 0, time: callback, data: c.copy(body[:])})
		e := c.freeze()
		if callback >= 100 && callback < 200 {
			if reasonOf(e) != ReasonContract {
				t.Fatal("measured complete frame silently omitted after failed Open")
			}
		} else if e != nil {
			t.Fatal("unmeasured terminal frame promoted into measured provenance")
		}
		if len(c.arena.bytes(c.view.frames[0].data)) != 528 {
			t.Fatal("unacknowledged equality buffer lost")
		}
	}
}
