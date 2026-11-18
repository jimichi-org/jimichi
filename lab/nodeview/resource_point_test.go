package nodeview

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestResourcePointIncludesPooledPeaksOnce(t *testing.T) {
	usage := &resourceUsage{}
	traffic := []uint64{1024, 2048, 3072, 2048, 1024}
	before := append([]uint64(nil), traffic...)
	for _, peak := range traffic {
		usage.start().record(peak, nil)
	}
	trainer, auditor := usage.start(), usage.start()
	trainer.record(6*1024, nil)
	auditor.record(7*1024, nil)
	auditor.record(100*1024, nil)
	point := usage.snapshot(4*1024, nil)
	// max(1,2,3,2,1,6,7,4) KiB = 7 * 1024 bytes, with no repeated contribution
	if !validResourcePoint(point) || point.MaxRSS == nil || *point.MaxRSS != 7168 || !reflect.DeepEqual(traffic, before) {
		t.Fatal("pooled resource maximum was omitted, duplicated or changed traffic")
	}
	usage.start().record(9*1024, nil)
	if *point.MaxRSS != 7168 || *usage.snapshot(4*1024, nil).MaxRSS != 9*1024 {
		t.Fatal("public resource snapshot aliases later private updates")
	}
	controller := usage.snapshot(12*1024, nil)
	if controller.MaxRSS == nil || *controller.MaxRSS != 12*1024 {
		t.Fatal("controller peak was not included by maximum")
	}
}

func TestResourcePointUnknownCoverageIsNotZero(t *testing.T) {
	for _, name := range []string{"pending", "usage", "controller"} {
		t.Run(name, func(t *testing.T) {
			usage := &resourceUsage{}
			ticket := usage.start()
			var sampleErr error
			want := ReasonChild
			switch name {
			case "usage":
				ticket.record(4096, fail(ReasonContract))
				want = ReasonContract
			case "controller":
				ticket.record(4096, nil)
				sampleErr = fail(ReasonUnsupported)
				want = ReasonUnsupported
			}
			point := usage.snapshot(2048, sampleErr)
			if !validResourcePoint(point) || point.MaxRSS != nil || point.Reason != want {
				t.Fatal("unknown resource coverage became a complete numeric maximum")
			}
			if name == "pending" {
				ticket.record(8192, nil)
				if point.MaxRSS != nil || point.Reason != ReasonChild {
					t.Fatal("late quarantine update changed a returned resource point")
				}
			}
		})
	}
}

func TestResourcePointPreservesIntegerAndSchema(t *testing.T) {
	value := uint64(1<<53 + 1)
	point := ResourcePoint{Scope: resourceScope, MaxRSS: &value}
	body, err := json.Marshal(point)
	if err != nil || string(body) != `{"scope":"owned-process-peaks-through-finalization-v1","max_rss":9007199254740993}` {
		t.Fatal("resource bytes were rounded through floating point")
	}
	for _, invalid := range []ResourcePoint{{}, {Scope: resourceScope}, {Scope: "other", MaxRSS: &value}, {Scope: resourceScope, MaxRSS: &value, Reason: ReasonChild}, {Scope: resourceScope, Reason: "unknown"}} {
		if validResourcePoint(invalid) {
			t.Fatal("invalid resource point accepted")
		}
	}
}
