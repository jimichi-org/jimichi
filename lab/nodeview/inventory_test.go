package nodeview

import "testing"

func TestCohortInventoriesRejectBeforeNextAppend(t *testing.T) {
	for _, row := range []struct {
		kind  uint8
		limit int
	}{{1, maxMessages}, {2, maxContexts}, {3, maxTruthRecords}, {4, maxSelectedCells}, {5, maxSelectedCells}} {
		i := cohortInventory{}
		for at := 0; at < row.limit; {
			n := min(128, row.limit-at)
			if i.reserveTruth(row.kind, n) != nil {
				t.Fatal("exact cap rejected")
			}
			at += n
		}
		before := i
		if i.reserveTruth(row.kind, 1) == nil || i != before {
			t.Fatal("over-cap inventory committed")
		}
	}
}

func TestThirtyTwoChildrenCannotCopyDistinctSealOverflow(t *testing.T) {
	i := cohortInventory{}
	accepted := 0
	for child := 0; child < 32; child++ {
		for left := 1025; left > 0; {
			n := min(128, left)
			if i.reserveTruth(3, n) != nil {
				// 31*1025+7*128 = 32671 is the last complete accepted chunk.
				if accepted != 32671 || child != 31 {
					t.Fatal("wrong prospective reject boundary")
				}
				return
			}
			accepted += n
			left -= n
		}
	}
	t.Fatal("32800 distinct records reached copy")
}
