package keymem

import (
	"os"
	"testing"
)

var testChildHook func([]string) (bool, int)

func TestMain(m *testing.M) {
	if testChildHook != nil {
		if handled, code := testChildHook(os.Args[1:]); handled {
			os.Exit(code)
		}
	}
	if handled, code := MaybeRunChild(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}
