package nodeview

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if handled, code := MaybeRunChild(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}
