package perf

import (
	"os"
	"testing"
)

// the child of these tests is the test binary itself
func TestMain(m *testing.M) {
	if handled, code := MaybeRunChild(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}
