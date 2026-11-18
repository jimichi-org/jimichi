//go:build !linux || !amd64

package nodeview

import (
	"context"
	"strings"
)

func run(context.Context, Config) (Report, error) { return Report{}, ErrUnsupported }
func MaybeRunChild(args []string) (bool, int) {
	for _, a := range args {
		if strings.HasPrefix(a, "--nodeview-child-v1") {
			return true, 2
		}
	}
	return false, 0
}
