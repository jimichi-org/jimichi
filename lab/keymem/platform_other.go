//go:build !linux || !amd64

package keymem

import "context"

func Run(_ context.Context, c Config) (Report, error) {
	if e := c.validate(); e != nil {
		return Report{}, e
	}
	r := newReport(c)
	for i := range r.Trials {
		r.Trials[i].terminal("unsupported_platform")
	}
	_ = r.finish()
	return r, errControllerFailed
}

func MaybeRunChild(args []string) (bool, int) {
	if len(args) > 0 && args[0] == privateArg {
		return true, 2
	}
	return false, 0
}
