//go:build (!linux || !amd64) && !windows

package nodeview

func availableHostMemory() (uint64, error) {
	return 0, ErrUnsupported
}
