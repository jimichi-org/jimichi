//go:build !linux

package vault

// linux is the only target; Windows cannot flush a directory handle
func syncDir(string) error { return nil }
