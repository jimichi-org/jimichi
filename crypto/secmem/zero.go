package secmem

import (
	"runtime"
	"runtime/debug"
)

// KeepAlive stops the compiler from dropping a clearing loop whose result is
// never read
func zero(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	runtime.KeepAlive(b)
}

// clears a heap copy of key material unless the policy has zeroing off, which
// only a baseline run does
func Zero(b []byte) {
	if CurrentPolicy().Zero {
		zero(b)
	}
}

// for a library that leaves a large working state derived from a secret on
// the heap, such as the Argon2id matrix: under zeroing the collector hands the
// freed pages back to the kernel at once, so a later dump of the process does
// not hold them. A heuristic, not a wipe: memory still referenced and pages
// already written to swap stay as they are
func ReturnFreed() {
	if CurrentPolicy().Zero {
		debug.FreeOSMemory()
	}
}
