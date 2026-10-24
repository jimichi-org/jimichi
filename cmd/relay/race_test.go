//go:build race

package main

// the race detector slows signature checks by two orders of magnitude on the
// CI runner, so the long simulations keep inside the package timeout there
const raceDetector = true
