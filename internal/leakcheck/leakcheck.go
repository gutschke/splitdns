// Package leakcheck is a tiny, dependency-free goroutine-leak detector for the chaos
// and reliability tests (replacing an external goleak dep, in keeping with the
// project's minimal-vendor posture). Capture a Baseline before starting a subsystem,
// tear the subsystem down, then AssertNoLeak: it polls until the goroutine count
// returns to the baseline, and on timeout dumps the lingering stacks.
package leakcheck

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// settleDelay lets just-spawned/just-stopped goroutines reach a stable count.
const settleDelay = 20 * time.Millisecond

// Baseline returns a settled goroutine count to compare against later.
func Baseline() int {
	return settle()
}

func settle() int {
	prev := -1
	for i := 0; i < 50; i++ {
		runtime.Gosched()
		n := runtime.NumGoroutine()
		if n == prev {
			return n
		}
		prev = n
		time.Sleep(settleDelay)
	}
	return runtime.NumGoroutine()
}

// AssertNoLeak fails t if the goroutine count has not returned to <= baseline within
// the timeout. Teardown goroutines exit asynchronously, so it polls before failing.
func AssertNoLeak(t testing.TB, baseline int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("goroutine leak: %d running, baseline %d\n%s", n, baseline, dumpStacks())
			return
		}
		time.Sleep(settleDelay)
	}
}

func dumpStacks() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	s := string(buf[:n])
	// Trim to keep the failure readable; the head holds the leaked goroutines.
	if len(s) > 8000 {
		s = s[:8000] + "\n...[truncated]"
	}
	return strings.TrimSpace(s)
}
