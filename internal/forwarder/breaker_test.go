package forwarder

import (
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_000_000, 0)} }

// consecOnly disables the ratio signal so a test isolates consecutive-failure trips.
func consecOnly(n int) Policy {
	return Policy{Window: 30 * time.Second, Buckets: 6, MinSamples: 1 << 30, FailRatio: 2,
		ConsecFail: n, Cooldown: 5 * time.Second, HalfOpenMax: 1}
}

// ratioOnly disables the consecutive signal so a test isolates ratio trips.
func ratioOnly(min int, ratio float64) Policy {
	return Policy{Window: 30 * time.Second, Buckets: 6, MinSamples: min, FailRatio: ratio,
		ConsecFail: 0, Cooldown: 5 * time.Second, HalfOpenMax: 1}
}

func TestBreakerConsecutiveTripAndRecover(t *testing.T) {
	clk := newClock()
	b := newBreaker(consecOnly(3), clk.now)

	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("request %d should be allowed while closed", i)
		}
		b.record(false)
	}
	if b.allow() {
		t.Fatal("breaker should be OPEN after 3 consecutive failures")
	}
	// Still within cooldown → denied.
	clk.advance(4 * time.Second)
	if b.allow() {
		t.Fatal("breaker should still be open during cooldown")
	}
	// Cooldown elapsed → one half-open probe admitted, extras denied.
	clk.advance(2 * time.Second)
	if !b.allow() {
		t.Fatal("breaker should admit a half-open probe after cooldown")
	}
	if b.allow() {
		t.Fatal("half-open must admit at most HalfOpenMax probes")
	}
	// Probe succeeds → closed again.
	b.record(true)
	if !b.allow() {
		t.Fatal("breaker should be CLOSED after a successful probe")
	}
}

func TestBreakerHalfOpenProbeFailureReopens(t *testing.T) {
	clk := newClock()
	b := newBreaker(consecOnly(2), clk.now)
	b.record(false)
	b.record(false) // open
	clk.advance(5 * time.Second)
	if !b.allow() {
		t.Fatal("expected a half-open probe")
	}
	b.record(false) // probe fails → reopen
	if b.allow() {
		t.Fatal("a failed probe must reopen the breaker (deny during new cooldown)")
	}
	clk.advance(5 * time.Second)
	if !b.allow() {
		t.Fatal("should probe again after the second cooldown")
	}
}

func TestBreakerRatioTripsOnFlapping(t *testing.T) {
	clk := newClock()
	b := newBreaker(ratioOnly(10, 0.5), clk.now)
	// Alternate ok/fail: never 2 failures in a row, but 50% over 10 samples.
	for i := 0; i < 10; i++ {
		if !b.allow() {
			t.Fatalf("flap sample %d denied early", i)
		}
		b.record(i%2 == 0) // 5 ok, 5 fail
	}
	if b.allow() {
		t.Fatal("breaker should trip on a 50%% failure ratio over the window (flapping)")
	}
}

func TestBreakerMinSamplesFloor(t *testing.T) {
	clk := newClock()
	b := newBreaker(ratioOnly(10, 0.5), clk.now)
	// One failure: ratio 1.0 but only 1 sample (< MinSamples) → must not trip.
	b.record(false)
	if !b.allow() {
		t.Fatal("breaker must not trip below MinSamples (1/1 is not a signal)")
	}
}

func TestBreakerWindowAgesOut(t *testing.T) {
	clk := newClock()
	b := newBreaker(ratioOnly(4, 0.9), clk.now)
	b.record(false)
	b.record(false)
	b.record(false) // 3 failures, below MinSamples=4 → closed
	if !b.allow() {
		t.Fatal("3 failures < MinSamples should not trip")
	}
	clk.advance(31 * time.Second) // past the 30s window → old failures age out
	b.record(false)               // a single fresh failure; total in-window is now 1
	if !b.allow() {
		t.Fatal("aged-out failures must not accumulate toward a trip")
	}
}

func TestBreakerResetsWindowOnRecovery(t *testing.T) {
	clk := newClock()
	// consec trips fast; ratio would also fire if stale fails survived recovery.
	b := newBreaker(Policy{Window: 30 * time.Second, Buckets: 6, MinSamples: 3, FailRatio: 0.5,
		ConsecFail: 3, Cooldown: 5 * time.Second, HalfOpenMax: 1}, clk.now)
	b.record(false)
	b.record(false)
	b.record(false) // open (3 fails also in-window)
	clk.advance(5 * time.Second)
	b.allow()      // half-open probe
	b.record(true) // recover → window reset
	// One fresh failure must not re-trip on the stale 3 (they were cleared).
	b.record(false)
	if !b.allow() {
		t.Fatal("window must reset on recovery so stale failures don't re-trip")
	}
}
