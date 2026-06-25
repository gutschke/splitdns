package forwarder

import (
	"sync"
	"time"
)

// A per-upstream circuit breaker. It fails fast on an upstream that is down or
// badly degraded so the forwarder can move on to a healthy one instead of paying a
// timeout per query (and starving the per-request budget — see Forward). Two trip
// signals are combined:
//
//   - consecutive failures: a fast trip for a hard-down upstream;
//   - rolling-window failure RATIO: catches a flapping upstream (ok/fail/ok/fail)
//     that never reaches N-in-a-row but is clearly degrading service.
//
// The window is bucketed over time so old failures age out; it accumulates only
// while CLOSED and is reset on the transition back to closed, so a recovered
// upstream starts from a clean slate (and a flap can still accrue a tripping ratio).
//
// This is a self-contained ~1-file implementation (no external breaker dependency,
// keeping the build's minimal-vendor / reduced supply-chain surface).

type cbState int

const (
	cbClosed cbState = iota
	cbOpen
	cbHalfOpen
)

// Policy tunes the breaker. The zero value is not valid; use DefaultPolicy.
type Policy struct {
	Window      time.Duration // rolling window length for the failure-ratio signal
	Buckets     int           // window granularity (>=1)
	MinSamples  int           // don't evaluate the ratio below this many requests in-window
	FailRatio   float64       // trip (closed→open) when failures/total >= this
	ConsecFail  int           // OR trip after this many consecutive failures (0 disables)
	Cooldown    time.Duration // open→half-open after this much time
	HalfOpenMax int           // probes admitted while half-open (>=1)
}

// DefaultPolicy returns conservative defaults: a hard-down upstream trips after 5
// failures in a row; a flapping one trips at >=50% failures over a 30s window once
// at least 10 requests are seen; recovery is probed 5s after opening.
func DefaultPolicy() Policy {
	return Policy{
		Window: 30 * time.Second, Buckets: 6, MinSamples: 10, FailRatio: 0.5,
		ConsecFail: 5, Cooldown: 5 * time.Second, HalfOpenMax: 1,
	}
}

type cbBucket struct{ ok, fail int }

type breaker struct {
	pol Policy
	now func() time.Time

	mu        sync.Mutex
	state     cbState
	consec    int
	openedAt  time.Time
	halfOpen  int // probes admitted since entering half-open
	buckets   []cbBucket
	bucketDur time.Duration
	headStart time.Time // start time of the current head bucket
	headIdx   int
}

func newBreaker(pol Policy, now func() time.Time) *breaker {
	if pol.Buckets < 1 {
		pol.Buckets = 1
	}
	if pol.HalfOpenMax < 1 {
		pol.HalfOpenMax = 1
	}
	return &breaker{
		pol: pol, now: now,
		buckets:   make([]cbBucket, pol.Buckets),
		bucketDur: pol.Window / time.Duration(pol.Buckets),
	}
}

// allow reports whether a request may be sent to this upstream. A half-open probe is
// reserved when returning true in the open→half-open transition.
func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case cbOpen:
		if b.now().Sub(b.openedAt) >= b.pol.Cooldown {
			b.state = cbHalfOpen
			b.halfOpen = 1
			return true
		}
		return false
	case cbHalfOpen:
		if b.halfOpen < b.pol.HalfOpenMax {
			b.halfOpen++
			return true
		}
		return false
	default: // cbClosed
		return true
	}
}

// record reports the outcome of an allowed request and drives state transitions.
func (b *breaker) record(ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	b.advanceLocked(t)
	if ok {
		b.buckets[b.headIdx].ok++
		b.consec = 0
		if b.state != cbClosed {
			b.closeLocked() // recovery: probe (or forced-pass) succeeded
		}
		return
	}
	b.buckets[b.headIdx].fail++
	b.consec++
	switch b.state {
	case cbHalfOpen:
		b.trip(t) // probe failed → reopen
	case cbClosed:
		if b.shouldTripLocked() {
			b.trip(t)
		}
	}
}

func (b *breaker) trip(t time.Time) {
	b.state = cbOpen
	b.openedAt = t
	b.halfOpen = 0
}

func (b *breaker) closeLocked() {
	b.state = cbClosed
	b.halfOpen = 0
	for i := range b.buckets {
		b.buckets[i] = cbBucket{}
	}
	b.headStart = time.Time{} // re-seed on next advance
}

// shouldTripLocked evaluates the trip predicate over the current window.
func (b *breaker) shouldTripLocked() bool {
	if b.pol.ConsecFail > 0 && b.consec >= b.pol.ConsecFail {
		return true
	}
	var ok, fail int
	for _, bk := range b.buckets {
		ok += bk.ok
		fail += bk.fail
	}
	total := ok + fail
	return total >= b.pol.MinSamples && float64(fail)/float64(total) >= b.pol.FailRatio
}

// status returns a read-only health snapshot at time t (for diagnostics). state is
// "closed" (healthy), "open" (tripped, failing fast), or "half-open" (probing recovery);
// ratio is the in-window failure ratio; openFor/cooldownLeft are meaningful when tripped.
func (b *breaker) status(t time.Time) (state string, consec int, ratio float64, openFor, cooldownLeft time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var ok, fail int
	for _, bk := range b.buckets {
		ok += bk.ok
		fail += bk.fail
	}
	if total := ok + fail; total > 0 {
		ratio = float64(fail) / float64(total)
	}
	consec = b.consec
	switch b.state {
	case cbOpen:
		state = "open"
		openFor = t.Sub(b.openedAt)
		if rem := b.pol.Cooldown - openFor; rem > 0 {
			cooldownLeft = rem
		}
	case cbHalfOpen:
		state = "half-open"
		openFor = t.Sub(b.openedAt)
	default:
		state = "closed"
	}
	return
}

// advanceLocked rolls the window head forward to time t, clearing aged-out buckets.
func (b *breaker) advanceLocked(t time.Time) {
	if b.headStart.IsZero() {
		b.headStart = t
		return
	}
	elapsed := t.Sub(b.headStart)
	if elapsed >= b.pol.Window {
		for i := range b.buckets {
			b.buckets[i] = cbBucket{}
		}
		b.headStart = t
		b.headIdx = 0
		return
	}
	for elapsed >= b.bucketDur {
		b.headIdx = (b.headIdx + 1) % len(b.buckets)
		b.buckets[b.headIdx] = cbBucket{}
		b.headStart = b.headStart.Add(b.bucketDur)
		elapsed -= b.bucketDur
	}
}
