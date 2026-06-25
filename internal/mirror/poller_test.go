package mirror

import (
	"context"
	"testing"
	"time"
)

// ctrlFetcher returns a controllable serial for a single zone.
type ctrlFetcher struct {
	serial uint32
	err    error
	calls  int
}

func (c *ctrlFetcher) Serial(context.Context, string) (uint32, error) {
	c.calls++
	return c.serial, c.err
}

// TestPollerExactlyOneRefresh is the design's §2.5 L0 contract: poll serial N with
// no prior fetch ⇒ fetch; poll N again ⇒ no fetch; poll N+1 ⇒ fetch exactly once.
func TestPollerExactlyOneRefresh(t *testing.T) {
	f := &ctrlFetcher{serial: 100}
	var refreshes int
	var lastObserved map[string]uint32
	refresh := func(_ context.Context, observed map[string]uint32) error {
		refreshes++
		lastObserved = observed
		return nil
	}
	now := time.Unix(5_000_000, 0)
	p := NewPoller([]string{"example.com"}, f, nil, refresh, time.Minute, time.Hour, func() time.Time { return now }, nil)
	ctx := context.Background()

	p.cycle(ctx) // cold: serial 100, never fetched => MUST fetch
	if refreshes != 1 {
		t.Fatalf("cold cycle: refreshes=%d, want 1", refreshes)
	}
	if lastObserved["example.com"] != 100 {
		t.Fatalf("observed serial not passed to refresh: %v", lastObserved)
	}

	p.cycle(ctx) // serial unchanged => MUST NOT fetch
	if refreshes != 1 {
		t.Fatalf("unchanged serial triggered a refresh: refreshes=%d", refreshes)
	}

	f.serial = 101
	p.cycle(ctx) // serial bumped => MUST fetch exactly once
	if refreshes != 2 {
		t.Fatalf("bumped serial: refreshes=%d, want 2", refreshes)
	}
}

func TestPollerForcedRefresh(t *testing.T) {
	f := &ctrlFetcher{serial: 100}
	var refreshes int
	refresh := func(context.Context, map[string]uint32) error { refreshes++; return nil }
	now := time.Unix(6_000_000, 0)
	clock := func() time.Time { return now }
	p := NewPoller([]string{"example.com"}, f, nil, refresh, time.Minute, 6*time.Hour, clock, nil)
	ctx := context.Background()

	p.cycle(ctx) // initial fetch
	if refreshes != 1 {
		t.Fatalf("initial: %d", refreshes)
	}
	now = now.Add(time.Hour) // unchanged serial, within forced window
	p.cycle(ctx)
	if refreshes != 1 {
		t.Fatalf("within forced window must not refresh: %d", refreshes)
	}
	now = now.Add(6 * time.Hour) // past the forced full-refresh interval
	p.cycle(ctx)
	if refreshes != 2 {
		t.Fatalf("forced refresh did not fire: %d", refreshes)
	}
}

// A warm restart MUST do exactly one reconciling refresh on the first cycle even when
// the serial is unchanged: the warm snapshot is published Stale/CFHealthy=false, so
// without this reconcile the daemon serves correct-but-flagged-stale data forever
// (regression guard — the live mirror showed "degraded (serving stale)" for 8h after a
// restart although the read token was fine, because every observed serial matched the
// cache). After the single reconcile, a still-unchanged serial must NOT refetch — that
// is where the warm cache's value is realized.
func TestPollerWarmReconcilesOnceThenIdles(t *testing.T) {
	f := &ctrlFetcher{serial: 100}
	var refreshes int
	refresh := func(context.Context, map[string]uint32) error { refreshes++; return nil }
	now := time.Unix(7_000_000, 0)
	seed := map[string]SerialState{"example.com": {Last: 100, Fetched: true}}
	p := NewPoller([]string{"example.com"}, f, seed, refresh, time.Minute, 6*time.Hour, func() time.Time { return now }, nil)
	ctx := context.Background()

	p.cycle(ctx) // warm + unchanged serial: MUST reconcile once to clear the stale flags
	if refreshes != 1 {
		t.Fatalf("warm first cycle must reconcile exactly once, got %d", refreshes)
	}
	p.cycle(ctx) // still unchanged, no longer the first cycle: cache value holds, no refetch
	if refreshes != 1 {
		t.Fatalf("unchanged serial after the reconcile must not refetch, got %d", refreshes)
	}
}

// A first cycle whose serial query fails entirely must NOT force a reconcile: with no
// observed serial we keep serving the warm snapshot rather than hammering a dead
// upstream. This is the boundary that keeps the first-cycle reconcile from regressing
// into "rebuild on every transient outage."
func TestPollerWarmSerialOutageKeepsState(t *testing.T) {
	f := &ctrlFetcher{err: context.DeadlineExceeded}
	var refreshes int
	refresh := func(context.Context, map[string]uint32) error { refreshes++; return nil }
	now := time.Unix(7_500_000, 0)
	seed := map[string]SerialState{"example.com": {Last: 100, Fetched: true}}
	p := NewPoller([]string{"example.com"}, f, seed, refresh, time.Minute, 6*time.Hour, func() time.Time { return now }, nil)

	p.cycle(context.Background())
	if refreshes != 0 {
		t.Fatalf("first cycle with a serial outage must not reconcile, got %d", refreshes)
	}
}

// A quiet-but-healthy mirror (stable serials, upstream reachable) must keep CONFIRMING
// currency every cycle — otherwise the watchdog mistakes "hasn't rebuilt lately" for
// "stale" and force-restarts it (the 55-restarts bug).
func TestPollerConfirmsWhenCurrent(t *testing.T) {
	f := &ctrlFetcher{serial: 100}
	refresh := func(context.Context, map[string]uint32) error { return nil }
	now := time.Unix(7_000_000, 0)
	seed := map[string]SerialState{"example.com": {Last: 100, Fetched: true}}
	p := NewPoller([]string{"example.com"}, f, seed, refresh, time.Minute, 6*time.Hour, func() time.Time { return now }, nil)
	var confirms int
	p.confirm = func() { confirms++ }
	ctx := context.Background()

	p.cycle(ctx) // first cycle reconciles + rebuilds => confirm
	if confirms != 1 {
		t.Fatalf("first cycle confirms=%d, want 1", confirms)
	}
	p.cycle(ctx) // serial unchanged, no rebuild, but upstream reachable => still current
	if confirms != 2 {
		t.Errorf("quiet healthy cycle confirms=%d, want 2 (a current mirror must not look stale)", confirms)
	}
}

// A total serial-query outage must NOT confirm currency — we can't vouch for it, so the
// watchdog is allowed to escalate.
func TestPollerNoConfirmOnUpstreamOutage(t *testing.T) {
	f := &ctrlFetcher{err: context.DeadlineExceeded}
	refresh := func(context.Context, map[string]uint32) error { return nil }
	now := time.Unix(8_500_000, 0)
	p := NewPoller([]string{"example.com"}, f, nil, refresh, time.Minute, 6*time.Hour, func() time.Time { return now }, nil)
	var confirms int
	p.confirm = func() { confirms++ }
	p.cycle(context.Background())
	if confirms != 0 {
		t.Errorf("serial outage confirms=%d, want 0 (cannot vouch for currency)", confirms)
	}
}

func TestPollerFetchErrorKeepsState(t *testing.T) {
	f := &ctrlFetcher{err: context.DeadlineExceeded}
	var refreshes int
	refresh := func(context.Context, map[string]uint32) error { refreshes++; return nil }
	now := time.Unix(8_000_000, 0)
	p := NewPoller([]string{"example.com"}, f, nil, refresh, time.Minute, 6*time.Hour, func() time.Time { return now }, nil)
	p.cycle(context.Background())
	if refreshes != 0 {
		t.Errorf("a serial-query error must not trigger a refresh, got %d", refreshes)
	}
}
