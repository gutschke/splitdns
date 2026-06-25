package supervisor

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

func fastOpts() Options {
	return Options{StallCheckEvery: 15 * time.Millisecond, GracePeriod: 30 * time.Millisecond}
}

func TestPanicRecoveryAndRestart(t *testing.T) {
	var starts atomic.Int64
	run := func(ctx context.Context, progress func()) {
		n := starts.Add(1)
		progress()
		if n <= 2 {
			panic("boom")
		}
		<-ctx.Done() // stable run
	}
	s := New(fastOpts())
	s.Register(Worker{Name: "w", Backoff: 5 * time.Millisecond, Run: run})

	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	waitFor(t, func() bool { return starts.Load() >= 3 }, "worker restarted past its panics")
	if p := s.Stats()["w"].Panics; p < 2 {
		t.Errorf("panics counted = %d, want >= 2", p)
	}
	cancel()
}

// TestStallDetection injects a NON-panicking deadlock that IGNORES its context; the
// stall-detector must restart it anyway (the "blocked forever on an empty queue" class).
func TestStallDetection(t *testing.T) {
	var starts atomic.Int64
	run := func(ctx context.Context, progress func()) {
		starts.Add(1)
		progress() // one beat, then wedge forever ignoring ctx
		select {}  // deadlock that context cancellation cannot clear
	}
	s := New(fastOpts())
	s.Register(Worker{Name: "w", Ceiling: 40 * time.Millisecond, Backoff: 5 * time.Millisecond, Run: run})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, func() bool { return starts.Load() >= 2 }, "stalled worker restarted")
	if st := s.Stats()["w"].Stalls; st < 1 {
		t.Errorf("stalls counted = %d, want >= 1", st)
	}
}

func TestGracefulShutdown(t *testing.T) {
	var running atomic.Bool
	run := func(ctx context.Context, progress func()) {
		running.Store(true)
		progress()
		<-ctx.Done()
		running.Store(false)
	}
	s := New(fastOpts())
	s.Register(Worker{Name: "w", Run: run})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	waitFor(t, func() bool { return running.Load() }, "worker started")
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not stop on ctx cancel")
	}
}

func TestWatchdogGating(t *testing.T) {
	var notifies atomic.Int64
	var live atomic.Bool
	live.Store(true)
	s := New(Options{
		WatchdogEvery: 15 * time.Millisecond,
		Liveness:      func() bool { return live.Load() },
		Notify:        func() error { notifies.Add(1); return nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitFor(t, func() bool { return notifies.Load() > 0 }, "watchdog notifies while live")
	// Go unhealthy: notifies must stop.
	live.Store(false)
	frozen := notifies.Load()
	time.Sleep(120 * time.Millisecond)
	if got := notifies.Load(); got > frozen+1 {
		t.Errorf("watchdog kept pinging while unhealthy: %d -> %d", frozen, got)
	}
}

func TestWatchdogTripsOnSnapshotAge(t *testing.T) {
	var notifies atomic.Int64
	s := New(Options{
		WatchdogEvery: 15 * time.Millisecond,
		TripCeiling:   50 * time.Millisecond,
		SnapshotAge:   func() time.Duration { return time.Second }, // way past trip
		Notify:        func() error { notifies.Add(1); return nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	time.Sleep(120 * time.Millisecond)
	if notifies.Load() != 0 {
		t.Errorf("watchdog must withhold pings past the trip ceiling, got %d", notifies.Load())
	}
}

func TestForceRestartOnSnapshotAge(t *testing.T) {
	var builderStarts atomic.Int64
	run := func(ctx context.Context, progress func()) {
		builderStarts.Add(1)
		progress()
		<-ctx.Done()
	}
	s := New(Options{
		WatchdogEvery: 15 * time.Millisecond,
		HardCeiling:   10 * time.Millisecond,
		BuilderName:   "builder",
		SnapshotAge:   func() time.Duration { return time.Second }, // past hard ceiling
		Notify:        func() error { return nil },
	})
	s.Register(Worker{Name: "builder", Backoff: 5 * time.Millisecond, Run: run})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, func() bool { return builderStarts.Load() >= 2 }, "builder force-restarted on stale snapshot")
}
