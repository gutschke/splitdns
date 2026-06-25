// Package supervisor runs the control-plane workers under a reliability harness
// (design §3 items 8/8a/9). It provides three guarantees a crashing or wedged
// refresher must never violate:
//
//   - Panic recovery (item 8): a worker that panics is logged, counted, and
//     restarted with capped exponential backoff — never `except BaseException: pass`,
//     and never able to take down :53.
//   - Progress-liveness / stall detection (item 8a): every worker publishes a
//     monotonic lastProgress each loop iteration; a worker whose progress age exceeds
//     its per-worker ceiling is treated as hung (deadlocked WITHOUT panicking), its
//     context cancelled, and it is restarted. A goroutine that ignores cancellation is
//     abandoned and a fresh one started.
//   - Watchdog (item 9): an sd_notify watchdog ping gated on an IN-PROCESS snapshot
//     liveness probe (never an on-wire :53 packet, so it is immune to the inbound
//     limiter and to forward/upstream outages). A hard snapshot-age ceiling escalates:
//     force-restart the builder first, then withhold the ping (controlled systemd
//     restart) if a force-rebuilt builder still cannot publish.
package supervisor

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Worker is a supervised control-plane goroutine. Run must call progress() at the
// end of every loop iteration — a successful cycle, a failed-but-backed-off cycle,
// or an idle wake — so the stall-detector can tell "alive and idle" from "wedged".
type Worker struct {
	Name    string
	Ceiling time.Duration // stall ceiling; 0 disables stall detection for this worker
	Backoff time.Duration // base restart backoff; 0 => default
	Run     func(ctx context.Context, progress func())
}

// Options configure the supervisor's watchdog/escalation behavior. All fields are
// optional; a zero Options yields panic-recovery + stall-detection with no watchdog.
type Options struct {
	// Liveness is the in-process probe (answers a synthetic query from the live
	// snapshot). The watchdog ping is withheld when it returns false.
	Liveness func() bool
	// SnapshotAge returns the age of the primary published snapshot.
	SnapshotAge func() time.Duration
	// HardCeiling: snapshot age past this force-restarts BuilderName.
	HardCeiling time.Duration
	// TripCeiling: snapshot age past this withholds the watchdog ping (trip).
	TripCeiling time.Duration
	BuilderName string
	// Notify sends one sd_notify watchdog keepalive (e.g. supervisor.NotifyWatchdog).
	Notify func() error
	// WatchdogEvery is the keepalive cadence; 0 disables the watchdog loop.
	WatchdogEvery time.Duration

	// StallCheckEvery / GracePeriod tune the stall-detector tick and the grace given
	// to a cancelled worker before its goroutine is abandoned; zero => defaults.
	StallCheckEvery time.Duration
	GracePeriod     time.Duration

	Log func(string)
	Now func() time.Time
}

type heartbeat struct{ ns atomic.Int64 }

func (h *heartbeat) set(t time.Time) { h.ns.Store(t.UnixNano()) }
func (h *heartbeat) age(now time.Time) time.Duration {
	return time.Duration(now.UnixNano() - h.ns.Load())
}

type workerState struct {
	w        Worker
	hb       heartbeat
	forceCh  chan struct{}
	panics   atomic.Int64
	stalls   atomic.Int64
	restarts atomic.Int64
}

// WorkerStats is an exported snapshot of a worker's counters (for /healthz).
type WorkerStats struct {
	Panics      int64
	Stalls      int64
	Restarts    int64
	ProgressAge time.Duration
}

// Supervisor manages a set of workers + the watchdog.
type Supervisor struct {
	opts    Options
	log     func(string)
	now     func() time.Time
	workers []*workerState
	byName  map[string]*workerState
	wg      sync.WaitGroup

	mu        sync.Mutex
	lastForce time.Time
}

const (
	defaultBackoff = 1 * time.Second
	maxBackoff     = 60 * time.Second
	defStallCheck  = 1 * time.Second
	defGrace       = 5 * time.Second
	healthyRun     = 30 * time.Second // a run longer than this resets backoff
)

// New builds a Supervisor.
func New(opts Options) *Supervisor {
	if opts.Log == nil {
		opts.Log = func(string) {}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.StallCheckEvery <= 0 {
		opts.StallCheckEvery = defStallCheck
	}
	if opts.GracePeriod <= 0 {
		opts.GracePeriod = defGrace
	}
	return &Supervisor{opts: opts, log: opts.Log, now: opts.Now, byName: map[string]*workerState{}}
}

// Register adds a worker (before Run).
func (s *Supervisor) Register(w Worker) {
	ws := &workerState{w: w, forceCh: make(chan struct{}, 1)}
	s.workers = append(s.workers, ws)
	s.byName[w.Name] = ws
}

// ForceRestart requests an out-of-band restart of a named worker (used by the
// snapshot-age escalation). Non-blocking and idempotent between restarts.
func (s *Supervisor) ForceRestart(name string) {
	if ws, ok := s.byName[name]; ok {
		select {
		case ws.forceCh <- struct{}{}:
		default:
		}
	}
}

// Stats returns per-worker counters for diagnostics.
func (s *Supervisor) Stats() map[string]WorkerStats {
	now := s.now()
	out := make(map[string]WorkerStats, len(s.workers))
	for _, ws := range s.workers {
		out[ws.w.Name] = WorkerStats{
			Panics: ws.panics.Load(), Stalls: ws.stalls.Load(),
			Restarts: ws.restarts.Load(), ProgressAge: ws.hb.age(now),
		}
	}
	return out
}

// Run starts every worker and the watchdog loop, blocking until ctx is cancelled.
func (s *Supervisor) Run(ctx context.Context) {
	for _, ws := range s.workers {
		s.wg.Add(1)
		go s.superviseWorker(ctx, ws)
	}
	if s.opts.WatchdogEvery > 0 {
		s.wg.Add(1)
		go s.watchdogLoop(ctx)
	}
	s.wg.Wait()
}

type outcome int

const (
	outReturned outcome = iota // worker goroutine returned (normal or panic)
	outStalled                 // progress age exceeded ceiling
	outForce                   // out-of-band force-restart
	outShutdown                // parent ctx cancelled
)

func (s *Supervisor) superviseWorker(ctx context.Context, ws *workerState) {
	defer s.wg.Done()
	backoff := ws.w.Backoff
	if backoff <= 0 {
		backoff = defaultBackoff
	}
	for {
		if ctx.Err() != nil {
			return
		}
		runCtx, cancel := context.WithCancel(ctx)
		ws.hb.set(s.now())
		started := s.now()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() {
				if r := recover(); r != nil {
					ws.panics.Add(1)
					s.log(fmt.Sprintf("supervisor: worker %q panicked: %v", ws.w.Name, r))
				}
			}()
			ws.w.Run(runCtx, func() { ws.hb.set(s.now()) })
		}()

		oc := s.monitor(ctx, ws, done)
		cancel()
		if oc == outShutdown {
			<-done // parent shutdown: the worker honors ctx and returns
			return
		}
		// Wait for the worker to actually exit, but never block forever on a goroutine
		// that ignores cancellation — abandon it (leak) and restart fresh.
		select {
		case <-done:
		case <-time.After(s.opts.GracePeriod):
			s.log(fmt.Sprintf("supervisor: worker %q ignored cancellation; abandoning goroutine and restarting", ws.w.Name))
		}

		if ctx.Err() != nil {
			return
		}
		switch oc {
		case outStalled:
			ws.stalls.Add(1)
			s.log(fmt.Sprintf("supervisor: worker %q stalled (no progress for > %s) — restarting", ws.w.Name, ws.w.Ceiling))
		case outForce:
			s.log(fmt.Sprintf("supervisor: worker %q force-restarted", ws.w.Name))
		}
		ws.restarts.Add(1)

		// Backoff: reset after a healthy long run, otherwise cap-double.
		if s.now().Sub(started) > healthyRun {
			backoff = defaultBackoff
		}
		if !sleepCtx(ctx, backoff) {
			return
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// monitor waits for the worker to return, a forced restart, parent shutdown, or a
// stall (progress age beyond ceiling).
func (s *Supervisor) monitor(ctx context.Context, ws *workerState, done <-chan struct{}) outcome {
	var tick <-chan time.Time
	if ws.w.Ceiling > 0 {
		t := time.NewTicker(s.opts.StallCheckEvery)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-done:
			return outReturned
		case <-ctx.Done():
			return outShutdown
		case <-ws.forceCh:
			return outForce
		case <-tick:
			if ws.hb.age(s.now()) > ws.w.Ceiling {
				return outStalled
			}
		}
	}
}

func (s *Supervisor) watchdogLoop(ctx context.Context) {
	defer s.wg.Done()
	t := time.NewTicker(s.opts.WatchdogEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.watchdogTick()
		}
	}
}

func (s *Supervisor) watchdogTick() {
	var age time.Duration
	if s.opts.SnapshotAge != nil {
		age = s.opts.SnapshotAge()
	}
	// Stage 1: a wedged builder is force-restarted first (cheaper than a process
	// restart and keeps :53 bound), rate-limited so we don't thrash.
	if s.opts.HardCeiling > 0 && age > s.opts.HardCeiling && s.opts.BuilderName != "" {
		s.mu.Lock()
		if s.now().Sub(s.lastForce) > s.opts.HardCeiling {
			s.lastForce = s.now()
			s.mu.Unlock()
			s.log(fmt.Sprintf("supervisor: snapshot age %s > hard ceiling — force-restarting %q", age, s.opts.BuilderName))
			s.ForceRestart(s.opts.BuilderName)
		} else {
			s.mu.Unlock()
		}
	}
	// Stage 2: if a force-rebuilt builder still cannot publish, withhold the watchdog
	// ping → controlled systemd restart from a clean process state.
	trip := s.opts.TripCeiling > 0 && age > s.opts.TripCeiling
	healthy := s.opts.Liveness == nil || s.opts.Liveness()
	if healthy && !trip {
		if s.opts.Notify != nil {
			if err := s.opts.Notify(); err != nil {
				s.log(fmt.Sprintf("supervisor: watchdog notify failed: %v", err))
			}
		}
		return
	}
	s.log(fmt.Sprintf("supervisor: WITHHOLDING watchdog ping (snapshot_liveness=%v snapshot_age=%s trip=%v) — systemd will restart if this persists", healthy, age, trip))
}

// sleepCtx sleeps for d unless ctx is cancelled first; returns false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
