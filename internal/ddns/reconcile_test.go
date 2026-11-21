package ddns

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gutschke/splitdns/internal/model"
)

// mutableSource is a RecordSource whose records (and failure mode) tests change between
// calls, standing in for a Cloudflare zone that drifts or is briefly unreachable.
type mutableSource struct {
	mu    sync.Mutex
	recs  map[string][]model.RR
	fail  error
	calls int
}

func (m *mutableSource) RecordsForHost(_ context.Context, host string) ([]model.RR, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.fail != nil {
		return nil, m.fail
	}
	return m.recs[host], nil
}

func (m *mutableSource) set(host string, rrs ...model.RR) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs[host] = rrs
}

func (m *mutableSource) setFail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = err
}

// An API outage at the moment of the announcement must not lose the change: the next
// periodic pass applies it once the source answers again.
func TestReconcileAcceptedRepairsAfterOutage(t *testing.T) {
	src := &mutableSource{recs: map[string][]model.RR{}}
	src.set("edge", rr("z1", "r1", "edge.example.com.", "1.1.1.1"))
	src.setFail(errors.New("api unavailable"))
	ed := &opLog{}
	w := newTestWriter(baseCfg(), src, ed, nil, nil)

	if out, err := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")}); err == nil || out != OutcomeError {
		t.Fatalf("got (%v,%v), want error during the outage", out, err)
	}
	src.setFail(nil)
	w.ReconcileAccepted(context.Background(), nil)
	if len(ed.updates) != 1 || !strings.HasSuffix(ed.updates[0], "9.9.9.9") {
		t.Fatalf("periodic pass should apply the lost change, got updates=%v", ed.updates)
	}
}

// A record edited by hand drifts back to the announced address on the next pass; a
// converged host costs a read but no write.
func TestReconcileAcceptedRepairsDrift(t *testing.T) {
	src := &mutableSource{recs: map[string][]model.RR{}}
	src.set("edge", rr("z1", "r1", "edge.example.com.", "9.9.9.9"))
	ed := &opLog{}
	w := newTestWriter(baseCfg(), src, ed, nil, nil)

	if out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")}); out != OutcomeUnchanged {
		t.Fatalf("got %v, want unchanged", out)
	}
	w.ReconcileAccepted(context.Background(), nil)
	if len(ed.updates) != 0 {
		t.Fatalf("a converged host must not be rewritten, got %v", ed.updates)
	}
	src.set("edge", rr("z1", "r1", "edge.example.com.", "8.8.4.4"))
	w.ReconcileAccepted(context.Background(), nil)
	if len(ed.updates) != 1 || !strings.HasSuffix(ed.updates[0], "9.9.9.9") {
		t.Fatalf("drift should be repaired, got updates=%v", ed.updates)
	}
}

// A repair that hits the per-host rate limit is retried by a later pass rather than lost.
func TestReconcileAcceptedRetriesAfterRateLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	src := &mutableSource{recs: map[string][]model.RR{}}
	src.set("edge", rr("z1", "r1", "edge.example.com.", "1.1.1.1"))
	ed := &opLog{}
	cfg := baseCfg()
	cfg.Rate = 10 * time.Minute
	w := newTestWriter(cfg, src, ed, clock, nil)

	if out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")}); out != OutcomeApplied {
		t.Fatalf("got %v, want applied", out)
	}
	src.set("edge", rr("z1", "r1", "edge.example.com.", "1.1.1.1")) // the write did not stick
	now = now.Add(time.Minute)
	w.ReconcileAccepted(context.Background(), nil)
	if len(ed.updates) != 1 {
		t.Fatalf("inside the rate window no second write may happen, got %v", ed.updates)
	}
	now = now.Add(10 * time.Minute)
	w.ReconcileAccepted(context.Background(), nil)
	if len(ed.updates) != 2 {
		t.Fatalf("after the rate window the repair should go through, got %v", ed.updates)
	}
}

// A host whose records are no longer eligible is forgotten instead of being re-read forever.
func TestReconcileAcceptedForgetsIneligible(t *testing.T) {
	src := &mutableSource{recs: map[string][]model.RR{}}
	src.set("edge", rr("z1", "r1", "edge.example.com.", "9.9.9.9"))
	w := newTestWriter(baseCfg(), src, &opLog{}, nil, nil)
	w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")})

	src.set("edge") // records removed
	w.ReconcileAccepted(context.Background(), nil)
	before := src.calls
	w.ReconcileAccepted(context.Background(), nil)
	if src.calls != before {
		t.Errorf("a forgotten host must not be looked up again (calls %d -> %d)", before, src.calls)
	}
}

// Run drives the periodic pass on Config.Reconcile without any new announcement.
func TestRunPeriodicReconcile(t *testing.T) {
	src := &mutableSource{recs: map[string][]model.RR{}}
	src.set("edge", rr("z1", "r1", "edge.example.com.", "9.9.9.9"))
	ed := &opLog{}
	cfg := baseCfg()
	cfg.Reconcile = 20 * time.Millisecond
	w := newTestWriter(cfg, src, ed, nil, nil)
	w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")})
	src.set("edge", rr("z1", "r1", "edge.example.com.", "8.8.4.4"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx, nil); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ed.mu.Lock()
		n := len(ed.updates)
		ed.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(ed.updates) == 0 {
		t.Fatal("Run should have repaired the drift on its own")
	}
}
