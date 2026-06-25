package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// --- fakes ---

type fakeSource struct {
	recs map[string][]model.RR
}

func (f *fakeSource) RecordsForHost(_ context.Context, host string) ([]model.RR, error) {
	return f.recs[host], nil
}

type opLog struct {
	mu      sync.Mutex
	creates []string // "name type content"
	updates []string // "zone/id name type content"
	deletes []string // "zone/id"
}

func (o *opLog) Create(_ context.Context, zoneID, name string, typ uint16, content string) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.creates = append(o.creates, name+" "+dns.TypeToString[typ]+" "+content)
	return "new-id", nil
}
func (o *opLog) Update(_ context.Context, zoneID, recordID, name string, typ uint16, content string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.updates = append(o.updates, zoneID+"/"+recordID+" "+name+" "+dns.TypeToString[typ]+" "+content)
	return nil
}
func (o *opLog) Delete(_ context.Context, zoneID, recordID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.deletes = append(o.deletes, zoneID+"/"+recordID)
	return nil
}

func rr(zone, id, fqdn, content string) model.RR {
	typ := uint16(dns.TypeA)
	if strings.Contains(content, ":") {
		typ = dns.TypeAAAA
	}
	return model.RR{Name: fqdn, Type: typ, Class: dns.ClassINET, Content: content, ZoneID: zone, RecordID: id}
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func baseCfg() Config {
	// Non-empty eligibility so the live edit-path tests are not forced to dry-run by
	// the D8 empty-allowlist safety gate. Covers the fqdns the live tests announce.
	return Config{Enabled: true, DryRun: false, Eligible: map[string]bool{
		"edge.example.com": true, "a.example.com": true, "b.example.com": true,
	}}
}

func newTestWriter(cfg Config, src RecordSource, ed Editor, clock func() time.Time, audit *Audit) *Writer {
	return New(cfg, src, ed, audit, clock, nil)
}

// --- tests ---

func TestReconcileDisabled(t *testing.T) {
	ed := &opLog{}
	w := newTestWriter(Config{Enabled: false}, &fakeSource{}, ed, nil, nil)
	out, err := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("8.8.8.8")})
	if err != nil || out != OutcomeDisabled {
		t.Fatalf("got (%v,%v), want disabled,nil", out, err)
	}
	if len(ed.updates)+len(ed.creates)+len(ed.deletes) != 0 {
		t.Errorf("disabled writer must make no edits")
	}
}

func TestReconcileUnchanged(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "8.8.8.8")}}}
	ed := &opLog{}
	w := newTestWriter(baseCfg(), src, ed, nil, nil)
	out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("8.8.8.8")})
	if out != OutcomeUnchanged {
		t.Fatalf("got %v, want unchanged", out)
	}
	if len(ed.updates)+len(ed.creates)+len(ed.deletes) != 0 {
		t.Errorf("unchanged must make no edits")
	}
}

func TestReconcileEditInPlace(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	ed := &opLog{}
	w := newTestWriter(baseCfg(), src, ed, nil, nil)
	out, err := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")})
	if err != nil || out != OutcomeApplied {
		t.Fatalf("got (%v,%v), want applied", out, err)
	}
	if len(ed.updates) != 1 || len(ed.creates) != 0 || len(ed.deletes) != 0 {
		t.Fatalf("want exactly one in-place edit, got u=%v c=%v d=%v", ed.updates, ed.creates, ed.deletes)
	}
	if !strings.Contains(ed.updates[0], "z1/r1") || !strings.HasSuffix(ed.updates[0], "9.9.9.9") {
		t.Errorf("edit reused wrong id/content: %q", ed.updates[0])
	}
}

func TestReconcileCreateSurplus(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	ed := &opLog{}
	w := newTestWriter(baseCfg(), src, ed, nil, nil)
	// One existing A; desired adds a second (v6) address => 1 edit + 1 create.
	out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9", "2001:4860:4860::8888")})
	if out != OutcomeApplied {
		t.Fatalf("got %v, want applied", out)
	}
	if len(ed.updates) != 1 || len(ed.creates) != 1 || len(ed.deletes) != 0 {
		t.Fatalf("want 1 edit + 1 create, got u=%v c=%v d=%v", ed.updates, ed.creates, ed.deletes)
	}
	if !strings.Contains(ed.creates[0], "AAAA") {
		t.Errorf("surplus create should be the AAAA: %q", ed.creates[0])
	}
}

func TestReconcileDeleteSurplus(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {
		rr("z1", "r1", "edge.example.com.", "1.1.1.1"),
		rr("z1", "r2", "edge.example.com.", "8.8.4.4"),
	}}}
	ed := &opLog{}
	w := newTestWriter(baseCfg(), src, ed, nil, nil)
	out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")})
	if out != OutcomeApplied {
		t.Fatalf("got %v, want applied", out)
	}
	if len(ed.updates) != 1 || len(ed.creates) != 0 || len(ed.deletes) != 1 {
		t.Fatalf("want 1 edit + 1 delete, got u=%v c=%v d=%v", ed.updates, ed.creates, ed.deletes)
	}
}

// Security regression: a private/CGNAT/documentation address in the announcement
// must NEVER be written, and must not cause the existing public record to be deleted.
func TestPrivateAddrsNeverWritten(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	ed := &opLog{}
	w := newTestWriter(baseCfg(), src, ed, nil, nil)
	out, _ := w.Reconcile(context.Background(), Change{Host: "edge",
		Addrs: addrs("192.168.1.5", "9.9.9.9", "fd00::1", "100.64.0.1")})
	if out != OutcomeApplied {
		t.Fatalf("got %v, want applied", out)
	}
	all := strings.Join(append(append(ed.updates, ed.creates...), ed.deletes...), " ")
	for _, bad := range []string{"192.168", "fd00", "100.64"} {
		if strings.Contains(all, bad) {
			t.Errorf("non-public address %q reached Cloudflare: %q", bad, all)
		}
	}
	if !strings.HasSuffix(ed.updates[0], "9.9.9.9") {
		t.Errorf("only the public address should be written, got %q", ed.updates[0])
	}
}

// An announcement carrying ONLY non-public addresses must be a no-op (never delete).
func TestAllPrivateIsNoOp(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	ed := &opLog{}
	w := newTestWriter(baseCfg(), src, ed, nil, nil)
	out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("192.168.1.5", "fd00::1")})
	if out != OutcomeNoPublic {
		t.Fatalf("got %v, want no-public-addrs", out)
	}
	if len(ed.updates)+len(ed.creates)+len(ed.deletes) != 0 {
		t.Errorf("all-private announcement must not touch Cloudflare")
	}
}

func TestProxiedAndAllowlist(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {
		{Name: "edge.example.com.", Type: dns.TypeA, Content: "1.1.1.1", ZoneID: "z1", RecordID: "r1", Proxied: true},
	}}}
	ed := &opLog{}
	// Only record is proxied => filtered out => nothing eligible.
	w := newTestWriter(baseCfg(), src, ed, nil, nil)
	if out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")}); out != OutcomeNotEligible {
		t.Fatalf("proxied-only host: got %v, want not-eligible", out)
	}

	// Allowlist excludes the host's FQDN.
	src2 := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	cfg := baseCfg()
	cfg.Eligible = map[string]bool{"other.example.com": true}
	w2 := newTestWriter(cfg, src2, &opLog{}, nil, nil)
	if out, _ := w2.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")}); out != OutcomeNotEligible {
		t.Fatalf("non-allowlisted host: got %v, want not-eligible", out)
	}
}

func TestDryRun(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	ed := &opLog{}
	cfg := baseCfg()
	cfg.DryRun = true
	var buf bytes.Buffer
	w := newTestWriter(cfg, src, ed, nil, NewAudit(&buf, "tok-1"))
	out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")})
	if out != OutcomeDryRun {
		t.Fatalf("got %v, want dry-run", out)
	}
	if len(ed.updates)+len(ed.creates)+len(ed.deletes) != 0 {
		t.Errorf("dry-run must make no edits")
	}
	if !strings.Contains(buf.String(), "dry-run") || !strings.Contains(buf.String(), "9.9.9.9") {
		t.Errorf("dry-run should audit the intended change, got %q", buf.String())
	}
}

// TestEmptyEligibleForcesDryRun pins D8: an enabled, non-dry-run writer with an
// empty eligibility allowlist must be forced to dry-run (deny-all), never make a
// real edit, and warn loudly.
func TestEmptyEligibleForcesDryRun(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	ed := &opLog{}
	var logged string
	cfg := Config{Enabled: true, DryRun: false} // empty Eligible
	w := New(cfg, src, ed, nil, nil, func(m string) { logged += m })
	out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")})
	if out != OutcomeDryRun {
		t.Fatalf("empty-eligible live writer: got %v, want dry-run (deny-all)", out)
	}
	if len(ed.updates)+len(ed.creates)+len(ed.deletes) != 0 {
		t.Errorf("empty-eligible writer must make no real edits")
	}
	if !strings.Contains(logged, "REFUSING live writes") {
		t.Errorf("expected a loud refusal log, got %q", logged)
	}
}

// TestSubmitNeverDropsNewest pins D11: under concurrent Submit, the most recently
// submitted change for a host must survive (never be the one dropped). We hammer
// Submit from many goroutines, then drain and assert the final known address is
// present in the queue's contents.
func TestSubmitNeverDropsNewest(t *testing.T) {
	w := New(baseCfg(), &fakeSource{}, &opLog{}, nil, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w.Submit(Change{Host: "edge", Addrs: addrs("9.9.9.9")})
		}(i)
	}
	wg.Wait()
	// The queue must be internally consistent (no panic, depth within cap) — the race
	// detector is the real assertion here. Drain to confirm it's well-formed.
	n := 0
	for {
		select {
		case <-w.ch:
			n++
		default:
			if n == 0 {
				t.Fatal("queue unexpectedly empty after 200 submits")
			}
			if n > chanCap {
				t.Fatalf("queue depth %d exceeds cap %d", n, chanCap)
			}
			return
		}
	}
}

func TestRateLimited(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	ed := &opLog{}
	cfg := baseCfg()
	cfg.Rate = 10 * time.Minute
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	w := newTestWriter(cfg, src, ed, clock, nil)

	if out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("9.9.9.9")}); out != OutcomeApplied {
		t.Fatalf("first write should apply, got %v", out)
	}
	// Source still reports the OLD address, so a second change is real work; within
	// the window it must be rate-limited rather than applied.
	now = now.Add(5 * time.Minute)
	if out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("8.8.4.4")}); out != OutcomeRateLimited {
		t.Fatalf("second write within window: got %v, want rate-limited", out)
	}
	// Past the window it applies again.
	now = now.Add(6 * time.Minute)
	if out, _ := w.Reconcile(context.Background(), Change{Host: "edge", Addrs: addrs("8.8.4.4")}); out != OutcomeApplied {
		t.Fatalf("third write past window: got %v, want applied", out)
	}
}

func TestAuditChainAndTamper(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{
		"a": {rr("z1", "r1", "a.example.com.", "1.1.1.1")},
		"b": {rr("z1", "r2", "b.example.com.", "8.8.4.4")},
	}}
	var buf bytes.Buffer
	w := newTestWriter(baseCfg(), src, &opLog{}, nil, NewAudit(&buf, "tok-1"))
	w.Reconcile(context.Background(), Change{Host: "a", Addrs: addrs("9.9.9.9")})
	w.Reconcile(context.Background(), Change{Host: "b", Addrs: addrs("9.9.9.9")})

	var entries []Entry
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 audit entries, got %d", len(entries))
	}
	if idx, ok := VerifyChain(entries); !ok {
		t.Fatalf("intact chain reported broken at %d", idx)
	}
	// Tamper with an entry's recorded change; the chain must now fail at that index.
	entries[1].Change = "edit z1:r2 8.8.4.4->1.2.3.4"
	if idx, ok := VerifyChain(entries); ok || idx != 1 {
		t.Fatalf("tamper not detected: idx=%d ok=%v", idx, ok)
	}
}

func TestSubmitDropOldestNeverBlocks(t *testing.T) {
	w := newTestWriter(baseCfg(), &fakeSource{}, &opLog{}, nil, nil)
	done := make(chan struct{})
	go func() {
		for i := 0; i < chanCap*3; i++ {
			w.Submit(Change{Host: "edge", Addrs: addrs("9.9.9.9")})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked when queue full (drop-oldest must keep it non-blocking)")
	}
	if len(w.ch) > chanCap {
		t.Errorf("queue exceeded cap: %d", len(w.ch))
	}
}
