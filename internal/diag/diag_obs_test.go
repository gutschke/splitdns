package diag

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gutschke/splitdns/internal/anscache"
	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/qlog"
	"github.com/gutschke/splitdns/internal/supervisor"
)

// The observability providers (cache, queries, backends, workers) render in both the
// JSON and HTML views when wired.
func TestObservabilitySections(t *testing.T) {
	snap := testSnap()
	view := &model.MDNSView{}
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return view }, "t", nil)

	s.WithCacheStats(func() (anscache.Stats, bool) {
		return anscache.Stats{Hits: 7, Misses: 3, Entries: 1, Capacity: 10}, true
	})
	ql := qlog.New(10, 10)
	ql.Record(qlog.Entry{
		Time: time.Unix(1_700_000_000, 0), Client: netip.MustParseAddr("10.0.0.5"),
		Name: "a.example.", Qtype: "A", Decision: qlog.Forward, Rcode: "NOERROR", Latency: 2 * time.Millisecond,
	})
	s.WithQueryLog(ql)
	s.WithBackends(func() []forwarder.BackendStatus {
		return []forwarder.BackendStatus{{
			Addr: "192.0.2.1:853", Net: "tcp-tls", Role: "primary", State: "open",
			Healthy: false, Consec: 5, FailRatio: 1, OpenFor: 3 * time.Second, Cooldown: 2 * time.Second,
		}}
	})
	s.WithWorkers(func() map[string]supervisor.WorkerStats {
		return map[string]supervisor.WorkerStats{"mirror": {Restarts: 2, ProgressAge: 5 * time.Second}}
	})

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())

	// JSON has all four sections.
	code, body := get(t, "http://"+s.Addr()+"/diag.json")
	if code != 200 {
		t.Fatalf("diag.json status = %d", code)
	}
	var p map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"answer_cache", "queries", "backends", "workers"} {
		if _, ok := p[key]; !ok {
			t.Errorf("diag.json missing %q section", key)
		}
	}

	// HTML surfaces the human-readable bits.
	_, html := get(t, "http://"+s.Addr()+"/")
	for _, want := range []string{"Answer cache", "Upstreams", "Workers", "Queries", "10.0.0.5", "a.example.", "open"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

// Client names (from the cache/mDNS resolver) annotate the query telemetry.
func TestClientNamesRendered(t *testing.T) {
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	ql := qlog.New(10, 10)
	ql.Record(qlog.Entry{Time: time.Unix(1_700_000_000, 0), Client: netip.MustParseAddr("10.0.0.7"), Name: "a.", Qtype: "A", Decision: qlog.Forward, Rcode: "NOERROR"})
	s.WithQueryLog(ql)
	s.WithClientNames(func(ip netip.Addr) string {
		if ip == netip.MustParseAddr("10.0.0.7") {
			return "laptop.local"
		}
		return ""
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())

	_, html := get(t, "http://"+s.Addr()+"/")
	if !strings.Contains(html, "laptop.local") {
		t.Error("HTML should show the resolved client name")
	}
	code, body := get(t, "http://"+s.Addr()+"/diag.json")
	if code != 200 || !strings.Contains(body, `"client_name": "laptop.local"`) {
		t.Errorf("diag.json should carry client_name; body has it: %v", strings.Contains(body, "laptop.local"))
	}
}

// When no providers are wired, the new sections are simply absent (back-compat).
func TestObservabilitySectionsOmittedWhenUnset(t *testing.T) {
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	_, body := get(t, "http://"+s.Addr()+"/diag.json")
	var p map[string]json.RawMessage
	json.Unmarshal([]byte(body), &p)
	for _, key := range []string{"answer_cache", "queries", "backends", "workers"} {
		if _, ok := p[key]; ok {
			t.Errorf("diag.json should omit %q when unset", key)
		}
	}
}
