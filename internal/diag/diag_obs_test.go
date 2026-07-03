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

// The enriched telemetry — hottest cache entries, per-upstream lifetime stats, and each
// busy client's most-asked names — renders in both the JSON and HTML views.
func TestEnrichedTelemetry(t *testing.T) {
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)

	s.WithCacheStats(func() (anscache.Stats, bool) {
		return anscache.Stats{Hits: 9, Misses: 1, Entries: 2, Capacity: 100}, true
	})
	s.WithCacheEntries(func(n int) []anscache.EntryStat {
		return []anscache.EntryStat{
			{Name: "hot.example.", Type: "A", Kind: "positive", Hits: 12, Age: 5 * time.Second, TTL: 300 * time.Second, Live: true},
			{Name: "gone.example.", Type: "AAAA", Kind: "negative", Hits: 0, Age: 400 * time.Second, TTL: 60 * time.Second, Live: false},
		}
	})
	s.WithBackends(func() []forwarder.BackendStatus {
		return []forwarder.BackendStatus{{
			Addr: "192.0.2.1:853", Net: "tcp-tls", Role: "primary", State: "closed", Healthy: true,
			Queries: 100, Failures: 4, AvgRTT: 12500 * time.Microsecond, LastRTT: 9 * time.Millisecond,
		}}
	})
	now := time.Unix(1_700_000_000, 0)
	ql := qlog.New(50, 50, qlog.WithClock(func() time.Time { return now })) // freeze: no decay in-test
	for i := 0; i < 3; i++ {
		ql.Record(qlog.Entry{Time: now, Client: netip.MustParseAddr("10.0.0.9"), Name: "busy.example.", Qtype: "A", Decision: qlog.Forward, Rcode: "NOERROR"})
	}
	s.WithQueryLog(ql)

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())

	_, body := get(t, "http://"+s.Addr()+"/diag.json")
	for _, want := range []string{
		`"hot_entries"`, `"hot.example."`, `"kind": "negative"`, // cache entries
		`"queries": 100`, `"failures": 4`, `"avg_rtt"`, // upstream stats
		`"top_names"`, `"busy.example."`, // per-client top names
	} {
		if !strings.Contains(body, want) {
			t.Errorf("diag.json missing %q", want)
		}
	}

	_, html := get(t, "http://"+s.Addr()+"/")
	for _, want := range []string{
		"Hottest entries", "hot.example.", // cache entries table
		"avg rtt", "12.5 ms", // upstream avg latency column
		"top names", "busy.example.", // top-names column
	} {
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

// The encrypted/DDR status panel and per-query transport render in both JSON and HTML.
func TestEncryptedStatusAndTransport(t *testing.T) {
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)

	now := time.Unix(1_700_000_000, 0)
	ql := qlog.New(50, 50, qlog.WithClock(func() time.Time { return now }))
	ql.Record(qlog.Entry{Time: now, Client: netip.MustParseAddr("10.0.0.9"), Transport: "dot", Name: "a.example.", Qtype: "A", Decision: qlog.Forward, Rcode: "NOERROR"})
	s.WithQueryLog(ql)

	s.WithEncrypted(func() *EncStatus {
		return &EncStatus{
			Enabled: true, ADN: "dns.example.net", CertValid: true, Expiry: "in 40d (2026-08-12)",
			SANs: []string{"dns.example.net"}, DoT: []string{"192.0.2.53:853"},
			DoH: []string{"192.0.2.53:443"}, DoHPath: "/dns-query",
			AdvertiseDDR: true, DDRReady: true,
			SVCB:   []string{`_dns.resolver.arpa.	300	IN	SVCB 1 dns.example.net. alpn="dot" port=853`},
			Checks: []EncCheck{{Name: "certificate valid & unexpired", OK: true, Detail: "in 40d"}, {Name: "DoT listener up", OK: true}},
		}
	})

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())

	_, body := get(t, "http://"+s.Addr()+"/diag.json")
	for _, want := range []string{
		`"encrypted"`, `"cert_valid": true`, `"ddr_ready": true`, `"dns.example.net"`, // status
		`"by_transport"`, `"transport": "dot"`, // per-query + rollup transport
	} {
		if !strings.Contains(body, want) {
			t.Errorf("diag.json missing %q", want)
		}
	}

	_, html := get(t, "http://"+s.Addr()+"/")
	for _, want := range []string{
		"Encrypted &amp; DDR", "DDR advertised", "certificate valid", // status panel
		"<th>proto</th>", "<th>transports</th>", // transport columns
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}
