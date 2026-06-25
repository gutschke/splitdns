package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/anscache"
	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/model"
)

// fakeClock is a race-safe controllable clock for cache TTL tests.
type fakeClock struct{ ns atomic.Int64 }

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Unix(1_000_000, 0).UnixNano())
	return c
}
func (c *fakeClock) now() time.Time      { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) add(d time.Duration) { c.ns.Add(int64(d)) }

// countingUpstream answers A with 203.0.113.5 (TTL 60) and counts queries received.
func countingUpstream(t *testing.T) (addr string, count *int32, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var n int32
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		atomic.AddInt32(&n, 1)
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 203.0.113.5")
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	return pc.LocalAddr().String(), &n, func() { srv.Shutdown() }
}

// startCachedServer wires a server to the given upstream + cache, returning the bound
// address and a stop for the server alone (the caller owns the upstream's lifecycle).
func startCachedServer(t *testing.T, upAddr string, cache *anscache.Cache) (addr string, stop func()) {
	t.Helper()
	fwd := forwarder.NewWithUpstreams([]forwarder.Upstream{{Addr: upAddr, Net: "udp"}}, nil, false, nil)
	snap := &model.Snapshot{}
	s := New(Config{
		Access:    allowLoopback(t),
		Snapshot:  func() *model.Snapshot { return snap },
		View:      func() *model.MDNSView { return &model.MDNSView{} },
		Forwarder: fwd,
		Cache:     cache,
	})
	if err := s.Start([]string{"127.0.0.1:0"}, true, false); err != nil {
		t.Fatalf("start: %v", err)
	}
	return s.BoundAddrs()[0].String(), s.Shutdown
}

// A repeated forwarded query is served from cache: the upstream is hit exactly once.
func TestForwardAnswerCacheHit(t *testing.T) {
	upAddr, count, stopUp := countingUpstream(t)
	defer stopUp()
	cache := anscache.New(anscache.Defaults(), nil)
	addr, stopSrv := startCachedServer(t, upAddr, cache)
	defer stopSrv()

	for i := 0; i < 3; i++ {
		r := dnsQuery(t, addr, "example.org.", dns.TypeA)
		if got := aContents(r); len(got) != 1 || got[0] != "203.0.113.5" {
			t.Fatalf("query %d answer = %v, want [203.0.113.5]", i, got)
		}
	}
	if n := atomic.LoadInt32(count); n != 1 {
		t.Errorf("upstream queried %d times; want 1 (repeats served from cache)", n)
	}
	if s := cache.Stats(); s.Hits < 2 {
		t.Errorf("cache hits = %d, want >= 2", s.Hits)
	}
}

// When the cached entry has expired AND the upstream is down, serve-stale returns the
// last-known answer instead of SERVFAIL (RFC 8767 — the fail-static behavior).
func TestForwardServeStaleOnUpstreamFailure(t *testing.T) {
	upAddr, count, stopUp := countingUpstream(t)
	clk := newFakeClock()
	cache := anscache.New(anscache.Defaults(), clk.now)
	addr, stopSrv := startCachedServer(t, upAddr, cache)
	defer stopSrv()

	// Prime the cache from the live upstream.
	if got := aContents(dnsQuery(t, addr, "example.org.", dns.TypeA)); len(got) != 1 {
		t.Fatalf("prime answer = %v, want one A", got)
	}
	if n := atomic.LoadInt32(count); n != 1 {
		t.Fatalf("priming should hit upstream once, got %d", n)
	}

	// Expire the cached entry (TTL 60s) and take the upstream down.
	clk.add(120 * time.Second)
	stopUp()

	r := dnsQuery(t, addr, "example.org.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("serve-stale: rcode = %s, want NOERROR (not SERVFAIL)", dns.RcodeToString[r.Rcode])
	}
	if got := aContents(r); len(got) != 1 || got[0] != "203.0.113.5" {
		t.Errorf("serve-stale answer = %v, want [203.0.113.5]", got)
	}
	if s := cache.Stats(); s.StaleServes != 1 {
		t.Errorf("stale serves = %d, want 1", s.StaleServes)
	}
}
