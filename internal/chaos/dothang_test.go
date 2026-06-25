package chaos

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/leakcheck"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
	"github.com/gutschke/splitdns/internal/server"
)

// stallListener accepts TCP connections and holds them open forever without ever
// completing a TLS handshake — the classic DoT black hole.
func stallListener(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stall listener: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { <-done; c.Close() }(c) // hold; never speak TLS
		}
	}()
	return ln.Addr().String(), func() { close(done); ln.Close() }
}

// TestDoTHandshakeHang pins S29: when the only DoT upstream accepts TCP but never
// finishes the TLS handshake, every forwarded query must SERVFAIL within the
// per-request budget (D4), the inbound slot must be released (the server stays
// responsive), and no handler goroutine may leak.
func TestDoTHandshakeHang(t *testing.T) {
	base := leakcheck.Baseline()

	addr, stop := stallListener(t)

	// DoT-only (cleartext fallback off) pointed at the black hole.
	fwd := forwarder.NewWithUpstreams(
		[]forwarder.Upstream{{Addr: addr, Net: "tcp-tls", ServerName: "stall.test"}}, nil, false, nil)
	allow, err := netmatch.ParseSet([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	snap := &model.Snapshot{Static: map[string][]model.RR{
		"gw.example.test.": {{Type: dns.TypeA, Class: dns.ClassINET, TTL: 300, Content: "203.0.113.99"}},
	}}
	srv := server.New(server.Config{
		Access:      netmatch.Access{Allow: allow},
		Snapshot:    func() *model.Snapshot { return snap },
		View:        func() *model.MDNSView { return &model.MDNSView{} },
		Forwarder:   fwd,
		QueryBudget: 600 * time.Millisecond,
		MaxInflight: 64, // > the concurrent burst below, so drops are slot-leaks not backpressure
	})
	if err := srv.Start([]string{"127.0.0.1:0"}, true, false); err != nil {
		t.Fatalf("server start: %v", err)
	}
	saddr := srv.BoundAddrs()[0].String()

	query := func(name string, qtype uint16) (*dns.Msg, time.Duration) {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
		start := time.Now()
		resp, _, err := c.Exchange(m, saddr)
		if err != nil {
			t.Fatalf("exchange %s: %v", name, err)
		}
		return resp, time.Since(start)
	}

	// Forwarded name → hits the black hole → SERVFAIL within ~budget, not the 3s client timeout.
	resp, elapsed := query("public.example.org.", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("hung DoT: want SERVFAIL, got rcode=%d", resp.Rcode)
	}
	if elapsed > 2*time.Second {
		t.Errorf("hung DoT not bounded by the budget: took %v", elapsed)
	}

	// Slot released / not wedged: a local (non-forwarded) query still answers promptly.
	local, lel := query("gw.example.test.", dns.TypeA)
	if len(local.Answer) != 1 || lel > time.Second {
		t.Errorf("server wedged after a hung forward (slot leak?): answers=%d took=%v", len(local.Answer), lel)
	}

	// Concurrent flood of hung forwards must all return (each releases its slot).
	done := make(chan int, 32)
	for i := 0; i < 32; i++ {
		go func() {
			m := new(dns.Msg)
			m.SetQuestion("public.example.org.", dns.TypeA)
			c := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
			resp, _, err := c.Exchange(m, saddr)
			if err != nil {
				done <- -1
				return
			}
			done <- resp.Rcode
		}()
	}
	for i := 0; i < 32; i++ {
		if rc := <-done; rc != dns.RcodeServerFailure {
			t.Errorf("concurrent hung forward #%d: rcode=%d (slot exhaustion/leak?)", i, rc)
		}
	}

	srv.Shutdown()
	stop()
	leakcheck.AssertNoLeak(t, base)
}
