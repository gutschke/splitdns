package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
)

// blackhole returns the address of a UDP socket that accepts packets but never
// replies, so a forward to it hangs until the deadline/cancel fires.
func blackhole(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole listen: %v", err)
	}
	return pc.LocalAddr().String(), func() { pc.Close() }
}

// newServerCtx builds a server whose only upstream is a black hole, with an
// explicit per-request budget and daemon context (D4 plumbing).
func newServerCtx(t *testing.T, ctx context.Context, budget time.Duration) (*Server, string, func()) {
	t.Helper()
	bhAddr, stopBH := blackhole(t)
	// Single cleartext-UDP "primary" that never answers; no DoT fallback noise.
	fwd := forwarder.NewWithUpstreams([]forwarder.Upstream{{Addr: bhAddr, Net: "udp"}}, nil, false, nil)
	snap := &model.Snapshot{}
	s := New(Config{
		Access:      netmatch.Access{Allow: mustSet(t, "127.0.0.0/8")},
		Snapshot:    func() *model.Snapshot { return snap },
		View:        func() *model.MDNSView { return &model.MDNSView{} },
		Forwarder:   fwd,
		Context:     ctx,
		QueryBudget: budget,
	})
	if err := s.Start([]string{"127.0.0.1:0"}, true, false); err != nil {
		t.Fatalf("start: %v", err)
	}
	return s, s.BoundAddrs()[0].String(), func() { s.Shutdown(); stopBH() }
}

func mustSet(t *testing.T, cidr string) *netmatch.Set {
	t.Helper()
	set, err := netmatch.ParseSet([]string{cidr})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// upstream answers A by name: "private.*" => 192.168.1.50, else 203.0.113.5.
func upstream(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			ip := "203.0.113.5"
			if len(r.Question[0].Name) >= 8 && r.Question[0].Name[:8] == "private." {
				ip = "192.168.1.50"
			}
			rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A " + ip)
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	return pc.LocalAddr().String(), func() { srv.Shutdown() }
}

func newServer(t *testing.T, access netmatch.Access) (*Server, string, func()) {
	t.Helper()
	upAddr, stopUp := upstream(t)
	fwd := forwarder.NewWithUpstreams([]forwarder.Upstream{{Addr: upAddr, Net: "udp"}}, nil, false, nil)

	snap := &model.Snapshot{
		Static:      map[string][]model.RR{"gw.example.test.": {{Type: dns.TypeA, Class: dns.ClassINET, TTL: 300, Content: "203.0.113.99"}}},
		AllowSuffix: []string{"example.test."},
	}
	s := New(Config{
		Access:    access,
		Snapshot:  func() *model.Snapshot { return snap },
		View:      func() *model.MDNSView { return &model.MDNSView{} },
		Forwarder: fwd,
	})
	if err := s.Start([]string{"127.0.0.1:0"}, true, true); err != nil {
		t.Fatalf("start: %v", err)
	}
	addr := s.BoundAddrs()[0].String()
	return s, addr, func() { s.Shutdown(); stopUp() }
}

func allowLoopback(t *testing.T) netmatch.Access {
	allow, err := netmatch.ParseSet([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	return netmatch.Access{Allow: allow}
}

func dnsQuery(t *testing.T, server, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		t.Fatalf("exchange %s: %v", name, err)
	}
	return resp
}

func aContents(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out
}

func TestServerStaticAnswer(t *testing.T) {
	_, addr, stop := newServer(t, allowLoopback(t))
	defer stop()
	resp := dnsQuery(t, addr, "gw.example.test.", dns.TypeA)
	if got := aContents(resp); len(got) != 1 || got[0] != "203.0.113.99" {
		t.Fatalf("static answer = %v, want [203.0.113.99]", got)
	}
	if !resp.Authoritative {
		t.Errorf("local answer should set AA")
	}
}

func TestServerForwardsPublic(t *testing.T) {
	_, addr, stop := newServer(t, allowLoopback(t))
	defer stop()
	resp := dnsQuery(t, addr, "public.example.org.", dns.TypeA)
	if got := aContents(resp); len(got) != 1 || got[0] != "203.0.113.5" {
		t.Fatalf("forwarded public answer = %v, want [203.0.113.5]", got)
	}
}

func TestServerRebindStripsPrivate(t *testing.T) {
	_, addr, stop := newServer(t, allowLoopback(t))
	defer stop()
	// Upstream returns a private 192.168.x for this forwarded name; it must be stripped.
	resp := dnsQuery(t, addr, "private.example.org.", dns.TypeA)
	if got := aContents(resp); len(got) != 0 {
		t.Fatalf("rebind: private forwarded answer must be stripped, got %v", got)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("stripped-to-empty should be NODATA (NOERROR), got rcode=%d", resp.Rcode)
	}
}

// TestRebindLabelBoundary pins panel finding D1: a forwarded look-alike name
// (evilcorp.example.test.) must NOT be treated as under the allow-suffix
// example.test., so its private answer is still rebind-stripped. underAllow must be
// label-aligned, not a bare string suffix.
func TestRebindLabelBoundary(t *testing.T) {
	// A name genuinely under the allow suffix bypasses the filter; a look-alike does not.
	allow := []string{"example.test."}
	if !underAllow("www.example.test.", allow) {
		t.Errorf("legit subdomain must be under allow suffix")
	}
	if !underAllow("example.test.", allow) {
		t.Errorf("the apex itself must match")
	}
	if underAllow("evilexample.test.", allow) {
		t.Errorf("D1: look-alike evilexample.test. must NOT match allow example.test.")
	}
	if underAllow("notexample.test.", allow) {
		t.Errorf("D1: look-alike notexample.test. must NOT match")
	}
}

// TestForwardDeadline pins D4: a forward to a non-responsive upstream must
// SERVFAIL within roughly the per-request budget, not hang for the full
// 1.5s per-try / 4s overall forwarder ceiling.
func TestForwardDeadline(t *testing.T) {
	budget := 300 * time.Millisecond
	_, addr, stop := newServerCtx(t, context.Background(), budget)
	defer stop()

	start := time.Now()
	resp := dnsQuery(t, addr, "hang.example.org.", dns.TypeA)
	elapsed := time.Since(start)

	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("hanging upstream: want SERVFAIL, got rcode=%d", resp.Rcode)
	}
	if elapsed > budget+500*time.Millisecond {
		t.Fatalf("forward took %v, want <~%v (budget not enforced)", elapsed, budget)
	}
}

// TestForwardCancelsOnShutdown pins the D4 shutdown linkage: cancelling the
// daemon context aborts an in-flight forward promptly instead of waiting out
// the per-request budget.
func TestForwardCancelsOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Long budget so only ctx-cancel can end the forward quickly.
	_, addr, stop := newServerCtx(t, ctx, 10*time.Second)
	defer stop()

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		resp := dnsQuery(t, addr, "hang.example.org.", dns.TypeA)
		if resp.Rcode != dns.RcodeServerFailure {
			t.Errorf("cancelled forward: want SERVFAIL, got rcode=%d", resp.Rcode)
		}
		done <- time.Since(start)
	}()

	time.Sleep(150 * time.Millisecond) // let the forward get in flight
	cancel()

	select {
	case elapsed := <-done:
		if elapsed > 2*time.Second {
			t.Fatalf("forward did not cancel on ctx cancel: took %v", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not return after ctx cancel")
	}
}

// newBigServer serves a static name with many A records (a >512B answer) so the
// EDNS/TC path (D2) can be exercised. Returns the UDP and TCP listener addresses.
func newBigServer(t *testing.T) (udpAddr, tcpAddr string, stop func()) {
	t.Helper()
	upAddr, stopUp := upstream(t)
	fwd := forwarder.NewWithUpstreams([]forwarder.Upstream{{Addr: upAddr, Net: "udp"}}, nil, false, nil)
	const nRecs = 60
	recs := make([]model.RR, 0, nRecs)
	for i := 0; i < nRecs; i++ {
		recs = append(recs, model.RR{Type: dns.TypeA, Class: dns.ClassINET, TTL: 300,
			Content: net.IPv4(203, 0, byte(i>>8), byte(i)).String()})
	}
	snap := &model.Snapshot{Static: map[string][]model.RR{"big.example.test.": recs}}
	s := New(Config{
		Access:    netmatch.Access{Allow: mustSet(t, "127.0.0.0/8")},
		Snapshot:  func() *model.Snapshot { return snap },
		View:      func() *model.MDNSView { return &model.MDNSView{} },
		Forwarder: fwd,
	})
	if err := s.Start([]string{"127.0.0.1:0"}, true, true); err != nil {
		t.Fatalf("start: %v", err)
	}
	for _, a := range s.BoundAddrs() {
		switch a.(type) {
		case *net.UDPAddr:
			udpAddr = a.String()
		case *net.TCPAddr:
			tcpAddr = a.String()
		}
	}
	return udpAddr, tcpAddr, func() { s.Shutdown(); stopUp() }
}

// TestEDNSTruncation pins D2: an oversized authoritative answer over UDP with a
// small EDNS bufsize sets TC and trims; the server echoes an OPT; TCP returns the
// full RRset.
func TestEDNSTruncation(t *testing.T) {
	udpAddr, tcpAddr, stop := newBigServer(t)
	defer stop()

	// EDNS bufsize 512 over UDP → must truncate and set TC, with a server OPT.
	m := new(dns.Msg)
	m.SetQuestion("big.example.test.", dns.TypeA)
	m.SetEdns0(512, false)
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second, UDPSize: 512}
	resp, _, err := c.Exchange(m, udpAddr)
	if err != nil {
		t.Fatalf("udp exchange: %v", err)
	}
	if !resp.Truncated {
		t.Errorf("oversized UDP answer must set TC")
	}
	if resp.IsEdns0() == nil {
		t.Errorf("server must echo an OPT to an EDNS client")
	}
	if len(resp.Answer) >= 60 {
		t.Errorf("answer should be trimmed to fit 512B, got %d records", len(resp.Answer))
	}

	// Same query over TCP → full RRset, no truncation.
	mt := new(dns.Msg)
	mt.SetQuestion("big.example.test.", dns.TypeA)
	mt.SetEdns0(4096, false)
	ct := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	rt, _, err := ct.Exchange(mt, tcpAddr)
	if err != nil {
		t.Fatalf("tcp exchange: %v", err)
	}
	if rt.Truncated {
		t.Errorf("TCP answer must not set TC")
	}
	if len(rt.Answer) != 60 {
		t.Errorf("TCP must return the full RRset, got %d records", len(rt.Answer))
	}
}

// TestClassicClientNoOPT pins that a non-EDNS (classic) client never gets a
// volunteered OPT in the reply.
func TestClassicClientNoOPT(t *testing.T) {
	_, addr, stop := newServer(t, allowLoopback(t))
	defer stop()
	m := new(dns.Msg)
	m.SetQuestion("gw.example.test.", dns.TypeA) // small static answer
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.IsEdns0() != nil {
		t.Errorf("classic client must not receive an OPT")
	}
}

func TestServerRefusesDisallowedClient(t *testing.T) {
	// Allow only 10/8 — the loopback test client is refused.
	allow, _ := netmatch.ParseSet([]string{"10.0.0.0/8"})
	_, addr, stop := newServer(t, netmatch.Access{Allow: allow})
	defer stop()
	resp := dnsQuery(t, addr, "gw.example.test.", dns.TypeA)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("disallowed client: want REFUSED, got rcode=%d", resp.Rcode)
	}
}

func TestServerTCP(t *testing.T) {
	s, _, stop := newServer(t, allowLoopback(t))
	defer stop()
	// With ephemeral port 0, UDP and TCP bind different ports; pick the TCP one.
	var tcpAddr string
	for _, a := range s.BoundAddrs() {
		if _, ok := a.(*net.TCPAddr); ok {
			tcpAddr = a.String()
		}
	}
	if tcpAddr == "" {
		t.Fatal("no TCP listener bound")
	}
	m := new(dns.Msg)
	m.SetQuestion("gw.example.test.", dns.TypeA)
	c := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, tcpAddr)
	if err != nil {
		t.Fatalf("tcp exchange: %v", err)
	}
	if got := aContents(resp); len(got) != 1 || got[0] != "203.0.113.99" {
		t.Fatalf("tcp static answer = %v", got)
	}
}
