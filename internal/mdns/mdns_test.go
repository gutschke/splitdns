package mdns

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// announce builds the same authoritative mDNS response packet that
// splitdns-notify(8) emits, so the tests exercise the real on-wire format.
func announce(t *testing.T, host string, addrs ...string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.Response = true
	m.Authoritative = true
	for _, s := range addrs {
		a := netip.MustParseAddr(s)
		hdr := dns.RR_Header{Name: host, Class: dns.ClassINET, Ttl: 120}
		if a.Is4() {
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IP(a.AsSlice())})
		} else {
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(a.AsSlice())})
		}
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return b
}

func TestParsePacket(t *testing.T) {
	m := new(dns.Msg)
	m.Response = true
	add := func(name string, rr dns.RR) { m.Answer = append(m.Answer, rr) }
	add("router.local.", &dns.A{Hdr: dns.RR_Header{Name: "router.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 90}, A: net.ParseIP("192.0.2.10")})
	add("router.local.", &dns.AAAA{Hdr: dns.RR_Header{Name: "router.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP("2001:db8::1")})
	add("router.local.", &dns.AAAA{Hdr: dns.RR_Header{Name: "router.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP("fe80::1")}) // link-local dropped
	add("_svc._tcp.local.", &dns.A{Hdr: dns.RR_Header{Name: "_svc._tcp.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("192.0.2.20")}) // service name dropped
	b, _ := m.Pack()

	got := ParsePacket(b)
	if len(got) != 1 || got[0].Host != "router" {
		t.Fatalf("want single host 'router', got %+v", got)
	}
	if len(got[0].Addrs) != 2 {
		t.Fatalf("want 2 addrs (fe80 dropped), got %v", got[0].Addrs)
	}
	if got[0].TTL != 90 {
		t.Errorf("want min TTL 90, got %d", got[0].TTL)
	}
}

func TestParseRejectsQueries(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("router.local.", dns.TypeA) // QR=0 query, not a response
	b, _ := q.Pack()
	if got := ParsePacket(b); len(got) != 0 {
		t.Errorf("query packet must yield no announcements, got %+v", got)
	}
	if got := ParsePacket([]byte{0x01, 0x02}); len(got) != 0 {
		t.Errorf("garbage must yield no announcements")
	}
}

type changeRec struct {
	mu     sync.Mutex
	events []string // "host:csv-addrs"
}

func (c *changeRec) fn(host string, addrs []netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, host+":"+joinAddrs(addrs))
}
func (c *changeRec) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return ""
	}
	return c.events[len(c.events)-1]
}
func (c *changeRec) count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.events) }

func TestCacheApplyChangeAndIdempotency(t *testing.T) {
	rec := &changeRec{}
	c := NewCache(rec.fn)
	t0 := time.Unix(1000, 0)

	if !c.Apply(Announcement{Host: "edge", Addrs: ma("192.0.2.10"), TTL: 120}, t0, TrustWeak) {
		t.Fatal("first apply should report change")
	}
	if rec.last() != "edge:192.0.2.10" {
		t.Errorf("unexpected change event %q", rec.last())
	}
	// Same set again: no change, no new event.
	if c.Apply(Announcement{Host: "edge", Addrs: ma("192.0.2.10"), TTL: 120}, t0.Add(time.Second), TrustWeak) {
		t.Error("identical apply should not report change")
	}
	if rec.count() != 1 {
		t.Errorf("idempotent apply fired an extra event: %d", rec.count())
	}
	// New set after the burst window: replaces, fires change.
	if !c.Apply(Announcement{Host: "edge", Addrs: ma("198.51.100.5"), TTL: 120}, t0.Add(10*time.Second), TrustWeak) {
		t.Error("changed set should report change")
	}
	if rec.last() != "edge:198.51.100.5" {
		t.Errorf("replace failed, got %q", rec.last())
	}
}

// TestCacheTTLClamp pins D12: an oversized announced TTL is clamped to maxTTL so a
// hostile responder cannot pin an entry indefinitely.
func TestCacheTTLClamp(t *testing.T) {
	c := NewCache(nil)
	t0 := time.Unix(1000, 0)
	c.Apply(Announcement{Host: "evil", Addrs: ma("192.0.2.10"), TTL: 999999}, t0, TrustWeak)
	v := c.View(t0)
	recs := v.Forward["evil"]
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].TTL > maxTTL {
		t.Errorf("served TTL %d exceeds clamp %d", recs[0].TTL, maxTTL)
	}
}

// TestCacheLRUEviction pins D12: at capacity a new host evicts the least-recently
// seen host instead of being dropped forever.
func TestCacheLRUEviction(t *testing.T) {
	c := NewCache(nil)
	base := time.Unix(10000, 0)
	// Fill to capacity; host i seen at base+i so "h0" is least-recently-seen.
	for i := 0; i < maxHosts; i++ {
		c.Apply(Announcement{Host: hostName(i), Addrs: ma("192.0.2.10"), TTL: 120}, base.Add(time.Duration(i)*time.Second), TrustWeak)
	}
	if c.Len() != maxHosts {
		t.Fatalf("expected full cache %d, got %d", maxHosts, c.Len())
	}
	// One more distinct host must be admitted (evicting the LRU victim h0).
	newcomer := "newcomer"
	if !c.Apply(Announcement{Host: newcomer, Addrs: ma("198.51.100.5"), TTL: 120}, base.Add(time.Hour), TrustWeak) {
		t.Fatal("newcomer at capacity should be admitted (change reported)")
	}
	if c.Len() != maxHosts {
		t.Errorf("cache should stay at cap %d, got %d", maxHosts, c.Len())
	}
	v := c.View(base.Add(time.Hour))
	if len(v.Forward[newcomer]) == 0 {
		t.Errorf("newcomer was not admitted")
	}
	if len(v.Forward[hostName(0)]) != 0 {
		t.Errorf("LRU victim h0 should have been evicted")
	}
}

func hostName(i int) string {
	return "h" + strconv.Itoa(i)
}

// TestCacheUntrustedNoTrigger pins D7: an untrusted announcement updates the
// *.local view but must NOT fire the DDNS trigger; a trusted one does.
func TestCacheUntrustedNoTrigger(t *testing.T) {
	rec := &changeRec{}
	c := NewCache(rec.fn)
	t0 := time.Unix(1000, 0)

	c.Apply(Announcement{Host: "edge", Addrs: ma("9.9.9.9"), TTL: 120}, t0, TrustNone)
	if rec.count() != 0 {
		t.Errorf("untrusted announcement must not fire the DDNS trigger, got %d", rec.count())
	}
	if v := c.View(t0); len(v.Forward["edge"]) != 1 {
		t.Errorf("untrusted announcement should still update the *.local view")
	}
	// A trusted announcement with a different address fires the trigger.
	c.Apply(Announcement{Host: "edge", Addrs: ma("8.8.8.8"), TTL: 120}, t0.Add(10*time.Second), TrustWeak)
	if rec.count() != 1 {
		t.Errorf("trusted announcement should fire the trigger, got %d", rec.count())
	}
}

func TestCacheBurstUnion(t *testing.T) {
	rec := &changeRec{}
	c := NewCache(rec.fn)
	t0 := time.Unix(2000, 0)
	c.Apply(Announcement{Host: "edge", Addrs: ma("192.0.2.10"), TTL: 120}, t0, TrustWeak)
	// Within burst window an A and AAAA from separate packets union.
	c.Apply(Announcement{Host: "edge", Addrs: ma("2001:db8::1"), TTL: 120}, t0.Add(2*time.Second), TrustWeak)
	if got := rec.last(); got != "edge:192.0.2.10,2001:db8::1" {
		t.Errorf("burst union failed, got %q", got)
	}
}

func TestCacheExpire(t *testing.T) {
	rec := &changeRec{}
	c := NewCache(rec.fn)
	t0 := time.Unix(3000, 0)
	c.Apply(Announcement{Host: "edge", Addrs: ma("192.0.2.10"), TTL: 30}, t0, TrustWeak)
	if n := c.Expire(t0.Add(10 * time.Second)); n != 0 {
		t.Fatalf("premature expiry: %d", n)
	}
	if n := c.Expire(t0.Add(40 * time.Second)); n != 1 {
		t.Fatalf("want 1 expired, got %d", n)
	}
	if c.Len() != 0 {
		t.Errorf("host not removed")
	}
	if rec.last() != "edge:" {
		t.Errorf("expiry should fire empty-set change, got %q", rec.last())
	}
}

func TestView(t *testing.T) {
	c := NewCache(nil)
	t0 := time.Unix(4000, 0)
	c.Apply(Announcement{Host: "edge", Addrs: ma("192.0.2.10", "2001:db8::1"), TTL: 120}, t0, TrustWeak)
	v := c.View(t0)
	fwd := v.Forward["edge"]
	if len(fwd) != 2 {
		t.Fatalf("want 2 forward RRs, got %d", len(fwd))
	}
	if fwd[0].Name != "edge.local." {
		t.Errorf("forward RR name = %q, want edge.local.", fwd[0].Name)
	}
	arpa, _ := dns.ReverseAddr("192.0.2.10")
	ptr := v.Reverse[arpa]
	if len(ptr) != 1 || ptr[0].Type != dns.TypePTR || ptr[0].Content != "edge.local." {
		t.Fatalf("reverse PTR wrong: %+v", ptr)
	}
}

// TestListenerLoopbackUnicast proves the real socket path: a packet sent by unicast
// to the bound port (the cross-subnet path splitdns-notify relies on) updates the
// published view.
func TestListenerLoopbackUnicast(t *testing.T) {
	src := NewSource(nil, nil)
	// nil trusted matcher: view still updates, DDNS triggering is irrelevant here.
	l, err := Listen(src, 0, nil, nil, false, func(string) {})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()
	port := l.Port()
	if port == 0 {
		t.Fatal("no bound port")
	}

	conn, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(announce(t, "edge.local.", "192.0.2.10", "2001:db8::1")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v := src.View(); v != nil && len(v.Forward["edge"]) == 2 {
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("view did not reflect the unicast announcement; forward=%v", src.View().Forward)
}

func ma(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}
