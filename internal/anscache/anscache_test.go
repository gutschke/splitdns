package anscache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// clock is a controllable time source for deterministic TTL tests.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestCache(cfg Config) (*Cache, *clock) {
	clk := &clock{t: time.Unix(1_000_000, 0)}
	return New(cfg, clk.now), clk
}

func aRecord(name string, ttl uint32, ip string) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP(ip)}
}

func soa(name string, hdrTTL, minTTL uint32) dns.RR {
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: hdrTTL},
		Ns:  "ns." + name, Mbox: "hostmaster." + name, Minttl: minTTL,
	}
}

func reply(name string, qtype uint16, rcode int, ans, ns []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Response = true
	m.Rcode = rcode
	m.Answer = ans
	m.Ns = ns
	return m
}

func keyFor(t *testing.T, name string, qtype uint16) Key {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	k, ok := KeyFor(q)
	if !ok {
		t.Fatalf("KeyFor(%s/%d) not cacheable-shaped", name, qtype)
	}
	return k
}

// Positive caching: a fresh hit returns the answer with TTLs decremented by age.
func TestPositiveCacheFreshAndDecrement(t *testing.T) {
	c, clk := newTestCache(Defaults())
	k := keyFor(t, "example.com.", dns.TypeA)
	c.Store(k, reply("example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("example.com.", 300, "1.2.3.4")}, nil))

	clk.add(10 * time.Second)
	msg, res := c.Lookup(k)
	if res != Fresh {
		t.Fatalf("res = %v, want Fresh", res)
	}
	if got := msg.Answer[0].Header().Ttl; got != 290 {
		t.Errorf("served TTL = %d, want 290 (300 - 10s age)", got)
	}
}

// The MinTTL floor keeps a TTL-1 record cached for the full floor (herd protection).
func TestMinTTLFloor(t *testing.T) {
	c, clk := newTestCache(Config{ServeStale: false}) // floor defaults to 5s
	k := keyFor(t, "cdn.example.", dns.TypeA)
	c.Store(k, reply("cdn.example.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("cdn.example.", 1, "1.2.3.4")}, nil))

	clk.add(3 * time.Second)
	if _, res := c.Lookup(k); res != Fresh {
		t.Errorf("at 3s a TTL-1 record floored to 5s must be Fresh, got %v", res)
	}
	clk.add(3 * time.Second) // now 6s, past the 5s floor
	if _, res := c.Lookup(k); res != Miss {
		t.Errorf("at 6s (>5s floor, no serve-stale) must be Miss, got %v", res)
	}
}

// NXDOMAIN with an SOA is negatively cached using the SOA minimum (RFC 2308).
func TestNegativeCacheNXDOMAIN(t *testing.T) {
	c, clk := newTestCache(Defaults())
	k := keyFor(t, "nope.example.com.", dns.TypeA)
	c.Store(k, reply("nope.example.com.", dns.TypeA, dns.RcodeNameError, nil,
		[]dns.RR{soa("example.com.", 3600, 30)}))

	if _, res := c.Lookup(k); res != Fresh {
		t.Fatalf("NXDOMAIN must be cached, got %v", res)
	}
	clk.add(20 * time.Second) // < 30s SOA minimum
	if _, res := c.Lookup(k); res != Fresh {
		t.Errorf("within negative TTL must stay Fresh, got %v", res)
	}
	clk.add(20 * time.Second) // now 40s > 30s, serve-stale window kicks in
	if _, res := c.Lookup(k); res != Stale {
		t.Errorf("expired negative within stale window must be Stale, got %v", res)
	}
}

// A negative answer with NO SOA cannot derive a TTL and must not be cached.
func TestNegativeNoSOANotCached(t *testing.T) {
	c, _ := newTestCache(Defaults())
	k := keyFor(t, "nope.example.com.", dns.TypeA)
	c.Store(k, reply("nope.example.com.", dns.TypeA, dns.RcodeNameError, nil, nil))
	if _, res := c.Lookup(k); res != Miss {
		t.Errorf("NXDOMAIN without SOA must not be cached, got %v", res)
	}
}

// NODATA (NOERROR + empty answer) caches off the authority SOA.
func TestNODATACaching(t *testing.T) {
	c, _ := newTestCache(Defaults())
	k := keyFor(t, "example.com.", dns.TypeAAAA)
	c.Store(k, reply("example.com.", dns.TypeAAAA, dns.RcodeSuccess, nil,
		[]dns.RR{soa("example.com.", 3600, 60)}))
	if _, res := c.Lookup(k); res != Fresh {
		t.Errorf("NODATA with SOA must be cached, got %v", res)
	}
}

func cname(name string, ttl uint32, target string) dns.RR {
	return &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}, Target: target}
}

// A NOERROR answer that terminates in a CNAME with no terminal record of the queried
// type is NODATA — cache it off the SOA (bounded by the negative cap), not positive off
// the CNAME's TTL.
func TestCNAMEOnlyIsNegative(t *testing.T) {
	c, clk := newTestCache(Defaults())
	k := keyFor(t, "www.example.com.", dns.TypeA)
	// CNAME present (TTL 3600), but NO A for the target; SOA minimum 30s.
	c.Store(k, reply("www.example.com.", dns.TypeA, dns.RcodeSuccess,
		[]dns.RR{cname("www.example.com.", 3600, "host.example.com.")},
		[]dns.RR{soa("example.com.", 3600, 30)}))

	if _, res := c.Lookup(k); res != Fresh {
		t.Fatalf("CNAME-only NODATA must be cached, got %v", res)
	}
	// It must expire on the SOA negative TTL (30s), NOT the CNAME's 3600s.
	clk.add(31 * time.Second)
	if _, res := c.Lookup(k); res == Fresh {
		t.Error("CNAME-only NODATA cached with the CNAME TTL (3600) instead of the negative TTL (30)")
	}
}

// A NOERROR answer that DOES include the requested type (after a CNAME) is positive.
func TestCNAMEChainWithTerminalIsPositive(t *testing.T) {
	c, _ := newTestCache(Defaults())
	k := keyFor(t, "www.example.com.", dns.TypeA)
	c.Store(k, reply("www.example.com.", dns.TypeA, dns.RcodeSuccess,
		[]dns.RR{cname("www.example.com.", 300, "host.example.com."), aRecord("host.example.com.", 300, "1.2.3.4")}, nil))
	if _, res := c.Lookup(k); res != Fresh {
		t.Errorf("CNAME chain ending in an A must be cached positive, got %v", res)
	}
}

// An out-of-bailiwick SOA (owner not at/above the qname) is rejected — it cannot forge a
// negative entry.
func TestNegativeRejectsOutOfBailiwickSOA(t *testing.T) {
	c, _ := newTestCache(Defaults())
	k := keyFor(t, "nope.example.com.", dns.TypeA)
	// SOA owner "evil.test." is unrelated to the queried example.com.
	c.Store(k, reply("nope.example.com.", dns.TypeA, dns.RcodeNameError, nil,
		[]dns.RR{soa("evil.test.", 3600, 30)}))
	if _, res := c.Lookup(k); res != Miss {
		t.Errorf("NXDOMAIN with an out-of-bailiwick SOA must not be cached, got %v", res)
	}
}

// Non-IN class queries are not cacheable-shaped.
func TestNonINETClassNotCacheable(t *testing.T) {
	q := new(dns.Msg)
	q.Question = []dns.Question{{Name: "version.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}
	if _, ok := KeyFor(q); ok {
		t.Error("CHAOS-class query must not be cacheable-shaped")
	}
}

// Serve-stale: expired-but-within-window returns Stale; beyond the window it's gone.
func TestServeStaleWindow(t *testing.T) {
	c, clk := newTestCache(Config{ServeStale: true, StaleMaxAge: time.Minute})
	k := keyFor(t, "example.com.", dns.TypeA)
	c.Store(k, reply("example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("example.com.", 10, "1.2.3.4")}, nil))

	clk.add(15 * time.Second) // expired (TTL 10), within 60s stale window
	msg, res := c.Lookup(k)
	if res != Stale {
		t.Fatalf("res = %v, want Stale", res)
	}
	if got := msg.Answer[0].Header().Ttl; got != 30 {
		t.Errorf("stale answer TTL = %d, want 30 (RFC 8767 stamp)", got)
	}
	clk.add(60 * time.Second) // now 75s > 10s TTL + 60s window
	if _, res := c.Lookup(k); res != Miss {
		t.Errorf("beyond stale window must be Miss, got %v", res)
	}
}

// Failure caching: StoreFail yields Fail within FailTTL, then Miss (RFC 9520).
func TestFailureCaching(t *testing.T) {
	c, clk := newTestCache(Config{FailTTL: 5 * time.Second})
	k := keyFor(t, "broken.example.", dns.TypeA)
	c.StoreFail(k)
	if _, res := c.Lookup(k); res != Fail {
		t.Fatalf("res = %v, want Fail", res)
	}
	clk.add(6 * time.Second)
	if _, res := c.Lookup(k); res != Miss {
		t.Errorf("expired failure must be Miss, got %v", res)
	}
}

// The DO bit is part of the key: DO=1 and DO=0 are independent entries.
func TestDOBitKeying(t *testing.T) {
	c, _ := newTestCache(Defaults())
	base := keyFor(t, "example.com.", dns.TypeA)
	doKey := base
	doKey.DO = true
	c.Store(base, reply("example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("example.com.", 300, "1.2.3.4")}, nil))

	if _, res := c.Lookup(doKey); res != Miss {
		t.Errorf("DO=1 must not hit a DO=0 entry, got %v", res)
	}
	if _, res := c.Lookup(base); res != Fresh {
		t.Errorf("DO=0 entry must hit, got %v", res)
	}
}

// Uncacheable shapes (truncated, ANY, multi-question) are silently not stored.
func TestUncacheableNotStored(t *testing.T) {
	c, _ := newTestCache(Defaults())

	// Truncated.
	k := keyFor(t, "example.com.", dns.TypeA)
	tc := reply("example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("example.com.", 300, "1.2.3.4")}, nil)
	tc.Truncated = true
	c.Store(k, tc)
	if _, res := c.Lookup(k); res != Miss {
		t.Errorf("truncated response must not be cached, got %v", res)
	}

	// ANY is not even key-able.
	any := new(dns.Msg)
	any.SetQuestion("example.com.", dns.TypeANY)
	if _, ok := KeyFor(any); ok {
		t.Error("ANY query must not be cacheable-shaped")
	}

	// Multi-question.
	mq := new(dns.Msg)
	mq.Question = []dns.Question{
		{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	if _, ok := KeyFor(mq); ok {
		t.Error("multi-question must not be cacheable-shaped")
	}
}

// The upstream OPT pseudo-RR is stripped before storing.
func TestOPTStrippedOnStore(t *testing.T) {
	c, _ := newTestCache(Defaults())
	k := keyFor(t, "example.com.", dns.TypeA)
	r := reply("example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("example.com.", 300, "1.2.3.4")}, nil)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(4096)
	r.Extra = append(r.Extra, opt)
	c.Store(k, r)

	msg, _ := c.Lookup(k)
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			t.Error("cached message must not retain the upstream OPT RR")
		}
	}
}

// LRU eviction bounds the cache and drops the least-recently-used entry.
func TestLRUEviction(t *testing.T) {
	c, _ := newTestCache(Config{MaxEntries: 2})
	mk := func(n string) Key { return keyFor(t, n, dns.TypeA) }
	store := func(n string) {
		c.Store(mk(n), reply(n, dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord(n, 300, "1.2.3.4")}, nil))
	}
	store("a.example.")
	store("b.example.")
	c.Lookup(mk("a.example.")) // touch a => b is now LRU
	store("c.example.")        // evicts b

	if _, res := c.Lookup(mk("b.example.")); res != Miss {
		t.Errorf("b should have been evicted as LRU, got %v", res)
	}
	if _, res := c.Lookup(mk("a.example.")); res != Fresh {
		t.Errorf("a was recently used and must survive, got %v", res)
	}
	if s := c.Stats(); s.Entries != 2 || s.Evictions == 0 {
		t.Errorf("stats: entries=%d evictions=%d, want entries=2 evictions>=1", s.Entries, s.Evictions)
	}
}

// Stats track hits and misses.
func TestStatsHitsMisses(t *testing.T) {
	c, _ := newTestCache(Defaults())
	k := keyFor(t, "example.com.", dns.TypeA)
	c.Lookup(k) // miss
	c.Store(k, reply("example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("example.com.", 300, "1.2.3.4")}, nil))
	c.Lookup(k) // hit
	c.Lookup(k) // hit
	s := c.Stats()
	if s.Hits != 2 || s.Misses != 1 {
		t.Errorf("hits=%d misses=%d, want 2/1", s.Hits, s.Misses)
	}
}

// Peek returns a fresh entry without recording stats or reordering LRU.
func TestPeek(t *testing.T) {
	c, clk := newTestCache(Defaults())
	k := keyFor(t, "host.example.", dns.TypeA)
	if _, ok := c.Peek(k); ok {
		t.Error("peek of an empty cache should miss")
	}
	c.Store(k, reply("host.example.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("host.example.", 300, "1.2.3.4")}, nil))

	if msg, ok := c.Peek(k); !ok || len(msg.Answer) == 0 {
		t.Fatalf("peek should return the stored answer, ok=%v", ok)
	}
	if s := c.Stats(); s.Hits != 0 || s.Misses != 0 {
		t.Errorf("Peek must not record stats, got %+v", s)
	}
	clk.add(400 * time.Second) // past TTL
	if _, ok := c.Peek(k); ok {
		t.Error("peek of an expired entry should miss")
	}
}

// Flush empties the cache.
func TestFlush(t *testing.T) {
	c, _ := newTestCache(Defaults())
	k := keyFor(t, "example.com.", dns.TypeA)
	c.Store(k, reply("example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("example.com.", 300, "1.2.3.4")}, nil))
	c.Lookup(k) // generate a hit so stats are non-zero
	c.Flush()
	if _, res := c.Lookup(k); res != Miss {
		t.Errorf("after Flush lookup must Miss, got %v", res)
	}
	// Flush zeroes the counters too (the post-Lookup miss above is the only stat now).
	if s := c.Stats(); s.Hits != 0 || s.Inserts != 0 || s.Entries != 0 {
		t.Errorf("after Flush stats should be reset, got %+v", s)
	}
}

// Entries lists what's actually cached, hottest first, with kind/liveness — and it
// neither records stats nor reorders the LRU (so polling it is side-effect-free).
func TestEntriesHotListing(t *testing.T) {
	c, clk := newTestCache(Defaults())
	kA := keyFor(t, "hot.example.", dns.TypeA)
	kB := keyFor(t, "cold.example.", dns.TypeA)
	c.Store(kA, reply("hot.example.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("hot.example.", 300, "1.2.3.4")}, nil))
	c.Store(kB, reply("cold.example.", dns.TypeA, dns.RcodeSuccess, []dns.RR{aRecord("cold.example.", 300, "5.6.7.8")}, nil))
	// Make A hot: three hits vs none for B.
	for i := 0; i < 3; i++ {
		if _, res := c.Lookup(kA); res != Fresh {
			t.Fatalf("lookup A: res = %v, want Fresh", res)
		}
	}
	statsBefore := c.Stats()

	es := c.Entries(0)
	if len(es) != 2 {
		t.Fatalf("Entries returned %d, want 2", len(es))
	}
	if es[0].Name != "hot.example." || es[0].Hits != 3 {
		t.Errorf("hottest = %+v, want hot.example. with 3 hits", es[0])
	}
	if es[0].Type != "A" || es[0].Kind != "positive" || !es[0].Live {
		t.Errorf("entry classification wrong: %+v", es[0])
	}
	if es[1].Name != "cold.example." || es[1].Hits != 0 {
		t.Errorf("second = %+v, want cold.example. with 0 hits", es[1])
	}
	// Read-only: listing must not have moved the hit counters.
	if after := c.Stats(); after.Hits != statsBefore.Hits || after.Misses != statsBefore.Misses {
		t.Errorf("Entries mutated stats: before %+v after %+v", statsBefore, after)
	}

	// n caps the result.
	if got := c.Entries(1); len(got) != 1 || got[0].Name != "hot.example." {
		t.Errorf("Entries(1) = %+v, want just the hottest", got)
	}

	// An expired-but-stale-eligible entry reports Live=false.
	clk.add(400 * time.Second)
	for _, e := range c.Entries(0) {
		if e.Live {
			t.Errorf("entry %s should be expired (Live=false) after TTL elapsed", e.Name)
		}
	}
}
