// Package anscache is the forward-path answer cache: a DNS MESSAGE cache for queries
// the resolver forwards to public upstreams. It implements TTL caching with a floor
// and cap, negative caching of NXDOMAIN/NODATA from the SOA minimum (RFC 2308), brief
// failure caching of SERVFAIL to protect a flapping upstream (RFC 9520), and serve-
// stale on upstream failure (RFC 8767) to match the daemon's fail-static posture.
//
// It deliberately caches the RAW upstream answer (pre rebind-filter): the §4.2 rebind
// filter and EDNS/OPT re-stamping are applied by the server on EGRESS for every serve,
// so a policy change takes effect immediately and cache hits and live misses go through
// the identical output path. The authoritative/local planes never enter this cache —
// only the forward path does.
package anscache

import (
	"container/list"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Config tunes the cache. Durations follow the DNS-expert brief defaults.
type Config struct {
	MaxEntries  int           // LRU capacity (default 10000)
	MinTTL      time.Duration // positive floor (default 5s) — herd protection on TTL 0/1
	MaxTTL      time.Duration // positive cap (default 24h)
	NegMinTTL   time.Duration // negative floor (default 5s)
	NegMaxTTL   time.Duration // negative cap (default 1h)
	FailTTL     time.Duration // SERVFAIL/failure cache (default 5s, RFC 9520 hard cap 5m)
	ServeStale  bool          // serve expired data on upstream failure (default true)
	StaleTTL    time.Duration // TTL stamped on a stale answer (default 30s, RFC 8767)
	StaleMaxAge time.Duration // how long past expiry an entry stays serve-stale-eligible (default 24h)
}

// Defaults returns the brief's recommended defaults.
func Defaults() Config {
	return Config{
		MaxEntries:  10000,
		MinTTL:      5 * time.Second,
		MaxTTL:      24 * time.Hour,
		NegMinTTL:   5 * time.Second,
		NegMaxTTL:   time.Hour,
		FailTTL:     5 * time.Second,
		ServeStale:  true,
		StaleTTL:    30 * time.Second,
		StaleMaxAge: 24 * time.Hour,
	}
}

// Key identifies a cached message. Name is lower-cased FQDN (RFC 4343); DO keys the
// DNSSEC-OK bit so a DO=1 client never gets a DO=0-shaped answer (RFC 6840).
type Key struct {
	Name   string
	Qtype  uint16
	Qclass uint16
	DO     bool
}

// KeyFor builds a cache Key from a request, reporting whether it is cacheable-shaped
// (exactly one question, not an ANY query).
func KeyFor(req *dns.Msg) (Key, bool) {
	if len(req.Question) != 1 {
		return Key{}, false
	}
	q := req.Question[0]
	if q.Qtype == dns.TypeANY || q.Qclass != dns.ClassINET {
		return Key{}, false // ANY is non-cacheable; only IN-class is cached
	}
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	return Key{Name: strings.ToLower(q.Name), Qtype: q.Qtype, Qclass: q.Qclass, DO: do}, true
}

// Result classifies a Lookup.
type Result int

const (
	Miss  Result = iota // not present (or expired beyond stale window)
	Fresh               // within TTL; msg has decremented TTLs, serve as-is
	Stale               // expired but serve-stale-eligible; serve ONLY if upstream refresh fails
	Fail                // a cached failure (SERVFAIL); return SERVFAIL without forwarding (RFC 9520)
)

type kind int

const (
	kindPositive kind = iota
	kindNegative
	kindFail
)

type entry struct {
	key        Key
	msg        *dns.Msg // nil for kindFail
	insertedAt time.Time
	ttl        time.Duration
	kind       kind
	hits       uint64
}

// Stats is a point-in-time snapshot of cache counters.
type Stats struct {
	Hits        uint64 `json:"hits"`
	Misses      uint64 `json:"misses"`
	StaleServes uint64 `json:"stale_serves"`
	FailHits    uint64 `json:"fail_hits"`
	Inserts     uint64 `json:"inserts"`
	Evictions   uint64 `json:"evictions"`
	Entries     int    `json:"entries"`
	Capacity    int    `json:"capacity"`
}

// Cache is a bounded LRU message cache. Safe for concurrent use.
type Cache struct {
	cfg Config
	now func() time.Time

	mu    sync.Mutex
	ll    *list.List // front = most-recently-used
	m     map[Key]*list.Element
	stats Stats
}

// New builds a Cache. now may be nil (time.Now). Zero/negative config fields fall back
// to Defaults() field-by-field, so a partial Config is fine.
func New(cfg Config, now func() time.Time) *Cache {
	d := Defaults()
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = d.MaxEntries
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = d.MinTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = d.MaxTTL
	}
	if cfg.NegMinTTL <= 0 {
		cfg.NegMinTTL = d.NegMinTTL
	}
	if cfg.NegMaxTTL <= 0 {
		cfg.NegMaxTTL = d.NegMaxTTL
	}
	if cfg.FailTTL <= 0 {
		cfg.FailTTL = d.FailTTL
	}
	if cfg.FailTTL > 5*time.Minute {
		cfg.FailTTL = 5 * time.Minute // RFC 9520 §4 ceiling
	}
	if cfg.StaleTTL <= 0 {
		cfg.StaleTTL = d.StaleTTL
	}
	if cfg.StaleMaxAge <= 0 {
		cfg.StaleMaxAge = d.StaleMaxAge
	}
	if now == nil {
		now = time.Now
	}
	return &Cache{cfg: cfg, now: now, ll: list.New(), m: map[Key]*list.Element{}}
}

// Lookup returns a cached answer for k. For Fresh the returned *dns.Msg has its TTLs
// decremented and is ready to serve (Id still 0; the caller sets it). For Stale the
// TTLs are stamped to StaleTTL and the caller serves it ONLY if a refresh fails. For
// Fail/Miss the message is nil.
func (c *Cache) Lookup(k Key) (*dns.Msg, Result) {
	now := c.now() // snapshot the clock OUTSIDE the lock (don't hold c.mu across now())
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[k]
	if !ok {
		c.stats.Misses++
		return nil, Miss
	}
	e := el.Value.(*entry)
	age := now.Sub(e.insertedAt)

	if e.kind == kindFail {
		if age < e.ttl {
			c.ll.MoveToFront(el)
			e.hits++
			c.stats.FailHits++
			return nil, Fail
		}
		c.removeEl(el)
		c.stats.Misses++
		return nil, Miss
	}

	if age < e.ttl {
		c.ll.MoveToFront(el)
		e.hits++
		c.stats.Hits++
		return decrementTTL(e.msg, age), Fresh
	}

	// Expired. Keep it as a serve-stale candidate within the retention window.
	if c.cfg.ServeStale && age < e.ttl+c.cfg.StaleMaxAge {
		c.ll.MoveToFront(el)
		return stampTTL(e.msg, c.cfg.StaleTTL), Stale
	}

	// Dead beyond the stale window.
	c.removeEl(el)
	c.stats.Misses++
	return nil, Miss
}

// NoteStaleServed records that a Stale candidate was actually served (the upstream
// refresh failed). Counting here, not in Lookup, keeps the metric to real activations.
func (c *Cache) NoteStaleServed() {
	c.mu.Lock()
	c.stats.StaleServes++
	c.mu.Unlock()
}

// Store caches a successful upstream answer (NOERROR/NXDOMAIN). It validates
// cacheability and computes the TTL internally; non-cacheable messages are ignored.
func (c *Cache) Store(k Key, resp *dns.Msg) {
	ttl, knd, ok := c.cacheable(resp)
	if !ok {
		return
	}
	m := resp.Copy()
	stripOPT(m)
	m.Id = 0
	c.put(&entry{key: k, msg: m, insertedAt: c.now(), ttl: ttl, kind: knd})
}

// StoreFail caches a brief failure marker so a flapping upstream is not hammered
// (RFC 9520). Used when the upstream errored/SERVFAILed AND no stale answer exists.
func (c *Cache) StoreFail(k Key) {
	c.put(&entry{key: k, insertedAt: c.now(), ttl: c.cfg.FailTTL, kind: kindFail})
}

// Peek returns a fresh cached answer for k WITHOUT recording stats or touching LRU
// order — for read-only introspection (e.g. resolving a client IP to a cached PTR name
// on the diagnostics page). Returns (nil, false) for a miss, an expired entry, or a
// cached failure.
func (c *Cache) Peek(k Key) (*dns.Msg, bool) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[k]
	if !ok {
		return nil, false
	}
	e := el.Value.(*entry)
	if e.kind == kindFail || now.Sub(e.insertedAt) >= e.ttl {
		return nil, false
	}
	return e.msg.Copy(), true
}

// Flush drops every entry AND zeroes the counters, so the hit-ratio and friends start
// fresh after an operator flush. (Used by the diagnostics control plane.)
func (c *Cache) Flush() {
	c.mu.Lock()
	c.ll.Init()
	c.m = map[Key]*list.Element{}
	c.stats = Stats{}
	c.mu.Unlock()
}

// Stats returns a snapshot of the counters plus live size/capacity.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Entries = c.ll.Len()
	s.Capacity = c.cfg.MaxEntries
	return s
}

// EntryStat describes one live cache entry for read-only diagnostics — what is actually
// cached (and how hot it is), beyond the cumulative counters.
type EntryStat struct {
	Name string        // lower-cased FQDN
	Type string        // RR type string (A, AAAA, PTR, …)
	Kind string        // "positive", "negative", or "fail"
	DO   bool          // DNSSEC-OK keyed entry
	Hits uint64        // times this entry has been served
	Age  time.Duration // since insertion
	TTL  time.Duration // cached TTL (after floor/cap)
	Live bool          // within TTL (vs. expired-but-serve-stale-eligible)
}

// Entries returns up to n live entries, hottest first (ties broken by youngest, then
// name). It neither records stats nor reorders the LRU, so it is safe to poll. n<=0
// returns every entry.
func (c *Cache) Entries(n int) []EntryStat {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]EntryStat, 0, len(c.m))
	for k, el := range c.m {
		e := el.Value.(*entry)
		age := now.Sub(e.insertedAt)
		es := EntryStat{
			Name: k.Name, Type: dns.TypeToString[k.Qtype], DO: k.DO,
			Hits: e.hits, Age: age, TTL: e.ttl, Live: age < e.ttl,
		}
		if es.Type == "" {
			es.Type = fmt.Sprintf("TYPE%d", k.Qtype)
		}
		switch e.kind {
		case kindNegative:
			es.Kind = "negative"
		case kindFail:
			es.Kind = "fail"
		default:
			es.Kind = "positive"
		}
		out = append(out, es)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		if out[i].Age != out[j].Age {
			return out[i].Age < out[j].Age
		}
		return out[i].Name < out[j].Name
	})
	if n > 0 && n < len(out) {
		out = out[:n]
	}
	return out
}

// cacheable decides whether resp may be cached and with what TTL/kind. Rules per the
// brief: TC=1, ANY, and multi-question are never cached; only NOERROR (positive or
// NODATA) and NXDOMAIN are cached; negatives require an SOA to derive the TTL.
func (c *Cache) cacheable(resp *dns.Msg) (time.Duration, kind, bool) {
	if resp == nil || resp.Truncated || len(resp.Question) != 1 {
		return 0, 0, false
	}
	if resp.Question[0].Qtype == dns.TypeANY {
		return 0, 0, false
	}
	qname := resp.Question[0].Name
	qtype := resp.Question[0].Qtype
	switch resp.Rcode {
	case dns.RcodeSuccess:
		// Positive only if the answer actually carries an RR of the requested type
		// (after any CNAME chain). A NOERROR whose answer terminates in a CNAME with no
		// matching terminal record is NODATA (RFC 2308 §2.2), not a positive answer, and
		// must be bounded by the negative TTL, not the CNAME's TTL.
		if answersType(resp.Answer, qtype) {
			return clamp(minTTL(resp.Answer), c.cfg.MinTTL, c.cfg.MaxTTL), kindPositive, true
		}
		if soa := findSOA(resp.Ns, qname); soa != nil {
			return clamp(soaTTL(soa), c.cfg.NegMinTTL, c.cfg.NegMaxTTL), kindNegative, true
		}
		return 0, 0, false
	case dns.RcodeNameError: // NXDOMAIN
		if soa := findSOA(resp.Ns, qname); soa != nil {
			return clamp(soaTTL(soa), c.cfg.NegMinTTL, c.cfg.NegMaxTTL), kindNegative, true
		}
		return 0, 0, false
	default:
		return 0, 0, false // SERVFAIL/REFUSED/FORMERR handled via StoreFail
	}
}

// answersType reports whether any RR in the section matches qtype (so a CNAME-only
// NOERROR answer for, say, an A query is correctly recognized as NODATA).
func answersType(rrs []dns.RR, qtype uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

// put inserts/replaces e under e.key and evicts LRU when over capacity. Caller-free
// (takes the lock itself).
func (c *Cache) put(e *entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[e.key]; ok {
		el.Value = e
		c.ll.MoveToFront(el)
	} else {
		c.m[e.key] = c.ll.PushFront(e)
	}
	c.stats.Inserts++
	for c.ll.Len() > c.cfg.MaxEntries {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.removeEl(back)
		c.stats.Evictions++
	}
}

// removeEl unlinks an element. Caller holds the lock.
func (c *Cache) removeEl(el *list.Element) {
	delete(c.m, el.Value.(*entry).key)
	c.ll.Remove(el)
}

// --- TTL helpers ---

func clamp(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

// minTTL returns the smallest RR TTL across a section, as a Duration.
func minTTL(rrs []dns.RR) time.Duration {
	min := ^uint32(0)
	for _, rr := range rrs {
		if t := rr.Header().Ttl; t < min {
			min = t
		}
	}
	return time.Duration(min) * time.Second
}

func soaTTL(soa *dns.SOA) time.Duration {
	// RFC 2308 §5: negative TTL = min(SOA.MINIMUM, SOA record TTL).
	t := soa.Minttl
	if soa.Hdr.Ttl < t {
		t = soa.Hdr.Ttl
	}
	return time.Duration(t) * time.Second
}

// findSOA returns the first authority SOA that is IN-BAILIWICK for qname — its owner is
// the queried name or a parent of it. This rejects an unrelated/out-of-zone SOA a buggy
// or hostile upstream might attach to forge a negative TTL (RFC 2308 §5 expects the SOA
// from the queried name's zone).
func findSOA(rrs []dns.RR, qname string) *dns.SOA {
	qn := strings.ToLower(qname)
	for _, rr := range rrs {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		owner := strings.ToLower(soa.Hdr.Name)
		if owner == "." || qn == owner || strings.HasSuffix(qn, "."+owner) {
			return soa
		}
	}
	return nil
}

// decrementTTL returns a copy of m with every RR TTL reduced by age (floored at 1s so a
// just-expiring RR still serves briefly; the message itself is fresh by construction).
func decrementTTL(m *dns.Msg, age time.Duration) *dns.Msg {
	out := m.Copy()
	rem := uint32(age / time.Second)
	adjust := func(rrs []dns.RR) {
		for _, rr := range rrs {
			h := rr.Header()
			if h.Ttl > rem+1 {
				h.Ttl -= rem
			} else {
				h.Ttl = 1
			}
		}
	}
	adjust(out.Answer)
	adjust(out.Ns)
	adjust(out.Extra)
	return out
}

// stampTTL returns a copy of m with every RR TTL set to ttl (RFC 8767 stale serve).
func stampTTL(m *dns.Msg, ttl time.Duration) *dns.Msg {
	out := m.Copy()
	t := uint32(ttl / time.Second)
	set := func(rrs []dns.RR) {
		for _, rr := range rrs {
			rr.Header().Ttl = t
		}
	}
	set(out.Answer)
	set(out.Ns)
	set(out.Extra)
	return out
}

// stripOPT removes any OPT pseudo-RR so the cached message carries no upstream EDNS
// framing; the server re-stamps its own OPT per response.
func stripOPT(m *dns.Msg) {
	if len(m.Extra) == 0 {
		return
	}
	kept := m.Extra[:0]
	for _, rr := range m.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		kept = append(kept, rr)
	}
	m.Extra = kept
}
