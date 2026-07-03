package mdns

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// burstWindow is how long successive packets for the same host are unioned rather
// than treated as a fresh, replacing announcement — a 5s combine window so a
// responder that sends A and AAAA in separate packets is not split.
const burstWindow = 5 * time.Second

// maxHosts bounds the cache so a flood of distinct names cannot grow it without
// limit (design §reliability: the mDNS map has an explicit upper bound).
const maxHosts = 4096

// maxTTL clamps an announced TTL so a hostile responder cannot pin an entry in the
// table indefinitely (D12). 4500s is the RFC 6762 default for shared records — well
// above any legitimate host announcement, but bounded.
const maxTTL = 4500

// staleServeTTL caps the DNS TTL handed out while a record is being served stale, so
// clients re-check soon (and pick up a refresh) rather than caching the stale value long.
const staleServeTTL = 30

// ChangeFunc is called when a host's cached address set changes (including going
// empty on expiry). It is the DDNS trigger; the wiring layer adapts it to a
// ddns.Change. The cache never calls it while holding its lock.
type ChangeFunc func(host string, addrs []netip.Addr)

type entry struct {
	addrs      map[netip.Addr]struct{}
	services   map[string]struct{} // DNS-SD service types the host advertises (diagnostic)
	freshUntil time.Time           // announced-TTL expiry — drives the SERVED DNS TTL
	expiry     time.Time           // removal time = freshUntil + staleGrace (serve-stale window)
	lastSeen   time.Time
	notified   string // canonical join of the address set last sent to onChange
}

// Cache is the concurrent *.local host store. All methods are safe for concurrent
// use; callers pass the current time so behavior is deterministic under test.
type Cache struct {
	mu       sync.Mutex
	hosts    map[string]*entry
	onChange ChangeFunc
	// staleGrace keeps a record served past its announced TTL (bridging a reconciler that
	// re-announces slower than the TTL); goodbyeGrace is the short cushion kept after an
	// explicit mDNS goodbye so an avahi bounce does not blink the host out. Both default 0
	// (no serve-stale; goodbye coerced to the legacy 120s) unless configured.
	staleGrace   time.Duration
	goodbyeGrace time.Duration
}

// NewCache returns an empty cache. onChange may be nil.
func NewCache(onChange ChangeFunc) *Cache {
	return &Cache{hosts: map[string]*entry{}, onChange: onChange}
}

// Apply folds one announcement into the cache and returns true if the host's
// address set changed. Within burstWindow of the last packet the sets are unioned;
// otherwise the new set replaces the old (so a host that drops an address is
// reflected once announcements are spaced apart).
//
// trusted gates the DDNS side effect ONLY: the *.local view is always updated, but
// onChange (the write-back trigger) fires only when the announcement came from a
// trusted source/channel (D7). An untrusted announcement still resolves on the LAN;
// it just cannot move a Cloudflare record.
func (c *Cache) Apply(a Announcement, now time.Time, trusted bool) bool {
	if a.Host == "" || len(a.Addrs) == 0 {
		return false
	}
	// TTL=0 is an mDNS goodbye. With goodbyeGrace configured we honor it (mark stale now,
	// keep a short cushion); otherwise fall back to the legacy 120s coercion.
	goodbye := a.TTL == 0 && c.goodbyeGrace > 0
	ttl := a.TTL
	if ttl == 0 && !goodbye {
		ttl = 120
	}
	if ttl > maxTTL {
		ttl = maxTTL // clamp hostile/oversized TTLs (D12)
	}

	c.mu.Lock()
	e, ok := c.hosts[a.Host]
	var evicted string
	if !ok {
		if len(c.hosts) >= maxHosts {
			// At capacity: evict the least-recently-seen host to admit the new one,
			// rather than dropping new hosts forever (D12 — LRU, not first-come-pin).
			evicted = c.evictOldestLocked()
		}
		e = &entry{addrs: map[netip.Addr]struct{}{}}
		c.hosts[a.Host] = e
	}
	if ok && now.Sub(e.lastSeen) > burstWindow {
		e.addrs = map[netip.Addr]struct{}{} // fresh announcement replaces
	}
	for _, addr := range a.Addrs {
		e.addrs[addr] = struct{}{}
	}
	e.lastSeen = now
	if goodbye {
		e.freshUntil = now // immediately stale (served with a short TTL)
		e.expiry = now.Add(c.goodbyeGrace)
	} else {
		e.freshUntil = now.Add(time.Duration(ttl) * time.Second)
		e.expiry = e.freshUntil.Add(c.staleGrace) // serve-stale window past the announced TTL
	}
	changed, set := c.diffLocked(a.Host, e)
	c.mu.Unlock()

	// Fire the DDNS trigger only for trusted announcements (D7). The view itself was
	// already updated above regardless, so untrusted hosts still resolve on the LAN.
	if trusted && c.onChange != nil {
		if evicted != "" {
			c.onChange(evicted, nil)
		}
		if changed {
			c.onChange(a.Host, set)
		}
	}
	return changed
}

// ApplyService records that an EXISTING cached host advertises a DNS-SD service type
// (diagnostic fingerprint). Returns true if the type was newly added. Services for an
// unknown host are dropped — they attach on a later packet once the host's address is known,
// and they share the host entry's lifetime. Never creates a host or affects resolution.
func (c *Cache) ApplyService(host, typ string, now time.Time) bool {
	if host == "" || typ == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.hosts[host]
	if !ok {
		return false
	}
	if e.services == nil {
		e.services = map[string]struct{}{}
	}
	if _, dup := e.services[typ]; dup {
		return false
	}
	e.services[typ] = struct{}{}
	return true
}

// evictOldestLocked removes and returns the host with the oldest lastSeen (the LRU
// victim), or "" if the cache is empty. Caller holds mu.
func (c *Cache) evictOldestLocked() string {
	var victim string
	var oldest time.Time
	for h, e := range c.hosts {
		if victim == "" || e.lastSeen.Before(oldest) {
			victim, oldest = h, e.lastSeen
		}
	}
	if victim != "" {
		delete(c.hosts, victim)
	}
	return victim
}

// Expire drops hosts whose TTL has elapsed, firing onChange(host, nil) for each so
// the view is rebuilt and the DDNS path safely no-ops (an empty set never deletes
// records). Returns the number of hosts removed.
func (c *Cache) Expire(now time.Time) int {
	c.mu.Lock()
	var gone []string
	for h, e := range c.hosts {
		if now.After(e.expiry) {
			gone = append(gone, h)
		}
	}
	for _, h := range gone {
		delete(c.hosts, h)
	}
	c.mu.Unlock()

	for _, h := range gone {
		if c.onChange != nil {
			c.onChange(h, nil)
		}
	}
	return len(gone)
}

// diffLocked computes the host's current sorted address set and reports whether it
// differs from what was last notified, updating the notified marker. Caller holds mu.
func (c *Cache) diffLocked(host string, e *entry) (bool, []netip.Addr) {
	set := make([]netip.Addr, 0, len(e.addrs))
	for a := range e.addrs {
		set = append(set, a)
	}
	sort.Slice(set, func(i, j int) bool { return set[i].Less(set[j]) })
	key := joinAddrs(set)
	if key == e.notified {
		return false, set
	}
	e.notified = key
	return true, set
}

// View builds the immutable MDNSView for the hot path from non-expired hosts.
func (c *Cache) View(now time.Time) *model.MDNSView {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := &model.MDNSView{
		Forward: map[string][]model.RR{},
		Reverse: map[string][]model.RR{},
		BuiltAt: now,
	}
	for host, e := range c.hosts {
		if now.After(e.expiry) {
			continue
		}
		fqdn := host + ".local."
		// Serve the announced-TTL remainder while fresh; once stale (serve-stale window),
		// serve a short TTL so clients re-check soon and pick up a refresh promptly.
		ttl := ttlUntil(e.freshUntil, now)
		if now.After(e.freshUntil) {
			if rem := ttlUntil(e.expiry, now); rem < staleServeTTL {
				ttl = rem
			} else {
				ttl = staleServeTTL
			}
		}
		set := make([]netip.Addr, 0, len(e.addrs))
		for a := range e.addrs {
			set = append(set, a)
		}
		sort.Slice(set, func(i, j int) bool { return set[i].Less(set[j]) })
		for _, a := range set {
			typ := uint16(dns.TypeA)
			if a.Is6() {
				typ = dns.TypeAAAA
			}
			v.Forward[host] = append(v.Forward[host], model.RR{
				Name: fqdn, Type: typ, Class: dns.ClassINET, TTL: ttl, Content: a.String(),
			})
			if arpa, err := dns.ReverseAddr(a.String()); err == nil {
				v.Reverse[arpa] = append(v.Reverse[arpa], model.RR{
					Name: arpa, Type: dns.TypePTR, Class: dns.ClassINET, TTL: ttl,
					Content: fqdn, Target: fqdn,
				})
			}
		}
		if len(e.services) > 0 && len(e.addrs) > 0 {
			svcs := make([]string, 0, len(e.services))
			for s := range e.services {
				svcs = append(svcs, s)
			}
			sort.Strings(svcs)
			if v.Services == nil {
				v.Services = map[string][]string{}
			}
			v.Services[host] = svcs
		}
	}
	return v
}

// Len reports the number of cached hosts (test/metrics helper).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hosts)
}

func joinAddrs(set []netip.Addr) string {
	parts := make([]string, len(set))
	for i, a := range set {
		parts[i] = a.String()
	}
	return strings.Join(parts, ",")
}

func ttlUntil(expiry, now time.Time) uint32 {
	d := expiry.Sub(now).Seconds()
	if d < 1 {
		return 1
	}
	return uint32(d)
}
