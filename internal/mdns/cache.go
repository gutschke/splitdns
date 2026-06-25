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

// ChangeFunc is called when a host's cached address set changes (including going
// empty on expiry). It is the DDNS trigger; the wiring layer adapts it to a
// ddns.Change. The cache never calls it while holding its lock.
type ChangeFunc func(host string, addrs []netip.Addr)

type entry struct {
	addrs    map[netip.Addr]struct{}
	expiry   time.Time
	lastSeen time.Time
	notified string // canonical join of the address set last sent to onChange
}

// Cache is the concurrent *.local host store. All methods are safe for concurrent
// use; callers pass the current time so behavior is deterministic under test.
type Cache struct {
	mu       sync.Mutex
	hosts    map[string]*entry
	onChange ChangeFunc
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
	ttl := a.TTL
	if ttl == 0 {
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
	e.expiry = now.Add(time.Duration(ttl) * time.Second)
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
		ttl := ttlUntil(e.expiry, now)
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
