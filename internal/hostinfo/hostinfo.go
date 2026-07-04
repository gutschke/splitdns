package hostinfo

import (
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Info is the diagnostic-only enrichment for one host. All fields derive from data already
// on the box (the host's addresses, the local ARP table, the local OUI database); nothing
// here is sent off the box.
type Info struct {
	Vendors  []string `json:"vendors,omitempty"`  // distinct hardware manufacturers (OUI)
	MACs     []string `json:"macs,omitempty"`     // distinct MACs found (EUI-64 or ARP)
	Families string   `json:"families,omitempty"` // "IPv4+IPv6" | "IPv4" | "IPv6"
	Scopes   []string `json:"scopes,omitempty"`   // address scopes present (LAN/GUA/ULA/public/CGNAT/…)
	Services []string `json:"services,omitempty"` // DNS-SD service types (set by the caller from the mDNS view)
}

// Options configure a Resolver.
type Options struct {
	TTL      time.Duration    // resolved-entry cache lifetime (default 5m)
	RetryTTL time.Duration    // unresolved-entry lifetime while a probe is in flight (default 20s)
	MaxHosts int              // cache cap (default 4096)
	Probe    bool             // fire an ASYNC ping/UDP probe to populate a missing neighbor entry
	Now      func() time.Time // test clock (default time.Now)
	probe    func(netip.Addr) // test hook for the neighbor-populating probe
}

// probeCooldown rate-limits re-probing the same address, so an unreachable host (or an
// off-segment one that will never appear in our neighbor table) is nudged at most this often
// — a "ping or two," never a flood.
const probeCooldown = 90 * time.Second

// Resolver enriches hosts on demand and caches the result per name. Safe for concurrent use.
type Resolver struct {
	oui      *OUIDB
	ttl      time.Duration
	retryTTL time.Duration
	max      int
	probeOn  bool
	now      func() time.Time
	probe    func(netip.Addr)

	mu    sync.Mutex
	cache map[string]cacheEntry

	probeMu  sync.Mutex
	probedAt map[netip.Addr]time.Time
}

type cacheEntry struct {
	info Info
	exp  time.Time
}

// New builds a Resolver over an OUI database.
func New(oui *OUIDB, opts Options) *Resolver {
	if opts.TTL <= 0 {
		opts.TTL = 5 * time.Minute
	}
	if opts.RetryTTL <= 0 {
		opts.RetryTTL = 20 * time.Second
	}
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = 4096
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	probe := opts.probe
	if probe == nil {
		probe = probeNeighbor
	}
	return &Resolver{
		oui: oui, ttl: opts.TTL, retryTTL: opts.RetryTTL, max: opts.MaxHosts, probeOn: opts.Probe,
		now: opts.Now, probe: probe, cache: map[string]cacheEntry{}, probedAt: map[netip.Addr]time.Time{},
	}
}

// Lookup returns cached enrichment for a host, computing (and caching) it on a miss. When an
// address can't be identified passively it fires an async probe and caches the (still empty)
// result briefly, so a follow-up lookup picks up the newly-populated neighbor entry.
func (r *Resolver) Lookup(name string, addrs []netip.Addr) Info {
	now := r.now()
	r.mu.Lock()
	if e, ok := r.cache[name]; ok && now.Before(e.exp) {
		r.mu.Unlock()
		return e.info
	}
	r.mu.Unlock()

	info, pending := r.compute(addrs)
	ttl := r.ttl
	if pending {
		ttl = r.retryTTL // a probe was fired — re-check soon so its result shows up
	}

	r.mu.Lock()
	if len(r.cache) >= r.max {
		for k := range r.cache { // evict an arbitrary entry to stay bounded
			delete(r.cache, k)
			break
		}
	}
	r.cache[name] = cacheEntry{info: info, exp: now.Add(ttl)}
	r.mu.Unlock()
	return info
}

// scheduleProbe fires one async, rate-limited neighbor probe for ip. Returns true if a probe
// was launched (so the caller can shorten the cache TTL and re-check soon).
func (r *Resolver) scheduleProbe(ip netip.Addr) bool {
	r.probeMu.Lock()
	if t, ok := r.probedAt[ip]; ok && r.now().Sub(t) < probeCooldown {
		r.probeMu.Unlock()
		return false
	}
	if len(r.probedAt) > 4096 { // bound the cooldown map
		r.probedAt = map[netip.Addr]time.Time{}
	}
	r.probedAt[ip] = r.now()
	r.probeMu.Unlock()
	go r.probe(ip)
	return true
}

func (r *Resolver) compute(addrs []netip.Addr) (Info, bool) {
	macs := map[string]net.HardwareAddr{}
	scopes := map[string]bool{}
	var v4, v6, pending bool
	for _, ip := range addrs {
		if !ip.IsValid() {
			continue
		}
		ip = ip.Unmap() // treat ::ffff:a.b.c.d as the IPv4 it is
		if ip.Is4() {
			v4 = true
		} else {
			v6 = true
		}
		scopes[scopeOf(ip)] = true
		if mac, ok := EUI64MAC(ip); ok { // passive, works across subnets
			macs[mac.String()] = mac
			continue
		}
		if mac, ok := NeighborMAC(ip); ok { // ARP (v4) / ND (v6) neighbor cache
			macs[mac.String()] = mac
			continue
		}
		// Not identifiable passively (e.g. a privacy IPv6 address not yet in the ND cache).
		// Fire one async, rate-limited probe so a later lookup can read the populated entry.
		if r.probeOn && scopeOf(ip) != "public" && r.scheduleProbe(ip) {
			pending = true
		}
	}

	var info Info
	vendorSet := map[string]bool{}
	for s, mac := range macs {
		info.MACs = append(info.MACs, s)
		if v := r.oui.Vendor(mac); v != "" {
			vendorSet[v] = true
		}
	}
	for v := range vendorSet {
		info.Vendors = append(info.Vendors, v)
	}
	for s := range scopes {
		info.Scopes = append(info.Scopes, s)
	}
	sort.Strings(info.MACs)
	sort.Strings(info.Vendors)
	sort.Strings(info.Scopes)
	switch {
	case v4 && v6:
		info.Families = "IPv4+IPv6"
	case v4:
		info.Families = "IPv4"
	case v6:
		info.Families = "IPv6"
	}
	return info, pending
}

// scopeOf labels an address by reachability class (for the address profile).
func scopeOf(ip netip.Addr) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsPrivate() && ip.Is4():
		return "LAN"
	case ip.IsPrivate(): // ULA (fc00::/7)
		return "ULA"
	case ip.Is4() && isCGNAT(ip):
		return "CGNAT"
	case ip.Is4():
		return "public"
	case ip.IsGlobalUnicast():
		return "GUA"
	default:
		return "other"
	}
}

func isCGNAT(ip netip.Addr) bool {
	return ip.Is4() && netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10).Contains(ip)
}

// probeNeighbor sends a tiny UDP datagram (a nudge or two) toward an on-link target so the
// kernel resolves and caches its MAC in the ARP/ND table. It runs in its own goroutine and
// NEVER blocks the caller; the populated entry is picked up by a later lookup. No raw socket
// / no privilege (harmless discard port). Off-link targets resolve the gateway, so no host
// MAC is learned — matching ARP/ND's L2 scope, which is why unreachable hosts stay unknown.
func probeNeighbor(ip netip.Addr) {
	c, err := net.DialTimeout("udp", netip.AddrPortFrom(ip, 9).String(), 500*time.Millisecond)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = c.Write([]byte{0})
	_, _ = c.Write([]byte{0}) // a second nudge ("a ping or two")
	_ = c.Close()
}
