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
}

// Options configure a Resolver.
type Options struct {
	TTL      time.Duration    // per-host cache lifetime (default 5m)
	MaxHosts int              // cache cap (default 4096)
	Ping     bool             // send a UDP probe to populate a missing IPv4 ARP entry
	Now      func() time.Time // test clock (default time.Now)
	probe    func(netip.Addr) // test hook for the ARP-populating probe
}

// Resolver enriches hosts on demand and caches the result per name. Safe for concurrent use.
type Resolver struct {
	oui   *OUIDB
	ttl   time.Duration
	max   int
	ping  bool
	now   func() time.Time
	probe func(netip.Addr)

	mu    sync.Mutex
	cache map[string]cacheEntry
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
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = 4096
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	probe := opts.probe
	if probe == nil {
		probe = populateARP
	}
	return &Resolver{oui: oui, ttl: opts.TTL, max: opts.MaxHosts, ping: opts.Ping, now: opts.Now, probe: probe, cache: map[string]cacheEntry{}}
}

// Lookup returns cached enrichment for a host, computing (and caching) it on a miss.
func (r *Resolver) Lookup(name string, addrs []netip.Addr) Info {
	now := r.now()
	r.mu.Lock()
	if e, ok := r.cache[name]; ok && now.Before(e.exp) {
		r.mu.Unlock()
		return e.info
	}
	r.mu.Unlock()

	info := r.compute(addrs)

	r.mu.Lock()
	if len(r.cache) >= r.max {
		for k := range r.cache { // evict an arbitrary entry to stay bounded
			delete(r.cache, k)
			break
		}
	}
	r.cache[name] = cacheEntry{info: info, exp: now.Add(r.ttl)}
	r.mu.Unlock()
	return info
}

func (r *Resolver) compute(addrs []netip.Addr) Info {
	macs := map[string]net.HardwareAddr{}
	scopes := map[string]bool{}
	var v4, v6 bool
	for _, ip := range addrs {
		if !ip.IsValid() {
			continue
		}
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
		if ip.Is4() {
			if mac, ok := ARPMAC(ip); ok {
				macs[mac.String()] = mac
			} else if r.ping {
				r.probe(ip) // limited active: populate a same-segment ARP entry
				if mac, ok := ARPMAC(ip); ok {
					macs[mac.String()] = mac
				}
			}
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
	return info
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

// populateARP sends a tiny UDP datagram toward an on-link IPv4 target so the kernel resolves
// (and caches) its MAC, then waits briefly for the ARP to complete. No raw socket / no
// privilege needed; harmless (discard port). Off-link targets resolve the gateway instead,
// so no MAC is learned — matching ARP's L2 scope.
func populateARP(ip netip.Addr) {
	c, err := net.DialTimeout("udp", netip.AddrPortFrom(ip, 9).String(), 200*time.Millisecond)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = c.Write([]byte{0})
	_ = c.Close()
	time.Sleep(60 * time.Millisecond) // allow the kernel to complete ARP before we re-read
}
