package mdns

import (
	"net/netip"
	"time"
)

// Trust is the authentication tier of an incoming mDNS announcement, decided at ingest.
//
//   - TrustNone   — unauthenticated (passive multicast / an untrusted source). Updates the
//     volatile *.local view only; inert for both DDNS write-back and the trusted store.
//   - TrustWeak   — the source IP is on the [ddns].trusted_sources allowlist but the packet
//     is unsigned. May TRIGGER DDNS write-back (the historical behavior), but must NOT earn
//     a trusted-view entry: a UDP source IP is spoofable, and a trusted-view entry is
//     persistent, shadow-immune, and resolution-authoritative — too much to hang on a
//     forgeable bit (security review, 2026-07-08).
//   - TrustStrong — a valid TSIG signature (RFC 8945, anti-replay) OR a peer-cred-checked
//     unix socket connection. The only tier that populates the persistent trusted store.
type Trust uint8

const (
	TrustNone Trust = iota
	TrustWeak
	TrustStrong
)

// triggersDDNS reports whether an announcement of this tier may move a Cloudflare record.
func (t Trust) triggersDDNS() bool { return t >= TrustWeak }

// isStrong reports whether an announcement of this tier may create/refresh a trusted-store
// entry (persistent, shadow-immune, resolution-authoritative).
func (t Trust) isStrong() bool { return t == TrustStrong }

// defaultMaxTrusted bounds the persistent trusted store when no explicit cap is configured,
// so even a compromised trusted key cannot grow it without limit. Independent of the
// volatile-cache maxHosts LRU (trusted entries are never LRU-evicted by a name flood).
const defaultMaxTrusted = 1024

// trustedTTL is the wire TTL handed out for a trusted-store address. SHORT on purpose:
// server-side RETENTION (surviving host-down) is orthogonal to client cache lifetime — a
// short TTL bounds the stale window to seconds after a renumber while the server keeps
// answering "when down" from its own retained config.
const trustedTTL = 120

// trustedEntry is one host's persistent, trusted static allocation. It lives in a store
// SEPARATE from the volatile cache, so it is never LRU-evicted by a name flood and its
// lifetime is decoupled from the liveness (freshUntil/expiry) clock.
type trustedEntry struct {
	addrs map[netip.Addr]struct{}
	seen  time.Time // last strong-trust announcement — drives the optional trustedGrace cap
}

// applyTrustedLocked reconciles one strong-trust announcement into the trusted store and
// reports whether the host's trusted address set changed. Caller holds c.mu.
//
//   - TTL==0 is a TRUSTED withdrawal: the host's allocation is removed (only a strong-trust
//     packet can do this, so a spoofed untrusted goodbye can never evict a static host).
//   - Otherwise the set is reconciled: outside burstWindow a fresh announcement REPLACES the
//     set (so a renumber drops the old address); within it the sets union (A/AAAA split
//     across packets). seen is refreshed so a re-announcing cron keeps the entry alive.
func (c *Cache) applyTrustedLocked(a Announcement, now time.Time) bool {
	if a.TTL == 0 {
		if _, ok := c.trusted[a.Host]; ok {
			delete(c.trusted, a.Host)
			return true
		}
		return false
	}
	te, ok := c.trusted[a.Host]
	before := ""
	if ok {
		before = trustedKey(te.addrs)
	} else {
		if c.maxTrusted > 0 && len(c.trusted) >= c.maxTrusted {
			c.evictOldestTrustedLocked()
		}
		te = &trustedEntry{addrs: map[netip.Addr]struct{}{}}
		c.trusted[a.Host] = te
	}
	if ok && now.Sub(te.seen) > burstWindow {
		te.addrs = map[netip.Addr]struct{}{} // fresh announcement replaces (renumber)
	}
	for _, addr := range a.Addrs {
		te.addrs[addr] = struct{}{}
	}
	te.seen = now
	return trustedKey(te.addrs) != before
}

// trustedAddrsLocked returns host's live trusted addresses (respecting the optional grace
// cap), or nil. Caller holds c.mu.
func (c *Cache) trustedAddrsLocked(host string, now time.Time) map[netip.Addr]struct{} {
	te, ok := c.trusted[host]
	if !ok {
		return nil
	}
	if c.trustedGrace > 0 && now.Sub(te.seen) > c.trustedGrace {
		return nil
	}
	return te.addrs
}

// expireTrustedLocked drops trusted entries past the (optional) grace cap. Withdrawal is the
// primary removal path; the cap is a backstop for a trusted channel that vanishes without a
// goodbye (e.g. after a renumber). trustedGrace==0 means hold until an explicit withdrawal.
// Caller holds c.mu.
func (c *Cache) expireTrustedLocked(now time.Time) {
	if c.trustedGrace <= 0 {
		return
	}
	for h, te := range c.trusted {
		if now.Sub(te.seen) > c.trustedGrace {
			delete(c.trusted, h)
		}
	}
}

// evictOldestTrustedLocked removes the least-recently-refreshed trusted host to admit a new
// one at the maxTrusted bound. Caller holds c.mu.
func (c *Cache) evictOldestTrustedLocked() {
	var victim string
	var oldest time.Time
	for h, te := range c.trusted {
		if victim == "" || te.seen.Before(oldest) {
			victim, oldest = h, te.seen
		}
	}
	if victim != "" {
		delete(c.trusted, victim)
	}
}

// trustedKey is a stable, order-independent signature of an address set (for change
// detection). Small sets; sorted join.
func trustedKey(addrs map[netip.Addr]struct{}) string {
	set := make([]netip.Addr, 0, len(addrs))
	for a := range addrs {
		set = append(set, a)
	}
	sortAddrs(set)
	return joinAddrs(set)
}
