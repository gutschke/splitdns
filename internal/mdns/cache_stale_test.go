package mdns

import (
	"net/netip"
	"testing"
	"time"
)

// Serve-stale keeps a record past its announced TTL for the grace window (with a short
// served TTL), and an mDNS goodbye is honored but cushioned briefly rather than removing
// the host instantly.
func TestServeStaleAndGoodbye(t *testing.T) {
	c := NewCache(nil)
	c.staleGrace = 10 * time.Minute
	c.goodbyeGrace = 30 * time.Second
	base := time.Unix(1_000_000, 0)
	ann := func(host, ip string, ttl uint32, at time.Time) {
		c.Apply(Announcement{Host: host, Addrs: []netip.Addr{netip.MustParseAddr(ip)}, TTL: ttl}, at, TrustNone)
	}

	ann("h", "10.0.0.5", 120, base)
	if v := c.View(base.Add(60 * time.Second)); len(v.Forward["h"]) != 1 {
		t.Fatal("fresh: h should be present")
	}
	// Past the 120s TTL but within the 10m grace: still served, with a short TTL.
	stale := base.Add(200 * time.Second)
	v := c.View(stale)
	if len(v.Forward["h"]) != 1 {
		t.Fatal("stale-within-grace: h should still be served")
	}
	if ttl := v.Forward["h"][0].TTL; ttl > staleServeTTL {
		t.Errorf("stale served TTL = %d, want <= %d", ttl, staleServeTTL)
	}
	if c.Expire(stale); c.Len() != 1 {
		t.Error("Expire removed a still-in-grace host")
	}
	// Past TTL + grace: removed.
	c.Expire(base.Add(120*time.Second + 10*time.Minute + time.Second))
	if c.Len() != 0 {
		t.Error("past grace: host should be removed")
	}

	// Goodbye (TTL=0) is honored with a short cushion, not instant removal.
	ann("g", "10.0.0.6", 120, base)
	ann("g", "10.0.0.6", 0, base.Add(time.Second)) // goodbye
	if v := c.View(base.Add(10 * time.Second)); len(v.Forward["g"]) != 1 {
		t.Error("goodbye cushion: g should still be served briefly")
	}
	c.Expire(base.Add(40 * time.Second)) // > goodbye(+1s) + 30s
	if _, ok := c.hosts["g"]; ok {
		t.Error("after goodbye grace: g should be removed")
	}
}
