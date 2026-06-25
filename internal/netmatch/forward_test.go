package netmatch

import (
	"net/netip"
	"testing"
)

// TestIsForwardBlocked pins the §4.2 forwarded-path blocklist, including the two
// intentional divergences: 127.0.0.0/8 is NOT blocked (DNSBL carve-out) and
// fec0::/10 is NOT blocked (fe80::/10, not /9).
func TestIsForwardBlocked(t *testing.T) {
	blocked := []string{
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.0.1",
		"192.0.0.1", "198.18.0.1", "198.19.255.255",
		"fc00::1", "fd00::1", "fe80::1", "::1", "::",
	}
	for _, s := range blocked {
		if !IsForwardBlocked(netip.MustParseAddr(s)) {
			t.Errorf("IsForwardBlocked(%s) = false, want true (must be stripped from forwarded answers)", s)
		}
	}

	forwarded := []string{
		"8.8.8.8", "203.0.113.10", // public
		"127.0.0.1", "127.0.0.2", // DNSBL carve-out — must NOT be stripped
		"fec0::1",                      // deprecated site-local — fe80::/10 narrowing means forwarded
		"172.15.255.255", "172.32.0.1", // just outside 172.16/12
	}
	for _, s := range forwarded {
		if IsForwardBlocked(netip.MustParseAddr(s)) {
			t.Errorf("IsForwardBlocked(%s) = true, want false (must be returned, not stripped)", s)
		}
	}

	// v4-mapped private is decoded to v4 and blocked.
	if !IsForwardBlocked(netip.MustParseAddr("::ffff:10.0.0.1")) {
		t.Errorf("v4-mapped private ::ffff:10.0.0.1 must be blocked")
	}
	// v4-mapped loopback follows the v4 carve-out: NOT blocked.
	if IsForwardBlocked(netip.MustParseAddr("::ffff:127.0.0.2")) {
		t.Errorf("v4-mapped DNSBL ::ffff:127.0.0.2 must NOT be blocked")
	}
}
