package netmatch

import (
	"net/netip"
	"testing"
)

// TestIsDDNSEligible pins every boundary the design calls out (§4.4). This is the
// most security-load-bearing predicate: a false positive writes a private/CGNAT/
// documentation address into public DNS.
func TestIsDDNSEligible(t *testing.T) {
	reject := []string{
		// RFC 1918 — including the 172.16/12 boundary a naive string filter would mishandle.
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		// loopback / link-local / unspecified.
		"127.0.0.1", "169.254.1.1", "0.0.0.0",
		// CGNAT and documentation ranges.
		"100.64.0.1", "100.127.255.255", "192.0.2.1", "198.51.100.10", "203.0.113.7",
		// IPv6 private/link-local/loopback/doc — a naive "starts with f" check would drop
		// ALL of f…; we must reject these specific ones for the right (range-based) reason.
		"fd00::1", "fc00::1", "fe80::1", "::1", "2001:db8::1",
	}
	for _, s := range reject {
		if IsDDNSEligible(netip.MustParseAddr(s)) {
			t.Errorf("IsDDNSEligible(%s) = true, want false (must never reach public DNS)", s)
		}
	}

	accept := []string{
		"8.8.8.8",              // public v4
		"172.15.255.255",       // just below 172.16/12 — genuinely public
		"172.32.0.1",           // just above 172.16/12 — genuinely public
		"2001:4860:4860::8888", // public v6 (global unicast, not doc)
		"2606:4700:4700::1111", // public v6
	}
	for _, s := range accept {
		if !IsDDNSEligible(netip.MustParseAddr(s)) {
			t.Errorf("IsDDNSEligible(%s) = false, want true (genuinely public)", s)
		}
	}

	// v4-mapped IPv6 must be classified by its embedded v4 (private => reject).
	if IsDDNSEligible(netip.MustParseAddr("::ffff:10.0.0.1")) {
		t.Errorf("v4-mapped private ::ffff:10.0.0.1 must be rejected")
	}
	if !IsDDNSEligible(netip.MustParseAddr("::ffff:8.8.8.8")) {
		t.Errorf("v4-mapped public ::ffff:8.8.8.8 must be accepted")
	}
}
