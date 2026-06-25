// Package revzone derives the reverse-DNS zones (in-addr.arpa / ip6.arpa) that
// the server is authoritative for, from a set of locally-managed prefixes.
//
// Design (Q2, §8): be authoritative ONLY for our locally managed address spaces;
// forward every other PTR to the internet, where the global authoritative servers
// hold the truth. We deliberately do NOT answer every .arpa from a catch-all.
//
// SAFETY: the operator's concern is detecting the WRONG space and over- or
// under-representing it. Two rules prevent that:
//  1. Derive emits a zone ONLY at a natural reverse boundary — an octet boundary
//     for IPv4 (/8,/16,/24,/32) and a nibble boundary for IPv6 (/4 steps). A
//     prefix that is NOT boundary-aligned is REFUSED (returned in `unaligned`)
//     rather than guessed at, so we never claim addresses we don't manage nor
//     drop ones we do. The operator configures those explicitly.
//  2. The reverse name is computed by exact octet/nibble reversal — e.g.
//     192.168.0.0/16 => 168.192.in-addr.arpa. (NOT 192.168.in-addr.arpa.).
//
// Every function here is a PURE function of its inputs (no interface I/O except
// the clearly-separated LocalManagedPrefixes), so the whole derivation is
// exhaustively unit-testable with synthetic inputs.
package revzone

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Derive returns the sorted, de-duplicated set of reverse-zone apexes for the
// given locally-managed prefixes, plus any prefixes that are not aligned to a
// reverse-zone boundary (the caller should warn and require explicit config).
func Derive(prefixes []netip.Prefix) (zones []string, unaligned []netip.Prefix) {
	seen := map[string]bool{}
	for _, p := range prefixes {
		p = p.Masked()
		z, err := ZoneFor(p)
		if err != nil {
			unaligned = append(unaligned, p)
			continue
		}
		if !seen[z] {
			seen[z] = true
			zones = append(zones, z)
		}
	}
	sort.Strings(zones)
	return zones, unaligned
}

// ZoneFor returns the reverse-zone apex for a single boundary-aligned prefix, or
// an error if the prefix bits are not on an octet (IPv4) / nibble (IPv6) boundary.
func ZoneFor(p netip.Prefix) (string, error) {
	p = p.Masked()
	addr := p.Addr().Unmap()
	bits := p.Bits()
	if addr.Is4() {
		if bits%8 != 0 {
			return "", fmt.Errorf("revzone: IPv4 prefix %s not octet-aligned (bits=%d); configure explicitly", p, bits)
		}
		n := bits / 8 // number of leading octets that define the zone
		o := addr.As4()
		var labels []string
		for i := n - 1; i >= 0; i-- { // reverse the leading octets
			labels = append(labels, fmt.Sprintf("%d", o[i]))
		}
		return strings.Join(append(labels, "in-addr", "arpa"), ".") + ".", nil
	}
	if addr.Is6() {
		if bits%4 != 0 {
			return "", fmt.Errorf("revzone: IPv6 prefix %s not nibble-aligned (bits=%d); configure explicitly", p, bits)
		}
		n := bits / 4 // number of leading nibbles
		b := addr.As16()
		nibbles := make([]byte, 32)
		for i := 0; i < 16; i++ {
			nibbles[2*i] = b[i] >> 4
			nibbles[2*i+1] = b[i] & 0x0f
		}
		var labels []string
		for i := n - 1; i >= 0; i-- { // reverse the leading nibbles
			labels = append(labels, fmt.Sprintf("%x", nibbles[i]))
		}
		return strings.Join(append(labels, "ip6", "arpa"), ".") + ".", nil
	}
	return "", fmt.Errorf("revzone: address %s is neither IPv4 nor IPv6", addr)
}

// Detection scopes for DetectPrefixes / config reverse_detect.
const (
	ScopeOff     = "off"     // detect nothing (use explicit zones only)
	ScopePrivate = "private" // RFC 1918 + ULA (stable; usually configure explicitly instead)
	ScopeGlobal  = "global"  // global-unicast only (e.g. a DYNAMIC ISP-assigned GUA prefix)
	ScopeAll     = "all"     // private + ULA + global
)

// ValidScope reports whether s is a recognized detection scope.
func ValidScope(s string) bool {
	switch s {
	case ScopeOff, ScopePrivate, ScopeGlobal, ScopeAll:
		return true
	}
	return false
}

// classifyAndFilter is the PURE core of prefix detection: given the raw
// interface addresses and a scope, it returns the de-duplicated, scope-matching
// managed prefixes. Loopback and link-local are always excluded. Kept pure
// (takes []net.Addr) so detection logic is exhaustively unit-testable with
// synthetic *net.IPNet inputs and never depends on the live host.
func classifyAndFilter(addrs []net.Addr, scope string) []netip.Prefix {
	if scope == ScopeOff {
		return nil
	}
	var out []netip.Prefix
	seen := map[string]bool{}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ones, _ := ipn.Mask.Size()
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		var match bool
		switch scope {
		case ScopePrivate:
			match = ip.IsPrivate()
		case ScopeGlobal:
			match = ip.IsGlobalUnicast() && !ip.IsPrivate()
		case ScopeAll:
			match = ip.IsPrivate() || ip.IsGlobalUnicast()
		}
		if !match {
			continue
		}
		pfx := netip.PrefixFrom(ip, ones).Masked()
		if !seen[pfx.String()] {
			seen[pfx.String()] = true
			out = append(out, pfx)
		}
	}
	sortPrefixes(out)
	return out
}

// DetectPrefixes enumerates interface prefixes matching the given scope. This is
// the only function here that touches the system; the pure core is
// classifyAndFilter. A GUA range is "locally managed" only if you actually run
// authoritative DNS for it, which is why ScopeGlobal is opt-in — but because an
// ISP-assigned GUA can change, callers should re-run this on network changes
// (see Watcher).
func DetectPrefixes(scope string) ([]netip.Prefix, error) {
	if !ValidScope(scope) {
		return nil, fmt.Errorf("revzone: unknown detect scope %q", scope)
	}
	addrs, err := allInterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return classifyAndFilter(addrs, scope), nil
}

// allInterfaceAddrs returns addresses of all up, non-loopback interfaces.
func allInterfaceAddrs() ([]net.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("revzone: list interfaces: %w", err)
	}
	var out []net.Addr
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		a, err := ifc.Addrs()
		if err != nil {
			continue
		}
		out = append(out, a...)
	}
	return out, nil
}

// Contains reports whether reverse zone child is equal to or a subdomain of
// parent (both trailing-dot FQDNs). Used to drop a dynamically-detected zone
// that is already covered by a stable explicit zone (e.g. a detected ULA /64
// inside an explicit /48), preventing a more-specific zone from shadowing it.
func Contains(parent, child string) bool {
	if parent == child {
		return true
	}
	return strings.HasSuffix(child, "."+parent)
}

func sortPrefixes(p []netip.Prefix) {
	sort.Slice(p, func(i, j int) bool { return p[i].String() < p[j].String() })
}
