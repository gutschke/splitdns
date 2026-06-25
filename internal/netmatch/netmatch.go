// Package netmatch provides CIDR allow/deny matching for query access control,
// and helpers to select which local addresses to bind :53 on. It performs no
// I/O beyond enumerating local interface addresses.
//
// Design: §4.2 (access control / rebind) and the Q7 decision — default to allowing
// any PRIVATE/local client, and never bind global (GUA) addresses (which are more
// likely to leak through the firewall).
package netmatch

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// DefaultPrivateClients is the default query-access allow-list: every private and
// local address range, IPv4 and IPv6. Documented in splitdns.conf(5). It is a
// CONFIG DEFAULT — operators may widen or narrow it in the config file.
var DefaultPrivateClients = []string{
	"10.0.0.0/8",     // RFC 1918 private space
	"172.16.0.0/12",  // RFC 1918
	"192.168.0.0/16", // RFC 1918 (the most common home/SOHO LAN range)
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // IPv4 link-local
	"fc00::/7",       // IPv6 ULA (includes fd00::/8)
	"::1/128",        // IPv6 loopback
	"fe80::/10",      // IPv6 link-local
}

// Set is an immutable ordered list of prefixes for membership tests.
type Set struct {
	prefixes []netip.Prefix
}

// ParseSet builds a Set from CIDR strings (e.g. "10.0.0.0/8", "fc00::/7").
func ParseSet(cidrs []string) (*Set, error) {
	s := &Set{prefixes: make([]netip.Prefix, 0, len(cidrs))}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("netmatch: bad CIDR %q: %w", c, err)
		}
		s.prefixes = append(s.prefixes, p.Masked())
	}
	return s, nil
}

// Contains reports whether addr falls in any prefix. IPv4-mapped IPv6 addresses
// (::ffff:a.b.c.d) are unmapped first so a v4 rule matches a v4-mapped client.
func (s *Set) Contains(addr netip.Addr) bool {
	if s == nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range s.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Empty reports whether the set has no prefixes.
func (s *Set) Empty() bool { return s == nil || len(s.prefixes) == 0 }

// Access is an allow/deny policy. Refuse takes precedence over Allow.
type Access struct {
	Allow  *Set
	Refuse *Set
}

// Allowed reports whether a client address may query.
func (a Access) Allowed(addr netip.Addr) bool {
	if a.Refuse != nil && a.Refuse.Contains(addr) {
		return false
	}
	return a.Allow != nil && a.Allow.Contains(addr)
}

// IsLocalScope reports whether addr is loopback, RFC 1918 / ULA private, or
// link-local — i.e. NOT a global-unicast address. Used to decide which local
// interface addresses :53 binds to (the Q7 "never listen on global" rule).
func IsLocalScope(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

// forwardBlock is the forwarded-path DNS-rebinding blocklist (design §4.2). A
// FORWARDED answer (never an authoritative/stub/static one) whose A/AAAA falls in
// these ranges is stripped. Two intentional, documented divergences from a naive
// "all private" list: 127.0.0.0/8 and 0.0.0.0/8 are OMITTED (to preserve the DNSBL
// 127.0.0.x carve-out), and IPv6 uses fe80::/10 not fe80::/9 (dropping deprecated
// fec0::/10, which is therefore forwarded). v4-mapped IPv6 is decoded to v4 first.
var forwardBlock = mustPrefixes(
	// IPv4
	"10.0.0.0/8",     // RFC 1918
	"172.16.0.0/12",  // RFC 1918
	"192.168.0.0/16", // RFC 1918
	"169.254.0.0/16", // link-local
	"192.0.0.0/24",   // IETF protocol assignments (incl. 192.0.0.0/29 NAT64/DS-Lite)
	"198.18.0.0/15",  // benchmarking (RFC 2544)
	// IPv6
	"fc00::/7",  // ULA
	"fe80::/10", // link-local (NOT /9 — fec0::/10 deprecated, intentionally forwarded)
	"::1/128",   // loopback
	"::/128",    // unspecified
)

// IsForwardBlocked reports whether addr must be stripped from a FORWARDED answer as
// a rebinding-protection measure (design §4.2). It is applied only on the forward
// path and only to names NOT covered by Snapshot.AllowSuffix; locally-authoritative,
// stub, and static answers bypass it entirely (a private record in a mirrored zone
// is legitimate). 127.0.0.0/8 is deliberately NOT blocked (DNSBL carve-out).
func IsForwardBlocked(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}
	for _, p := range forwardBlock {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// nonRoutableSpecial are address ranges that are not globally routable public
// addresses even though IsGlobalUnicast may report true: CGNAT and the
// documentation ranges. They must never be mirrored to public DNS.
var nonRoutableSpecial = mustPrefixes(
	"100.64.0.0/10",   // RFC 6598 carrier-grade NAT / shared address space
	"192.0.2.0/24",    // RFC 5737 TEST-NET-1 (documentation)
	"198.51.100.0/24", // RFC 5737 TEST-NET-2 (documentation)
	"203.0.113.0/24",  // RFC 5737 TEST-NET-3 (documentation)
	"2001:db8::/32",   // RFC 3849 IPv6 documentation
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		ps = append(ps, netip.MustParsePrefix(c))
	}
	return ps
}

// IsDDNSEligible reports whether addr may be written to public DNS by the dynamic
// DNS writer (design §4.4). It is the most security-load-bearing predicate in the
// system and the single source of truth for "is this a genuinely public address":
// the address must be global-unicast and NOT private, link-local, or loopback, and
// must not fall in the CGNAT (100.64.0.0/10) or documentation ranges. It is a proper
// range check rather than a string-prefix heuristic, which is easy to get wrong (e.g.
// 172.16/12 boundaries, or any IPv6 starting with 'f'). v4-mapped IPv6 is unmapped first.
func IsDDNSEligible(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback() {
		return false
	}
	for _, p := range nonRoutableSpecial {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// SelectListenAddrs returns the host:port endpoints to bind. With mode
// "private-auto" it enumerates local interface addresses and keeps only
// local-scope ones (skipping global/GUA); loopback is always included so the
// daemon is reachable locally. With mode "explicit" it returns the configured
// addresses joined with port. The bool-keyed map dedups addresses.
func SelectListenAddrs(mode string, explicit []string, port int) ([]string, error) {
	switch mode {
	case "explicit":
		out := make([]string, 0, len(explicit))
		out = append(out, explicit...)
		return out, nil
	case "", "private-auto":
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("netmatch: enumerate interfaces: %w", err)
		}
		seen := map[string]bool{}
		out := []string{}
		add := func(a netip.Addr) {
			ap := netip.AddrPortFrom(a, uint16(port)).String()
			if !seen[ap] {
				seen[ap] = true
				out = append(out, ap)
			}
		}
		for _, iface := range ifaces {
			// A down interface has no usable bind address; skip it so we
			// don't try to bind an address that will EINVAL/EADDRNOTAVAIL.
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, ia := range addrs {
				pfx, ok := ia.(*net.IPNet)
				if !ok {
					continue
				}
				a, ok := netip.AddrFromSlice(pfx.IP)
				if !ok {
					continue
				}
				a = a.Unmap()
				if !IsLocalScope(a) {
					continue
				}
				// IPv6 link-local addresses are only bindable with their
				// interface scope (zone); a bare bind fails with EINVAL.
				// InterfaceAddrs() drops the zone, so attach it here.
				if a.Is6() && a.IsLinkLocalUnicast() {
					a = a.WithZone(iface.Name)
				} else {
					a = a.WithZone("")
				}
				add(a)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("netmatch: unknown listen mode %q", mode)
	}
}

// ListenNetwork returns base ("tcp" or "udp") with the address-family suffix
// implied by the host portion of hostport:
//
//	IPv4 literal, including the 0.0.0.0 wildcard -> base+"4"
//	IPv6 literal, including the ::      wildcard  -> base+"6"
//	empty host, or a hostname                    -> base (dual-stack / resolver)
//
// This pins an IPv4 wildcard to IPv4 ONLY. Go's net.Listen("tcp","0.0.0.0:p")
// otherwise opens a dual-stack [::] socket that also accepts IPv6, so a config
// of 0.0.0.0 would silently expose the service over IPv6 as well. Callers that
// genuinely want both families bind an empty host (":p") and get bare base.
func ListenNetwork(base, hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil || host == "" {
		return base
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return base // hostname: let the resolver pick the family
	}
	switch {
	case ip.Is4() || ip.Is4In6():
		return base + "4"
	case ip.Is6():
		return base + "6"
	default:
		return base
	}
}
