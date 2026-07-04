package mdns

import (
	"strings"

	"github.com/miekg/dns"
)

// serviceEnum is the DNS-SD service-type enumeration name (RFC 6763 §9): a PTR query for it
// returns the set of service types present on the link.
const serviceEnum = "_services._dns-sd._udp.local."

// maxDiscoveredTypes bounds the learned-type set so a hostile responder can't grow it without
// limit; maxQueryTypes bounds one query packet so it stays a single, un-fragmented datagram.
const (
	maxDiscoveredTypes     = 256
	maxQueryTypes          = 60
	maxDiscoveredInstances = 512
	maxQueryInstances      = 80
)

// commonServiceTypes seeds active discovery with the service types of the devices operators
// most want identified — printers, casts, home speakers, AirPlay/HomeKit, etc. — so they are
// found on the very first query, before the service-type enumeration response is parsed.
var commonServiceTypes = []string{
	"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp",
	"_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_spotify-connect._tcp",
	"_homekit._tcp", "_hap._tcp", "_matter._tcp", "_matterc._udp",
	"_http._tcp", "_https._tcp", "_ssh._tcp", "_sftp-ssh._tcp", "_workstation._tcp",
	"_smb._tcp", "_afpovertcp._tcp", "_device-info._tcp", "_companion-link._tcp",
}

// buildDiscoveryQuery packs ONE mDNS query with the service-type enumeration (PTR), a PTR
// for each service type (→ instances), and an SRV for each known instance (→ host + port).
// The explicit instance-SRV step is what reliably yields the SRV in the response's ANSWER —
// many responders (and reflectors) omit it from a type-PTR response's Additional, which is
// why services weren't being captured. One packet, many questions (reflector-friendly).
// Returns nil if it cannot pack.
func buildDiscoveryQuery(types, instances []string) []byte {
	m := new(dns.Msg)
	seen := map[string]bool{}
	add := func(name string, qtype uint16) {
		if seen[name] {
			return
		}
		seen[name] = true
		m.Question = append(m.Question, dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET})
	}
	add(serviceEnum, dns.TypePTR)
	for _, t := range types {
		add(dns.Fqdn(t+".local"), dns.TypePTR)
	}
	for _, inst := range instances {
		add(dns.Fqdn(inst), dns.TypeSRV)
	}
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

// parseInstances returns the service INSTANCE names listed in a service-type response (PTRs
// whose owner is a service type, e.g. _ipp._tcp.local → Printer._ipp._tcp.local), so active
// discovery can query each instance's SRV next round.
func parseInstances(b []byte) []string {
	var m dns.Msg
	if err := m.Unpack(b); err != nil || !m.Response {
		return nil
	}
	var out []string
	for _, sect := range [][]dns.RR{m.Answer, m.Extra} {
		for _, rr := range sect {
			ptr, ok := rr.(*dns.PTR)
			if !ok || ptr.Ptr == "" {
				continue
			}
			owner := strings.ToLower(strings.TrimSuffix(ptr.Hdr.Name, "."))
			if owner == strings.TrimSuffix(serviceEnum, ".") || serviceType(ptr.Hdr.Name) == "" {
				continue // the enum PTR, or an owner that isn't a service type
			}
			out = append(out, ptr.Ptr)
		}
	}
	return out
}

// parseServiceTypes returns the "_app._proto" service types listed in a service-type
// enumeration response (PTRs owned by _services._dns-sd._udp.local), so active discovery can
// learn types beyond the common seed and query their instances next round.
func parseServiceTypes(b []byte) []string {
	var m dns.Msg
	if err := m.Unpack(b); err != nil || !m.Response {
		return nil
	}
	var out []string
	for _, sect := range [][]dns.RR{m.Answer, m.Extra} {
		for _, rr := range sect {
			ptr, ok := rr.(*dns.PTR)
			if !ok || !strings.EqualFold(ptr.Hdr.Name, serviceEnum) {
				continue
			}
			if t := serviceType(ptr.Ptr); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}
