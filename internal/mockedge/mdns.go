package mockedge

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// MDNSAnnouncement builds the authoritative mDNS response packet splitdns-notify(8)
// emits: <host>.local. with the given A/AAAA addresses at ttl. host may be bare or
// already a .local. fqdn.
func MDNSAnnouncement(host string, ttl uint32, addrs ...string) ([]byte, error) {
	name := dns.Fqdn(host)
	if !hasLocalSuffix(name) {
		name = dns.Fqdn(trimDot(host) + ".local")
	}
	m := new(dns.Msg)
	m.Response = true
	m.Authoritative = true
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("mockedge: bad addr %q: %w", s, err)
		}
		hdr := dns.RR_Header{Name: name, Class: dns.ClassINET, Ttl: ttl}
		if a.Is4() {
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IP(a.AsSlice())})
		} else {
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(a.AsSlice())})
		}
	}
	return m.Pack()
}

// MDNSPeer sends mDNS announcements by unicast to a listener (the cross-subnet path
// splitdns-notify relies on). It is a trusted on-segment notifier for tests.
type MDNSPeer struct {
	target string // host:port of the listener
}

// NewMDNSPeer targets a listener at addr (host:port).
func NewMDNSPeer(addr string) *MDNSPeer { return &MDNSPeer{target: addr} }

// Announce builds and unicasts an announcement for host with the given addresses.
func (p *MDNSPeer) Announce(host string, ttl uint32, addrs ...string) error {
	pkt, err := MDNSAnnouncement(host, ttl, addrs...)
	if err != nil {
		return err
	}
	c, err := net.Dial("udp", p.target)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(pkt)
	return err
}

func hasLocalSuffix(fqdn string) bool {
	return len(fqdn) >= 7 && lower(fqdn[len(fqdn)-7:]) == ".local."
}

func trimDot(s string) string {
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}
