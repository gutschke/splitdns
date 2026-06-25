// Package mdns is the control-plane multicast-DNS source. It receives mDNS
// announcements (from avahi-style responders and from splitdns-notify(8)),
// maintains a cache of *.local hosts, publishes an immutable model.MDNSView for the
// hot path to answer *.local forward/reverse queries, and emits change events that
// drive the DDNS writer. It performs no work on the hot path (design §3, §2.2): the
// data plane only reads the published atomic snapshot.
package mdns

import (
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Announcement is the set of A/AAAA addresses for one bare *.local host extracted
// from a single mDNS response packet.
type Announcement struct {
	Host  string
	Addrs []netip.Addr
	TTL   uint32
}

// ParsePacket extracts host announcements from an mDNS response packet. Non-response
// packets and unparseable bytes yield no announcements. A/AAAA answers are grouped
// by host; link-local (fe80::/10) addresses are dropped (they are never useful for
// split-horizon resolution).
func ParsePacket(b []byte) []Announcement {
	var m dns.Msg
	if err := m.Unpack(b); err != nil || !m.Response {
		return nil
	}
	byHost := map[string]*Announcement{}
	var order []string
	add := func(host string, addr netip.Addr, ttl uint32) {
		if host == "" || !addr.IsValid() {
			return
		}
		addr = addr.Unmap()
		if addr.IsLinkLocalUnicast() {
			return
		}
		a, ok := byHost[host]
		if !ok {
			a = &Announcement{Host: host, TTL: ttl}
			byHost[host] = a
			order = append(order, host)
		}
		for _, ex := range a.Addrs {
			if ex == addr {
				return // dedup within a packet
			}
		}
		a.Addrs = append(a.Addrs, addr)
		if ttl < a.TTL || a.TTL == 0 {
			a.TTL = ttl
		}
	}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(v.A.To4()); ok {
				add(canonHost(v.Hdr.Name), ip, v.Hdr.Ttl)
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
				add(canonHost(v.Hdr.Name), ip, v.Hdr.Ttl)
			}
		}
	}
	out := make([]Announcement, 0, len(order))
	for _, h := range order {
		out = append(out, *byHost[h])
	}
	return out
}

// canonHost reduces an mDNS owner name to a bare single-label *.local host, or ""
// for anything else (service names, multi-label names, leading underscore).
func canonHost(name string) string {
	h := strings.ToLower(name)
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimSuffix(h, ".local")
	if h == "" || strings.Contains(h, ".") || strings.HasPrefix(h, "_") {
		return ""
	}
	return h
}
