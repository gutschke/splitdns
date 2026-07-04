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
	// Scan Answer AND Additional: a response to a service/PTR query carries the address
	// records in the Additional section (RFC 6762 §6.3), so overhearing another client's
	// query is a legitimate way to learn a host that isn't currently announcing itself.
	for _, sect := range [][]dns.RR{m.Answer, m.Extra} {
		for _, rr := range sect {
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

// Service links a DNS-SD service type (e.g. "_ipp._tcp") to the bare *.local host that
// offers it, derived from an SRV record's owner (the instance) and target (the host). It is
// a passive diagnostic fingerprint only — never answered on the wire.
type Service struct {
	Host string
	Type string
	TTL  uint32
}

// ParseServices extracts host->service-type links from an mDNS response's SRV records.
// Non-response / unparseable packets yield nothing.
func ParseServices(b []byte) []Service {
	var m dns.Msg
	if err := m.Unpack(b); err != nil || !m.Response {
		return nil
	}
	var out []Service
	seen := map[string]bool{}
	// SRV records commonly arrive in the Additional section of a service query-response, so
	// scan Answer AND Additional.
	for _, sect := range [][]dns.RR{m.Answer, m.Extra} {
		for _, rr := range sect {
			srv, ok := rr.(*dns.SRV)
			if !ok {
				continue
			}
			host := canonHost(srv.Target)
			typ := serviceType(srv.Hdr.Name)
			if host == "" || typ == "" {
				continue
			}
			key := host + "|" + typ
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Service{Host: host, Type: typ, TTL: srv.Hdr.Ttl})
		}
	}
	return out
}

// serviceType extracts the "_app._proto" DNS-SD service type from an instance owner name
// ("Instance._app._proto.local."), or "" if the trailing two labels are not both
// underscore-prefixed.
func serviceType(name string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	n = strings.TrimSuffix(n, ".local")
	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return ""
	}
	app, proto := labels[len(labels)-2], labels[len(labels)-1]
	if strings.HasPrefix(app, "_") && strings.HasPrefix(proto, "_") {
		return app + "." + proto
	}
	return ""
}
