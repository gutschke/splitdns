package resolver

import (
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// dnssdMeta is the DNS-SD service-type enumeration owner (bare, under the local domain).
const dnssdMeta = "_services._dns-sd._udp"

// dnssdTTL is the TTL for synthesized enumeration PTRs (instance SRV/TXT reuse the host TTL).
const dnssdTTL = 120

// answerDNSSD serves a DNS-SD node — the service-type meta-enumeration
// (_services._dns-sd._udp.<domain>), a service-type enumeration (_ipp._tcp.<domain>), or a
// service instance (host._ipp._tcp.<domain>) — synthesized from the passively-captured mDNS
// services. It is a READ-ONLY projection of view.Services and NEVER triggers an active query,
// so browsing can't provoke multicast. Returns ok=false when label is not a DNS-SD node (the
// caller then treats it as a bare host). A recognized-but-empty node is NODATA (mDNS carries
// no SOA, so the authority section stays empty), matching the bare-host convention.
func answerDNSSD(view *model.MDNSView, resp *dns.Msg, name, label string, qtype uint16) (Outcome, bool) {
	kind, host, typ := parseDNSSD(label)
	if kind == "" {
		return Outcome{}, false
	}
	suffix := name[len(label):] // ".lan." / ".local." — reuse the domain the client queried

	switch kind {
	case "meta": // enumerate the distinct service types present, as PTRs
		types := map[string]struct{}{}
		for _, svcs := range view.Services {
			for _, s := range svcs {
				types[s.Type] = struct{}{}
			}
		}
		for _, t := range sortedSet(types) {
			sdAppend(resp, qtype, dns.TypePTR, &dns.PTR{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: dnssdTTL},
				Ptr: t + suffix,
			})
		}
	case "type": // enumerate the instances (hosts) advertising this type, as PTRs
		var insts []string
		for h, svcs := range view.Services {
			for _, s := range svcs {
				if s.Type == typ {
					insts = append(insts, h+"."+typ+suffix)
					break
				}
			}
		}
		sort.Strings(insts)
		for _, inst := range insts {
			sdAppend(resp, qtype, dns.TypePTR, &dns.PTR{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: dnssdTTL},
				Ptr: inst,
			})
		}
	case "instance": // SRV (target = host.<domain>) + TXT for the named instance
		ttl := hostTTL(view, host)
		for _, s := range view.Services[host] {
			if s.Type != typ {
				continue
			}
			sdAppend(resp, qtype, dns.TypeSRV, &dns.SRV{
				Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl},
				Target: host + suffix, Port: s.Port,
			})
			if len(s.Text) > 0 {
				sdAppend(resp, qtype, dns.TypeTXT, &dns.TXT{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
					Txt: s.Text,
				})
			}
		}
	}
	return Outcome{Msg: resp}, true
}

// parseDNSSD classifies a bare local label as a DNS-SD node: "meta" (the service-type
// enumeration), "type" (a `_app._proto` service type), "instance" (a `host._app._proto`
// service instance), or "" (not a DNS-SD node).
func parseDNSSD(label string) (kind, host, typ string) {
	if label == dnssdMeta {
		return "meta", "", ""
	}
	labels := strings.Split(label, ".")
	n := len(labels)
	if n < 2 {
		return "", "", ""
	}
	if proto := labels[n-1]; proto != "_tcp" && proto != "_udp" {
		return "", "", ""
	}
	if !strings.HasPrefix(labels[n-2], "_") {
		return "", "", "" // second-to-last isn't a service label => not DNS-SD
	}
	typ = labels[n-2] + "." + labels[n-1]
	if n == 2 {
		return "type", "", typ
	}
	return "instance", strings.Join(labels[:n-2], "."), typ
}

// sdAppend adds rr to the Answer section iff the query asked for its type (or ANY).
func sdAppend(resp *dns.Msg, qtype, rrtype uint16, rr dns.RR) {
	if qtype == dns.TypeANY || qtype == rrtype {
		resp.Answer = append(resp.Answer, rr)
	}
}

// hostTTL returns the announced TTL of the host's address records (so a service's SRV/TXT
// expire with the host), defaulting to dnssdTTL if unknown.
func hostTTL(view *model.MDNSView, host string) uint32 {
	for _, rr := range view.Forward[host] {
		if rr.TTL > 0 {
			return rr.TTL
		}
	}
	return dnssdTTL
}

func sortedSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
