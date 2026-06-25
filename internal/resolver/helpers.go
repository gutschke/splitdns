package resolver

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// reply builds an authoritative-capable response skeleton for req.
func reply(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	return resp
}

func errReply(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	return resp
}

func isArpa(name string) bool {
	return strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.")
}

// isSuffixLabel reports whether apex is a label-aligned suffix of name (so
// "x.sub.example.com." matches apex "sub.example.com." but "xsub...." does not).
func isSuffixLabel(name, apex string) bool {
	if name == apex {
		return true
	}
	return strings.HasSuffix(name, "."+apex)
}

// longestZoneSuffix returns the longest zone apex that is a label suffix of name.
func longestZoneSuffix(name string, zones map[string]*model.Zone) string {
	best := ""
	for apex := range zones {
		if isSuffixLabel(name, apex) && len(apex) > len(best) {
			best = apex
		}
	}
	return best
}

func longestReverseZone(name string, rz map[string]*model.RevZone) *model.RevZone {
	var best *model.RevZone
	bestLen := 0
	for apex, z := range rz {
		if isSuffixLabel(name, apex) && len(apex) > bestLen {
			best, bestLen = z, len(apex)
		}
	}
	return best
}

// relativeOwner returns the owner label(s) of name relative to apex ("" for the
// apex itself), without the trailing dot (e.g. "www" or "a.b").
func relativeOwner(name, apex string) string {
	if name == apex {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSuffix(name, apex), ".")
}

func labelCount(owner string) int {
	if owner == "" {
		return 0
	}
	return strings.Count(owner, ".") + 1
}

// appendMatching appends every RR in recs whose type matches qtype (ANY matches
// all) to resp.Answer, rewriting the owner to name. Returns true if any matched.
func appendMatching(resp *dns.Msg, recs []model.RR, name string, qtype uint16) bool {
	matched := false
	for _, r := range recs {
		if qtype != dns.TypeANY && r.Type != qtype {
			continue
		}
		if rr := toRR(r, name); rr != nil {
			resp.Answer = append(resp.Answer, rr)
			matched = true
		}
	}
	return matched
}

// toRR renders a model.RR as a dns.RR with its owner overridden to name.
func toRR(r model.RR, name string) dns.RR {
	c := r
	c.Name = dns.Fqdn(name)
	rr, err := c.ToMiekg()
	if err != nil {
		return nil
	}
	return rr
}

// addrRR builds an A/AAAA dns.RR directly from an address string.
func addrRR(name string, qtype uint16, content string, ttl uint32) dns.RR {
	r := model.RR{Name: dns.Fqdn(name), Type: qtype, Class: dns.ClassINET, TTL: ttl, Content: content}
	rr, err := r.ToMiekg()
	if err != nil {
		return nil
	}
	return rr
}

// setNegativeSOA places the zone/reverse SOA in AUTHORITY with the RFC-2308 negative
// TTL = min(SOA.TTL, SOA.MINIMUM) and sets rcode (Success=NODATA, NameError=NXDOMAIN).
func setNegativeSOA(resp *dns.Msg, soa model.RR, apex string, rcode int) {
	resp.Rcode = rcode
	if soa.Content == "" && soa.Target == "" {
		return // no SOA available (e.g. mDNS); leave AUTHORITY empty
	}
	negTTL := soa.TTL
	if m := soaMinimum(soa); m > 0 && m < negTTL {
		negTTL = m
	}
	c := soa
	c.Name = dns.Fqdn(apex)
	c.TTL = negTTL
	if rr, err := c.ToMiekg(); err == nil {
		resp.Ns = append(resp.Ns, rr)
	}
}

// soaMinimum extracts the MINIMUM field (last token) from an SOA's canonical content
// "mname rname serial refresh retry expire minimum".
func soaMinimum(soa model.RR) uint32 {
	fields := strings.Fields(soa.Content)
	if len(fields) < 7 {
		return 0
	}
	n, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}
