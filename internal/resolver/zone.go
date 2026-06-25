package resolver

import (
	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

const maxCNAMEChain = 8 // RFC-1034 loop guard (design §2.4a step 6)

// answerAuthoritative is the central authoritative behavior (design §2.4a): exact
// owner → ENT/closest-encloser → wildcard (RFC 4592), tunnel-flattened addresses,
// in-zone CNAME chasing, and RFC-2308 negatives with the zone SOA in AUTHORITY.
func answerAuthoritative(req *dns.Msg, zone *model.Zone, name, owner string, qtype uint16) *dns.Msg {
	resp := reply(req)
	resp.Authoritative = true
	if zone == nil {
		resp.Rcode = dns.RcodeServerFailure
		return resp
	}
	ownerRecs := zone.Records[owner]
	tunnel := zone.TunnelAddr[owner]
	exactExists := ownerRecs != nil || tunnel != nil
	isENT := zone.ENT[owner]

	switch {
	case qtype == dns.TypeCNAME:
		// A flattened owner's CNAME does not exist as a CNAME (NODATA); a real CNAME
		// is answered normally.
		if cn := ownerRecs[dns.TypeCNAME]; len(cn) > 0 {
			appendMatching(resp, cn, name, dns.TypeCNAME)
			return resp
		}
		if exactExists || isENT {
			setNegativeSOA(resp, zone.SOA, zone.Apex, dns.RcodeSuccess)
			return resp
		}
		return wildcardOrNX(resp, zone, name, qtype)

	case qtype == dns.TypeA || qtype == dns.TypeAAAA:
		if a := ownerRecs[qtype]; len(a) > 0 { // real address wins
			appendMatching(resp, a, name, qtype)
			return resp
		}
		if t := tunnel[qtype]; len(t) > 0 { // flattened tunnel address
			appendMatching(resp, t, name, qtype)
			return resp
		}
		if cn := ownerRecs[dns.TypeCNAME]; len(cn) > 0 { // real CNAME → chase in-zone
			chaseCNAME(resp, zone, owner, name, qtype, 0)
			return resp
		}
		if exactExists || isENT {
			setNegativeSOA(resp, zone.SOA, zone.Apex, dns.RcodeSuccess)
			return resp
		}
		return wildcardOrNX(resp, zone, name, qtype)

	case qtype == dns.TypeANY && exactExists:
		// RFC-clean ANY: every RRset actually present at the owner (incl. TLSA). At a
		// flattened owner the CNAME is suppressed; tunnel addresses appear as A/AAAA.
		for t, rrs := range ownerRecs {
			if t == dns.TypeCNAME && tunnel != nil {
				continue
			}
			appendMatching(resp, rrs, name, t)
		}
		for t, rrs := range tunnel {
			appendMatching(resp, rrs, name, t)
		}
		return resp

	default:
		if rrs := ownerRecs[qtype]; len(rrs) > 0 { // MX/TXT/SOA/NS/CAA/HTTPS/TLSA/SRV…
			appendMatching(resp, rrs, name, qtype)
			return resp
		}
		// A real (non-flattened) CNAME at a non-apex owner is chased for other types.
		if owner != "" {
			if cn := ownerRecs[dns.TypeCNAME]; len(cn) > 0 {
				chaseCNAME(resp, zone, owner, name, qtype, 0)
				return resp
			}
		}
		if exactExists || isENT {
			setNegativeSOA(resp, zone.SOA, zone.Apex, dns.RcodeSuccess)
			return resp
		}
		return wildcardOrNX(resp, zone, name, qtype)
	}
}

// wildcardOrNX applies RFC-4592 wildcard synthesis (including the flattened wildcard
// tunnel addresses, TunnelAddr["*"]) or returns NXDOMAIN when no wildcard exists.
func wildcardOrNX(resp *dns.Msg, zone *model.Zone, name string, qtype uint16) *dns.Msg {
	wt := zone.TunnelAddr["*"]
	wc := zone.Wildcards
	if (qtype == dns.TypeA || qtype == dns.TypeAAAA) && len(wt[qtype]) > 0 {
		appendMatching(resp, wt[qtype], name, qtype)
		return resp
	}
	if len(wc[qtype]) > 0 {
		appendMatching(resp, wc[qtype], name, qtype)
		return resp
	}
	if len(wc) > 0 || len(wt) > 0 {
		// Wildcard owner exists but not for this type: NODATA.
		setNegativeSOA(resp, zone.SOA, zone.Apex, dns.RcodeSuccess)
		return resp
	}
	setNegativeSOA(resp, zone.SOA, zone.Apex, dns.RcodeNameError)
	return resp
}

// chaseCNAME appends the in-zone CNAME chain in order plus the terminal RRset for
// qtype (RFC 1034 §3.6.2). Out-of-zone targets stop the chase (just the CNAME RR).
func chaseCNAME(resp *dns.Msg, zone *model.Zone, owner, name string, qtype uint16, depth int) {
	if depth > maxCNAMEChain {
		return
	}
	cn := zone.Records[owner][dns.TypeCNAME]
	if len(cn) == 0 {
		return
	}
	appendMatching(resp, cn, name, dns.TypeCNAME)
	target := targetOf(cn[0])
	if !isSuffixLabel(target, zone.Apex) {
		return // out-of-zone: client/forwarder chases
	}
	tOwner := relativeOwner(target, zone.Apex)
	if rrs := zone.Records[tOwner][qtype]; len(rrs) > 0 {
		appendMatching(resp, rrs, target, qtype)
		return
	}
	if (qtype == dns.TypeA || qtype == dns.TypeAAAA) && len(zone.TunnelAddr[tOwner][qtype]) > 0 {
		appendMatching(resp, zone.TunnelAddr[tOwner][qtype], target, qtype)
		return
	}
	if len(zone.Records[tOwner][dns.TypeCNAME]) > 0 {
		chaseCNAME(resp, zone, tOwner, target, qtype, depth+1)
	}
}

func targetOf(r model.RR) string {
	if r.Target != "" {
		return dns.Fqdn(r.Target)
	}
	return dns.Fqdn(r.Content)
}
