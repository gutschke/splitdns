// Package resolver is the hot-path query pipeline: a PURE function over an
// immutable *model.Snapshot and *model.MDNSView that classifies a query and either
// produces the answer directly (authoritative CF zone, *.local, reverse, static,
// vhost redirect, RFC-2308 negatives) or signals that the handler must forward it
// (default upstreams, or a stub zone's resolvers). It performs NO I/O and takes no
// locks — the caller loads the two atomic snapshots once and passes them in
// (design §2.4). The precedence order here is load-bearing; see §2.4 steps 1-8.
package resolver

import (
	"strings"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// Outcome is the resolver's decision. Exactly one of the three modes applies:
// Msg != nil (reply directly), Forward (to default upstreams), or Stub (to these
// resolver host:port targets). Forwarded/stub answers are rebind-filtered by the
// handler unless the name is in Snapshot.AllowSuffix.
type Outcome struct {
	Msg     *dns.Msg
	Forward bool
	Stub    []string
}

// Resolve classifies req and returns the Outcome. snap/view must be non-nil.
func Resolve(snap *model.Snapshot, view *model.MDNSView, req *dns.Msg) Outcome {
	if len(req.Question) != 1 {
		return Outcome{Msg: errReply(req, dns.RcodeFormatError)}
	}
	q := req.Question[0]
	name := strings.ToLower(dns.Fqdn(q.Name))
	qtype := q.Qtype

	// Step 1b — resolver.arpa is a special-use domain (RFC 9462 §6.4) that MUST be
	// answered locally and never forwarded to the public root. With Discovery of
	// Designated Resolvers unconfigured, we return authoritative NODATA (NOERROR, no
	// records) for the whole space — the correct "no designated encrypted resolver"
	// signal — so a client's DDR probe (SVCB _dns.resolver.arpa) stays on the LAN
	// instead of leaking upstream. (This is also the hook where a future DDR feature
	// would synthesize the SVCB pointing at splitdnsd's own encrypted endpoint.)
	if name == "resolver.arpa." || strings.HasSuffix(name, ".resolver.arpa.") {
		resp := reply(req)
		resp.Authoritative = true
		return Outcome{Msg: resp}
	}

	// Step 2 — static specials / seeded hosts (R5), exact match wins.
	if out, ok := answerStatic(snap, req, name, qtype); ok {
		return out
	}
	// Step 3 — reverse PTR (R6): authoritative only under a configured reverse zone.
	if isArpa(name) {
		return answerReverse(snap, view, req, name, qtype)
	}
	// Step 4 — *.local / LAN (R4): served from the mDNS view only, never forwarded.
	if strings.HasSuffix(name, ".local.") {
		return answerLocal(view, req, name, qtype)
	}
	// Step 5 — stub/forward zones take precedence over the parent CF zone.
	if tgt := stubMatch(snap, name); len(tgt) > 0 {
		return Outcome{Stub: tgt}
	}
	// Steps 6+7 — vhost redirect (short-circuit) then authoritative CF zone.
	if apex := longestZoneSuffix(name, snap.Zones); apex != "" {
		return answerZoneOrVHost(snap, req, name, apex, qtype)
	}
	// Step 8 — everything else is forwarded. ANY is answered minimally (RFC 8482,
	// §2.4c) instead of relayed, so splitdnsd cannot be used as an ANY-amplification
	// reflector for forwarded public names.
	if qtype == dns.TypeANY {
		return Outcome{Msg: minimalANY(req, name)}
	}
	return Outcome{Forward: true}
}

// minimalANY builds the RFC 8482 minimal response: a single HINFO RR naming the
// RFC, served NOERROR. Not authoritative (the name is forwarded, not ours).
func minimalANY(req *dns.Msg, name string) *dns.Msg {
	resp := reply(req)
	resp.Answer = append(resp.Answer, &dns.HINFO{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: minimalANYTTL},
		Cpu: "RFC8482",
	})
	return resp
}

func answerStatic(snap *model.Snapshot, req *dns.Msg, name string, qtype uint16) (Outcome, bool) {
	recs, ok := snap.Static[name]
	if !ok {
		return Outcome{}, false
	}
	resp := reply(req)
	resp.Authoritative = true
	// appendMatching adds the records of this type. A static owner that exists but lacks
	// this type yields authoritative NODATA (no SOA — the static table is not a zone);
	// still authoritative, never forwarded.
	appendMatching(resp, recs, name, qtype)
	return Outcome{Msg: resp}, true
}

func answerReverse(snap *model.Snapshot, view *model.MDNSView, req *dns.Msg, name string, qtype uint16) Outcome {
	rz := longestReverseZone(name, snap.ReverseZ)
	if rz == nil {
		// PTR outside any managed reverse space is forwarded (Q2).
		return Outcome{Forward: true}
	}
	resp := reply(req)
	resp.Authoritative = true
	matched := false
	if qtype == dns.TypePTR || qtype == dns.TypeANY {
		matched = appendMatching(resp, view.Reverse[name], name, dns.TypePTR)
		if appendMatching(resp, snap.Static[name], name, dns.TypePTR) {
			matched = true
		}
	}
	if !matched {
		setNegativeSOA(resp, rz.SOA, rz.Apex, dns.RcodeSuccess)
	}
	return Outcome{Msg: resp}
}

func answerLocal(view *model.MDNSView, req *dns.Msg, name string, qtype uint16) Outcome {
	label := strings.TrimSuffix(name, ".local.")
	resp := reply(req)
	resp.Authoritative = true
	recs, exists := view.Forward[label]
	if !exists {
		// Unknown *.local host: NXDOMAIN (mDNS carries no SOA, so none in AUTHORITY).
		resp.Rcode = dns.RcodeNameError
		return Outcome{Msg: resp}
	}
	appendMatching(resp, recs, name, qtype) // NODATA if the host lacks this family
	return Outcome{Msg: resp}
}

func answerZoneOrVHost(snap *model.Snapshot, req *dns.Msg, name, apex string, qtype uint16) Outcome {
	zone := snap.Zones[apex]
	owner := relativeOwner(name, apex)

	// Step 6 — vhost / naked / www redirect, BEFORE the authoritative answer. Applies
	// to the apex or a single label that is www or a known vhost; configured excluded
	// zones (Snapshot.Excluded) fall through to the authoritative assembler.
	if isVHostCandidate(snap, apex, owner) {
		return Outcome{Msg: vhostReply(snap, req, name, owner, qtype, zone)}
	}
	// Step 7 — authoritative CF zone.
	return Outcome{Msg: answerAuthoritative(req, zone, name, owner, qtype)}
}

// isVHostCandidate implements the §2.4 step-6 gate: ≤1 relative label, zone not an
// excluded one, and the label empty (apex) / www / in the vhost set.
func isVHostCandidate(snap *model.Snapshot, apex, owner string) bool {
	if snap.Excluded[apex] {
		return false
	}
	// No redirect target configured ([vhost] proxy_v4/proxy_v6 unset) => the
	// vhost/naked/www redirect is OFF; serve the name authoritatively from the
	// zone rather than redirecting to a nonexistent proxy (which would NODATA it).
	if !snap.VHostV4.IsValid() && !snap.VHostV6.IsValid() {
		return false
	}
	if owner != "" && labelCount(owner) > 1 {
		return false
	}
	return owner == "" || owner == "www" || snap.VHosts[owner]
}

// vhostReply implements the §2.4 step-6 redirect, reconciled with §2.4a: address
// queries are redirected to the reverse proxy; CNAME and HTTPS are stripped to NODATA; and the
// APEX still serves its real non-address RRsets (MX/SOA/NS/CAA/TXT/TLSA) — only a
// pure www/vhost LABEL is address-only. (Inverting this would break mail/zone
// metadata for a redirected apex.)
func vhostReply(snap *model.Snapshot, req *dns.Msg, name, owner string, qtype uint16, zone *model.Zone) *dns.Msg {
	resp := reply(req)
	resp.Authoritative = true
	switch qtype {
	case dns.TypeA:
		if snap.VHostV4.IsValid() {
			resp.Answer = append(resp.Answer, addrRR(name, dns.TypeA, snap.VHostV4.String(), vhostTTL))
			return resp
		}
	case dns.TypeAAAA:
		if snap.VHostV6.IsValid() {
			resp.Answer = append(resp.Answer, addrRR(name, dns.TypeAAAA, snap.VHostV6.String(), vhostTTL))
			return resp
		}
	case dns.TypeCNAME, dns.TypeHTTPS:
		// Explicitly stripped on the redirect path.
	default:
		// At the apex, non-address RRsets are real (mail, zone metadata).
		if owner == "" && zone != nil {
			if rrs := zone.Records[""][qtype]; len(rrs) > 0 {
				appendMatching(resp, rrs, name, qtype)
				return resp
			}
		}
	}
	if zone != nil {
		setNegativeSOA(resp, zone.SOA, zone.Apex, dns.RcodeSuccess)
	}
	return resp
}

func stubMatch(snap *model.Snapshot, name string) []string {
	var best string
	for apex := range snap.StubZones {
		// Label-aligned longest-suffix match (isSuffixLabel); no bare HasSuffix (D23).
		if isSuffixLabel(name, apex) && len(apex) > len(best) {
			best = apex
		}
	}
	if best == "" {
		return nil
	}
	sz := snap.StubZones[best]
	out := make([]string, 0, len(sz.Target))
	for _, t := range sz.Target {
		out = append(out, t.String())
	}
	return out
}

const (
	vhostTTL      = 60
	minimalANYTTL = 3600 // RFC 8482 minimal-ANY HINFO TTL
)
