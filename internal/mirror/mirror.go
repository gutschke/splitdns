// Package mirror is the control-plane Cloudflare mirror: it fetches each configured
// local zone's records via the read-only CF API, builds the authoritative
// model.Zone (tunnel flattening, ENT/wildcard derivation, synthesized SOA),
// assembles a complete *model.Snapshot (zones + reverse + stub + vhost + the rebind
// AllowSuffix), and publishes it for the hot path to load atomically (design §2.5).
//
// This is the CORE mirror. Deferred to later steps (interfaces are in place for
// them): the SOAPoller serial state machine (§2.5 uses a periodic full refresh
// here), NS discovery, the SVCB/HTTPS sidecar, and warm-cache persistence.
package mirror

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/cfapi"
	"github.com/gutschke/splitdns/internal/config"
	"github.com/gutschke/splitdns/internal/model"
)

// wildcardProbe is the fixed sentinel label used to make CF synthesize the wildcard
// owner's tunnel addresses (design §2.5: a deterministic sentinel, never a random
// label that could collide with a real owner).
const wildcardProbe = "__splitdns_wildcard_probe__"

// ZoneLister is the slice of the CF API the mirror needs (satisfied by *cfapi.Client;
// faked in tests).
type ZoneLister interface {
	Zones(ctx context.Context) (map[string]string, error)
	AllRecords(ctx context.Context, zoneID string) ([]cfapi.Record, error)
}

// TunnelResolver resolves an owner name (or the wildcard sentinel) to the public
// addresses Cloudflare currently presents for it — the flattened tunnel addresses
// (design §2.5 TunnelResolver). AAAA absence is benign (e.g. an IPv4-only proxy).
type TunnelResolver interface {
	Resolve(ctx context.Context, fqdn string) (v4, v6 []netip.Addr, err error)
}

// BuildZone assembles one authoritative model.Zone from a zone's CF records.
func BuildZone(ctx context.Context, apex, zoneID string, recs []cfapi.Record, tr TunnelResolver, tunnelSuffixes []string) *model.Zone {
	apex = dns.Fqdn(strings.ToLower(apex))
	z := &model.Zone{
		ID:         zoneID,
		Apex:       apex,
		Records:    map[string]map[uint16][]model.RR{},
		Wildcards:  map[uint16][]model.RR{},
		ENT:        map[string]bool{},
		TunnelAddr: map[string]map[uint16][]model.RR{},
	}
	tunnelOwners := map[string]bool{}

	for _, r := range recs {
		owner := relOwner(r.Name, apex)
		rr, ok := toModelRR(r, zoneID)
		if !ok {
			continue // unsupported/sidecar-sourced type (HTTPS/SVCB) or malformed
		}
		if rr.Type == dns.TypeCNAME && isTunnelTarget(rr.Content, tunnelSuffixes) {
			tunnelOwners[owner] = true
			continue // flattened below; never stored as a CNAME
		}
		if owner == "*" {
			z.Wildcards[rr.Type] = append(z.Wildcards[rr.Type], rr)
		} else {
			if z.Records[owner] == nil {
				z.Records[owner] = map[uint16][]model.RR{}
			}
			z.Records[owner][rr.Type] = append(z.Records[owner][rr.Type], rr)
		}
		if rr.Type == dns.TypeNS && owner == "" {
			z.NS = append(z.NS, rr)
		}
	}

	// Flatten each tunnel owner: resolve the OWNER name (the wildcard uses the
	// sentinel) to its currently-presented public addresses.
	for owner := range tunnelOwners {
		fqdn := ownerFQDN(owner, apex)
		v4, v6, err := tr.Resolve(ctx, fqdn)
		if err != nil {
			continue // keep building; a failed tunnel flatten just omits those addrs
		}
		ta := map[uint16][]model.RR{}
		for _, a := range v4 {
			ta[dns.TypeA] = append(ta[dns.TypeA], addrRR(a))
		}
		for _, a := range v6 {
			ta[dns.TypeAAAA] = append(ta[dns.TypeAAAA], addrRR(a))
		}
		if len(ta) > 0 {
			z.TunnelAddr[owner] = ta
		}
	}

	deriveENT(z)
	z.SOA = synthSOA(apex)
	return z
}

// deriveENT marks interior nodes that have descendants but no RRset of their own as
// empty-non-terminals (RFC 4592), so the wildcard does not synthesize at/below them.
func deriveENT(z *model.Zone) {
	real := map[string]bool{}
	for owner := range z.Records {
		real[owner] = true
	}
	for owner := range z.Records {
		// Walk up the owner's ancestors (interior labels) toward the apex.
		labels := strings.Split(owner, ".")
		for i := 1; i < len(labels); i++ {
			anc := strings.Join(labels[i:], ".")
			if anc != "" && !real[anc] {
				z.ENT[anc] = true
			}
		}
	}
}

// BuildSnapshot fetches every configured local zone and assembles the full snapshot.
// A nil lister yields the base snapshot only (no CF mirror — local zones forward).
func BuildSnapshot(ctx context.Context, l ZoneLister, tr TunnelResolver, cfg config.Config, revZones []string) (*model.Snapshot, error) {
	if l == nil {
		return BaseSnapshot(cfg, revZones), nil
	}
	zones, err := l.Zones(ctx)
	if err != nil {
		return nil, fmt.Errorf("mirror: list zones: %w", err)
	}
	nameToID := map[string]string{}
	for id, name := range zones {
		nameToID[strings.ToLower(name)] = id
	}

	snap := BaseSnapshot(cfg, revZones)
	tunnelSuffixes := cfg.Cloudflare.ResolvedTunnelSuffixes()
	for _, zname := range cfg.Zones.Local {
		zname = strings.ToLower(strings.TrimSuffix(zname, "."))
		id, ok := nameToID[zname]
		if !ok {
			continue // configured local zone not in the account; skip (forwarded)
		}
		recs, rerr := l.AllRecords(ctx, id)
		if rerr != nil {
			return nil, fmt.Errorf("mirror: records for %s: %w", zname, rerr)
		}
		snap.Zones[dns.Fqdn(zname)] = BuildZone(ctx, zname, id, recs, tr, tunnelSuffixes)
	}
	snap.CFHealthy = true
	snap.BuiltAt = time.Now()
	return snap, nil
}

// BaseSnapshot builds the non-CF parts of the snapshot (reverse zones with
// synthesized SOAs, stub zones, the vhost redirect target, and the AllowSuffix set).
// Used both as the mirror's base and as main's cold-start snapshot (empty Zones).
func BaseSnapshot(cfg config.Config, revZones []string) *model.Snapshot {
	snap := &model.Snapshot{
		Zones:     map[string]*model.Zone{},
		StubZones: map[string]*model.StubZone{},
		ReverseZ:  map[string]*model.RevZone{},
		VHosts:    map[string]bool{},
		Static: map[string][]model.RR{
			// Synthetic record for the watchdog's in-process liveness probe (§3.9):
			// always present (even on a cold box before the first CF refresh), answered
			// purely from the snapshot, and never on the forward path.
			"health.splitdnsd.local.": {{
				Name: "health.splitdnsd.local.", Type: dns.TypeA, Class: dns.ClassINET,
				TTL: 60, Content: "127.0.0.1",
			}},
		},
		Excluded:     map[string]bool{},
		DDNSEligible: map[string]bool{},
		BuiltAt:      time.Now(),
	}
	for _, z := range cfg.VHost.ExcludeZones {
		snap.Excluded[dns.Fqdn(strings.ToLower(z))] = true
	}
	// Managed (DDNS-writable) names: the mDNS overlay must not shadow these (see resolver).
	for _, e := range cfg.DDNS.Eligible {
		snap.DDNSEligible[dns.Fqdn(strings.ToLower(strings.TrimSpace(e)))] = true
	}
	snap.LocalDomain = cfg.MDNS.LocalDomainLabel()
	var allow []string
	for _, z := range revZones {
		apex := dns.Fqdn(z)
		snap.ReverseZ[apex] = &model.RevZone{Apex: apex, SOA: synthSOA(apex)}
		allow = append(allow, apex)
	}
	for apex, targets := range cfg.Zones.Stub {
		a := dns.Fqdn(apex)
		var aps []netip.AddrPort
		for _, t := range targets {
			if ap, perr := netip.ParseAddrPort(t); perr == nil {
				aps = append(aps, ap)
			}
		}
		snap.StubZones[a] = &model.StubZone{Apex: a, Target: aps}
		allow = append(allow, a)
	}
	for _, z := range cfg.Zones.Local {
		allow = append(allow, dns.Fqdn(z))
	}
	if cfg.VHost.ProxyV4 != "" {
		if a, perr := netip.ParseAddr(cfg.VHost.ProxyV4); perr == nil {
			snap.VHostV4 = a
		}
	}
	if cfg.VHost.ProxyV6 != "" {
		if a, perr := netip.ParseAddr(cfg.VHost.ProxyV6); perr == nil {
			snap.VHostV6 = a
		}
	}
	sort.Strings(allow)
	snap.AllowSuffix = allow
	return snap
}

// --- record conversion ---

func toModelRR(r cfapi.Record, zoneID string) (model.RR, bool) {
	typ, ok := dns.StringToType[strings.ToUpper(r.Type)]
	if !ok {
		return model.RR{}, false
	}
	rr := model.RR{
		Name:     dns.Fqdn(strings.ToLower(r.Name)),
		Type:     typ,
		Class:    dns.ClassINET,
		TTL:      ttlOr(r.TTL),
		Proxied:  r.Proxied,
		ZoneID:   zoneID,
		RecordID: r.ID,
	}
	switch typ {
	case dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeTLSA:
		rr.Content = r.Content
	case dns.TypeCNAME, dns.TypeNS, dns.TypePTR:
		rr.Content = dns.Fqdn(r.Content)
		rr.Target = rr.Content
	case dns.TypeMX:
		pr, okp := model.CoercePriority(r.Priority)
		if !okp {
			return model.RR{}, false
		}
		rr.Priority = pr
		rr.Target = dns.Fqdn(r.Content)
	case dns.TypeSRV:
		w, p, t, err := model.ParseSRVContent(r.Content)
		if err != nil {
			return model.RR{}, false
		}
		pr, _ := model.CoercePriority(r.Priority)
		rr.Priority, rr.Weight, rr.Port, rr.Target = pr, w, p, t
	case dns.TypeTXT:
		rr.Content = quoteTXT(r.Content)
	default:
		// HTTPS/SVCB are sourced by the (deferred) SVCB sidecar, not the API; SOA is
		// synthesized. Skip anything else we do not model on the hot path.
		return model.RR{}, false
	}
	// Validate it actually renders, so a malformed record is dropped, not served.
	if _, err := rr.ToMiekg(); err != nil {
		return model.RR{}, false
	}
	return rr, true
}

func quoteTXT(s string) string {
	if strings.HasPrefix(s, `"`) {
		return s // already presentation-quoted
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func ttlOr(ttl int) uint32 {
	if ttl <= 1 { // CF "1" == automatic
		return 300
	}
	return uint32(ttl)
}

func addrRR(a netip.Addr) model.RR {
	typ := uint16(dns.TypeA)
	if a.Is6() {
		typ = dns.TypeAAAA
	}
	return model.RR{Type: typ, Class: dns.ClassINET, TTL: 300, Content: a.String(), Synthetic: true}
}

// isTunnelTarget reports whether a CNAME content ends in one of the configured
// tunnel suffixes (each already normalized to label-aligned ".suffix." form).
func isTunnelTarget(content string, tunnelSuffixes []string) bool {
	c := dns.Fqdn(strings.ToLower(content))
	for _, s := range tunnelSuffixes {
		if strings.HasSuffix(c, s) {
			return true
		}
	}
	return false
}

func relOwner(name, apex string) string {
	name = dns.Fqdn(strings.ToLower(name))
	if name == apex {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSuffix(name, apex), ".")
}

func ownerFQDN(owner, apex string) string {
	switch owner {
	case "":
		return apex
	case "*":
		return wildcardProbe + "." + apex
	default:
		return owner + "." + apex
	}
}

func synthSOA(apex string) model.RR {
	return model.RR{Name: apex, Type: dns.TypeSOA, Class: dns.ClassINET, TTL: 3600,
		Content: apex + " hostmaster." + apex + " 1 7200 3600 1209600 300"}
}

// withSOASerial returns soa with its serial field (the 3rd whitespace token of the
// SOA RDATA: mname rname SERIAL refresh retry expire minimum) replaced by serial.
// This is how the polled Cloudflare serial reaches the served SOA RDATA so the
// authoritative apex SOA and every negative-AUTHORITY SOA carry the real serial
// (§2.4d parity, D5). A malformed/short Content is returned unchanged.
func withSOASerial(soa model.RR, serial uint32) model.RR {
	f := strings.Fields(soa.Content)
	if len(f) != 7 {
		return soa
	}
	f[2] = strconv.FormatUint(uint64(serial), 10)
	soa.Content = strings.Join(f, " ")
	return soa
}
