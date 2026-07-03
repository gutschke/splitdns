package resolver

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

func soa(apex string) model.RR {
	return model.RR{Name: apex, Type: dns.TypeSOA, Class: dns.ClassINET, TTL: 3600,
		Content: "ns1." + apex + " hostmaster." + apex + " 1 7200 3600 1209600 300"}
}
func a(content string) model.RR {
	return model.RR{Type: dns.TypeA, Class: dns.ClassINET, TTL: 300, Content: content}
}
func aaaa(content string) model.RR {
	return model.RR{Type: dns.TypeAAAA, Class: dns.ClassINET, TTL: 300, Content: content}
}
func cname(target string) model.RR {
	return model.RR{Type: dns.TypeCNAME, Class: dns.ClassINET, TTL: 300, Content: target}
}

// rz10 is a reverse zone covering 10.0.0.0/8 so test mDNS addresses (10.x) count as local.
func rz10() map[string]*model.RevZone {
	return map[string]*model.RevZone{"10.in-addr.arpa.": {Apex: "10.in-addr.arpa.", SOA: soa("10.in-addr.arpa.")}}
}

func buildSnap() (*model.Snapshot, *model.MDNSView) {
	example := &model.Zone{
		Apex: "example.com.",
		SOA:  soa("example.com."),
		Records: map[string]map[uint16][]model.RR{
			"":       {dns.TypeMX: {{Type: dns.TypeMX, Class: dns.ClassINET, TTL: 3600, Priority: 10, Target: "mail.example.com."}}},
			"sip":    {dns.TypeA: {a("203.0.113.20")}},
			"alias1": {dns.TypeCNAME: {cname("alias2.example.com.")}},
			"alias2": {dns.TypeCNAME: {cname("host3.example.com.")}},
			"host3":  {dns.TypeA: {a("203.0.113.40")}},
		},
		ENT:       map[string]bool{"_udp.sip": true},
		Wildcards: map[uint16][]model.RR{},
		TunnelAddr: map[string]map[uint16][]model.RR{
			"":           {dns.TypeA: {a("203.0.113.10")}, dns.TypeAAAA: {aaaa("2001:db8::10")}},
			"*":          {dns.TypeA: {a("203.0.113.10")}, dns.TypeAAAA: {aaaa("2001:db8::10")}},
			"tunnelhost": {dns.TypeA: {a("203.0.113.30")}},
		},
	}
	// A zone configured as excluded from the vhost redirect (serves its tunnel addrs).
	excluded := &model.Zone{
		Apex:      "excluded.test.",
		SOA:       soa("excluded.test."),
		Records:   map[string]map[uint16][]model.RR{},
		ENT:       map[string]bool{},
		Wildcards: map[uint16][]model.RR{},
		TunnelAddr: map[string]map[uint16][]model.RR{
			"": {dns.TypeA: {a("203.0.113.50")}, dns.TypeAAAA: {aaaa("2001:db8::50")}},
		},
	}
	snap := &model.Snapshot{
		Zones:     map[string]*model.Zone{"example.com.": example, "excluded.test.": excluded},
		StubZones: map[string]*model.StubZone{"sub.example.com.": {Apex: "sub.example.com.", Target: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}}},
		ReverseZ:  map[string]*model.RevZone{"2.0.192.in-addr.arpa.": {Apex: "2.0.192.in-addr.arpa.", SOA: soa("2.0.192.in-addr.arpa.")}},
		VHosts:    map[string]bool{"shop": true},
		Excluded:  map[string]bool{"excluded.test.": true},
		Static:    map[string][]model.RR{"gw.example.test.": {a("203.0.113.99")}},
		VHostV4:   netip.MustParseAddr("198.51.100.7"),
	}
	view := &model.MDNSView{
		Forward: map[string][]model.RR{"edge": {a("192.0.2.50")}},
		Reverse: map[string][]model.RR{"10.2.0.192.in-addr.arpa.": {{Type: dns.TypePTR, Class: dns.ClassINET, TTL: 120, Content: "edge.local.", Target: "edge.local."}}},
	}
	return snap, view
}

func ask(t *testing.T, snap *model.Snapshot, view *model.MDNSView, qname string, qtype uint16) (Outcome, *dns.Msg) {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	out := Resolve(snap, view, req)
	return out, out.Msg
}

func answers(m *dns.Msg, qtype uint16) []string {
	var out []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				out = append(out, v.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				out = append(out, v.AAAA.String())
			}
		case *dns.PTR:
			if qtype == dns.TypePTR {
				out = append(out, v.Ptr)
			}
		}
	}
	return out
}

func hasType(m *dns.Msg, t uint16) bool {
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}

func TestStatic(t *testing.T) {
	snap, view := buildSnap()
	_, m := ask(t, snap, view, "gw.example.test.", dns.TypeA)
	if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != "203.0.113.99" {
		t.Fatalf("static A = %v, want [203.0.113.99]", got)
	}
}

func TestReverse(t *testing.T) {
	snap, view := buildSnap()
	_, m := ask(t, snap, view, "10.2.0.192.in-addr.arpa.", dns.TypePTR)
	if got := answers(m, dns.TypePTR); len(got) != 1 || got[0] != "edge.local." {
		t.Fatalf("PTR = %v, want [edge.local.]", got)
	}
	// Unknown PTR under the configured reverse zone => NODATA with the reverse SOA.
	_, m2 := ask(t, snap, view, "99.2.0.192.in-addr.arpa.", dns.TypePTR)
	if m2.Rcode != dns.RcodeSuccess || len(m2.Answer) != 0 || len(m2.Ns) != 1 {
		t.Fatalf("unknown PTR: rcode=%d ans=%d ns=%d, want NODATA+SOA", m2.Rcode, len(m2.Answer), len(m2.Ns))
	}
	if m2.Ns[0].Header().Name != "2.0.192.in-addr.arpa." {
		t.Errorf("reverse NODATA SOA owner = %s, want the reverse apex", m2.Ns[0].Header().Name)
	}
	// PTR outside any managed reverse space is forwarded.
	out, _ := ask(t, snap, view, "1.1.1.1.in-addr.arpa.", dns.TypePTR)
	if !out.Forward {
		t.Errorf("unmanaged PTR should forward")
	}
}

func TestLocal(t *testing.T) {
	snap, view := buildSnap()
	_, m := ask(t, snap, view, "edge.local.", dns.TypeA)
	if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != "192.0.2.50" {
		t.Fatalf(".local A = %v, want [192.0.2.50]", got)
	}
	_, m2 := ask(t, snap, view, "ghost.local.", dns.TypeA)
	if m2.Rcode != dns.RcodeNameError {
		t.Errorf("unknown .local: rcode=%d, want NXDOMAIN", m2.Rcode)
	}
}

func TestStubPrecedesZone(t *testing.T) {
	snap, view := buildSnap()
	out, _ := ask(t, snap, view, "host.sub.example.com.", dns.TypeA)
	if len(out.Stub) != 1 || out.Stub[0] != "192.0.2.53:53" {
		t.Fatalf("stub = %v, want [192.0.2.53:53] (must precede the parent zone)", out.Stub)
	}
}

// TestVHostDisabledServesAuthoritative pins the fix for the apex-NODATA bug: when no
// redirect target is configured (no proxy_v4/proxy_v6), the apex and www must serve
// their real authoritative records instead of being NODATA'd by a dead redirect.
func TestVHostDisabledServesAuthoritative(t *testing.T) {
	zone := &model.Zone{
		Apex: "example.com.",
		SOA:  soa("example.com."),
		Records: map[string]map[uint16][]model.RR{
			"":    {dns.TypeA: {a("203.0.113.1")}},
			"www": {dns.TypeA: {a("203.0.113.2")}},
		},
		ENT:        map[string]bool{},
		Wildcards:  map[uint16][]model.RR{},
		TunnelAddr: map[string]map[uint16][]model.RR{},
	}
	snap := &model.Snapshot{
		Zones:    map[string]*model.Zone{"example.com.": zone},
		VHosts:   map[string]bool{},
		Excluded: map[string]bool{},
		// VHostV4/VHostV6 deliberately unset => vhost redirect disabled.
	}
	view := &model.MDNSView{}
	want := map[string]string{"example.com.": "203.0.113.1", "www.example.com.": "203.0.113.2"}
	for name, ip := range want {
		_, m := ask(t, snap, view, name, dns.TypeA)
		if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != ip {
			t.Errorf("%s A with no vhost target = %v, want authoritative [%s] (not NODATA)", name, got, ip)
		}
	}
}

func TestVHostRedirect(t *testing.T) {
	snap, view := buildSnap()
	for _, name := range []string{"example.com.", "www.example.com.", "shop.example.com."} {
		_, m := ask(t, snap, view, name, dns.TypeA)
		if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != "198.51.100.7" {
			t.Errorf("%s A = %v, want reverse-proxy [198.51.100.7]", name, got)
		}
	}
	// Apex HTTPS is stripped to NODATA on the redirect path.
	_, mh := ask(t, snap, view, "example.com.", dns.TypeHTTPS)
	if mh.Rcode != dns.RcodeSuccess || len(mh.Answer) != 0 || len(mh.Ns) != 1 {
		t.Errorf("apex HTTPS: want NODATA+SOA, got rcode=%d ans=%d", mh.Rcode, len(mh.Answer))
	}
	// Apex MX is REAL even on a redirected zone (mail must survive).
	_, mm := ask(t, snap, view, "example.com.", dns.TypeMX)
	if !hasType(mm, dns.TypeMX) {
		t.Errorf("apex MX must return the real RRset on a redirected zone")
	}
}

func TestExcludedApexTunnel(t *testing.T) {
	snap, view := buildSnap()
	_, m := ask(t, snap, view, "excluded.test.", dns.TypeA)
	if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != "203.0.113.50" {
		t.Fatalf("excluded apex A = %v, want flattened tunnel [203.0.113.50]", got)
	}
}

func TestAuthoritativeExactAndNodata(t *testing.T) {
	snap, view := buildSnap()
	_, m := ask(t, snap, view, "sip.example.com.", dns.TypeA)
	if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != "203.0.113.20" {
		t.Fatalf("sip A = %v, want [203.0.113.20]", got)
	}
	// sip exists but has no AAAA => NODATA, wildcard suppressed.
	_, m2 := ask(t, snap, view, "sip.example.com.", dns.TypeAAAA)
	if m2.Rcode != dns.RcodeSuccess || len(m2.Answer) != 0 || len(m2.Ns) != 1 {
		t.Fatalf("sip AAAA: want NODATA+SOA (exact owner), got rcode=%d ans=%v", m2.Rcode, m2.Answer)
	}
}

func TestENTSuppressesWildcard(t *testing.T) {
	snap, view := buildSnap()
	// _udp.sip is an ENT: wildcard must NOT synthesize; NODATA.
	_, m := ask(t, snap, view, "_udp.sip.example.com.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Fatalf("ENT _udp.sip A: want NODATA, got rcode=%d ans=%v", m.Rcode, m.Answer)
	}
}

func TestWildcardTunnelAndNX(t *testing.T) {
	snap, view := buildSnap()
	// Nonexistent label synthesizes the wildcard tunnel addresses.
	_, m := ask(t, snap, view, "randomlabel.example.com.", dns.TypeA)
	if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != "203.0.113.10" {
		t.Fatalf("wildcard A = %v, want flattened tunnel [203.0.113.10]", got)
	}
	_, m6 := ask(t, snap, view, "randomlabel.example.com.", dns.TypeAAAA)
	if got := answers(m6, dns.TypeAAAA); len(got) != 1 || got[0] != "2001:db8::10" {
		t.Fatalf("wildcard AAAA = %v, want [2001:db8::10]", got)
	}
	// excluded.test has no wildcard => a nonexistent label is NXDOMAIN.
	_, mnx := ask(t, snap, view, "nope.excluded.test.", dns.TypeA)
	if mnx.Rcode != dns.RcodeNameError {
		t.Errorf("excluded zone nonexistent: want NXDOMAIN, got rcode=%d", mnx.Rcode)
	}
}

func TestTunnelOwnerAndCNAMEStrip(t *testing.T) {
	snap, view := buildSnap()
	_, m := ask(t, snap, view, "tunnelhost.example.com.", dns.TypeA)
	if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != "203.0.113.30" {
		t.Fatalf("tunnel owner A = %v, want [203.0.113.30]", got)
	}
	// CNAME-type query at a flattened owner => NODATA (no CNAME emitted).
	_, mc := ask(t, snap, view, "tunnelhost.example.com.", dns.TypeCNAME)
	if mc.Rcode != dns.RcodeSuccess || len(mc.Answer) != 0 {
		t.Fatalf("flattened owner CNAME: want NODATA, got rcode=%d ans=%v", mc.Rcode, mc.Answer)
	}
}

func TestCNAMEChase(t *testing.T) {
	snap, view := buildSnap()
	_, m := ask(t, snap, view, "alias1.example.com.", dns.TypeA)
	// Expect the two CNAMEs in chain order plus the terminal A.
	var cnames []string
	for _, rr := range m.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			cnames = append(cnames, c.Hdr.Name+"->"+c.Target)
		}
	}
	if len(cnames) != 2 {
		t.Fatalf("want 2 CNAMEs in chain, got %v", cnames)
	}
	if !strings.HasPrefix(cnames[0], "alias1.example.com.->alias2") {
		t.Errorf("chain order wrong: %v", cnames)
	}
	if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != "203.0.113.40" {
		t.Fatalf("terminal A = %v, want [203.0.113.40]", got)
	}
}

func TestForwardFallthrough(t *testing.T) {
	snap, view := buildSnap()
	out, _ := ask(t, snap, view, "google.com.", dns.TypeA)
	if !out.Forward {
		t.Errorf("name outside all zones should forward")
	}
}

// TestForwardMinimalANY pins D3: ANY for a forwarded public name is answered
// minimally (RFC 8482 HINFO), never relayed upstream.
func TestForwardMinimalANY(t *testing.T) {
	snap, view := buildSnap()
	out, msg := ask(t, snap, view, "google.com.", dns.TypeANY)
	if out.Forward {
		t.Fatalf("ANY for a forwarded name must NOT forward (amplification)")
	}
	if msg == nil || len(msg.Answer) != 1 {
		t.Fatalf("minimal-ANY must return exactly one RR, got %v", msg)
	}
	h, ok := msg.Answer[0].(*dns.HINFO)
	if !ok || h.Cpu != "RFC8482" {
		t.Fatalf("minimal-ANY answer = %v, want HINFO RFC8482", msg.Answer[0])
	}
	if msg.Rcode != dns.RcodeSuccess {
		t.Errorf("minimal-ANY rcode = %d, want NOERROR", msg.Rcode)
	}
}

// resolver.arpa (RFC 9462) is a special-use domain: answered locally as authoritative
// NODATA and NEVER forwarded, so a DDR probe can't leak to the public root.
func TestResolverArpaSpecialUse(t *testing.T) {
	snap := &model.Snapshot{}
	view := &model.MDNSView{}
	for _, name := range []string{"_dns.resolver.arpa", "resolver.arpa", "foo.resolver.arpa"} {
		out, msg := ask(t, snap, view, name, dns.TypeSVCB)
		if out.Forward || len(out.Stub) > 0 {
			t.Errorf("%s: must be answered locally, got Forward=%v Stub=%v", name, out.Forward, out.Stub)
		}
		if msg == nil {
			t.Fatalf("%s: nil message", name)
		}
		if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
			t.Errorf("%s: want NOERROR/NODATA (empty), got rcode=%s answers=%d", name, dns.RcodeToString[msg.Rcode], len(msg.Answer))
		}
		if !msg.Authoritative {
			t.Errorf("%s: response should be authoritative", name)
		}
	}
	// A lookalike that is NOT under resolver.arpa must still forward normally.
	if out, _ := ask(t, snap, view, "resolver.arpa.example.com", dns.TypeA); !out.Forward {
		t.Errorf("resolver.arpa.example.com should forward, got %+v", out)
	}
}

// svcbParam finds the SvcParam of the given key in an SVCB RR (nil if absent).
func svcbParam(rr dns.RR, key dns.SVCBKey) dns.SVCBKeyValue {
	s, ok := rr.(*dns.SVCB)
	if !ok {
		return nil
	}
	for _, kv := range s.Value {
		if kv.Key() == key {
			return kv
		}
	}
	return nil
}

// DDR synthesis (RFC 9462): when snap.DDR is live, _dns.resolver.arpa/SVCB yields two
// ServiceMode RRs (DoT then DoH) targeting the ADN, and the ADN resolves to the LAN hints.
func TestDDRSynthesis(t *testing.T) {
	snap := &model.Snapshot{DDR: &model.DDRAdvert{
		ADN:     "dns.example.net.",
		V4Hints: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		V6Hints: []netip.Addr{netip.MustParseAddr("2001:db8::53")},
		DoT:     &model.DDREndpoint{Port: 853},
		DoH:     &model.DDREndpoint{Port: 443, Path: "/dns-query"},
	}}
	view := &model.MDNSView{}

	out, msg := ask(t, snap, view, "_dns.resolver.arpa", dns.TypeSVCB)
	if out.Forward || len(out.Stub) > 0 || msg == nil || !msg.Authoritative {
		t.Fatalf("SVCB probe: out=%+v authoritative=%v", out, msg != nil && msg.Authoritative)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("want 2 SVCB RRs, got %d", len(msg.Answer))
	}
	dot, doh := msg.Answer[0].(*dns.SVCB), msg.Answer[1].(*dns.SVCB)
	if dot.Priority != 1 || dot.Target != "dns.example.net." {
		t.Errorf("DoT RR = prio %d target %q, want 1 / dns.example.net.", dot.Priority, dot.Target)
	}
	if a := svcbParam(dot, dns.SVCB_ALPN).(*dns.SVCBAlpn); a == nil || len(a.Alpn) != 1 || a.Alpn[0] != "dot" {
		t.Errorf("DoT alpn = %+v, want [dot]", a)
	}
	if p := svcbParam(dot, dns.SVCB_PORT).(*dns.SVCBPort); p == nil || p.Port != 853 {
		t.Errorf("DoT port = %+v, want 853", p)
	}
	if svcbParam(dot, dns.SVCB_IPV4HINT) == nil || svcbParam(dot, dns.SVCB_IPV6HINT) == nil {
		t.Errorf("DoT RR missing address hints")
	}
	if svcbParam(dot, dns.SVCB_DOHPATH) != nil {
		t.Errorf("DoT RR must not carry a dohpath")
	}
	if doh.Priority != 2 {
		t.Errorf("DoH priority = %d, want 2", doh.Priority)
	}
	if a := svcbParam(doh, dns.SVCB_ALPN).(*dns.SVCBAlpn); a == nil || a.Alpn[0] != "h2" {
		t.Errorf("DoH alpn = %+v, want [h2]", a)
	}
	if dp := svcbParam(doh, dns.SVCB_DOHPATH).(*dns.SVCBDoHPath); dp == nil || dp.Template != "/dns-query{?dns}" {
		t.Errorf("DoH dohpath = %+v, want /dns-query{?dns}", dp)
	}

	// Non-SVCB names/qtypes in the space stay NODATA even when DDR is live.
	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"_dns.resolver.arpa", dns.TypeA},
		{"resolver.arpa", dns.TypeSVCB},
		{"foo.resolver.arpa", dns.TypeSVCB},
	} {
		_, m := ask(t, snap, view, tc.name, tc.qtype)
		if m == nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || !m.Authoritative {
			t.Errorf("%s/%d: want authoritative NODATA, got %+v", tc.name, tc.qtype, m)
		}
	}
	// ANY at _dns.resolver.arpa enumerates the SVCB designation (functional local ANY).
	if _, m := ask(t, snap, view, "_dns.resolver.arpa", dns.TypeANY); len(m.Answer) != 2 {
		t.Errorf("_dns.resolver.arpa ANY = %d answers, want 2 SVCB", len(m.Answer))
	}

	// The ADN resolves to the LAN hints (split-horizon), consistent with the SVCB hints.
	if _, m := ask(t, snap, view, "dns.example.net", dns.TypeA); len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "192.0.2.53" {
		t.Errorf("ADN A = %+v, want 192.0.2.53", m.Answer)
	}
	if _, m := ask(t, snap, view, "dns.example.net", dns.TypeAAAA); len(m.Answer) != 1 || m.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::53" {
		t.Errorf("ADN AAAA = %+v, want 2001:db8::53", m.Answer)
	}
	// ANY on the ADN enumerates both families.
	if _, m := ask(t, snap, view, "dns.example.net", dns.TypeANY); len(m.Answer) != 2 {
		t.Errorf("ADN ANY = %d answers, want 2 (A+AAAA)", len(m.Answer))
	}
}

// Functional ANY on the local horizon: authoritative names enumerate every RRset, while
// forwarded/public names keep the RFC 8482 minimal response (anti-amplification).
func TestFunctionalLocalANY(t *testing.T) {
	snap, view := buildSnap()
	answerTypes := func(m *dns.Msg) map[uint16]bool {
		s := map[uint16]bool{}
		for _, rr := range m.Answer {
			s[rr.Header().Rrtype] = true
		}
		return s
	}
	// CF-mirrored zone owner (not vhost-redirected): ANY enumerates every RRset — here the
	// flattened tunnel A + AAAA.
	_, m := ask(t, snap, view, "excluded.test.", dns.TypeANY)
	if !m.Authoritative {
		t.Error("zone ANY should be authoritative")
	}
	types := answerTypes(m)
	for _, want := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if !types[want] {
			t.Errorf("zone ANY missing %s (got %v)", dns.TypeToString[want], m.Answer)
		}
	}
	// Static host: ANY returns its record(s).
	if _, ms := ask(t, snap, view, "gw.example.test.", dns.TypeANY); len(ms.Answer) == 0 {
		t.Error("static ANY should return the host's records")
	}
	// mDNS *.local host: ANY returns its address records.
	if _, ml := ask(t, snap, view, "edge.local.", dns.TypeANY); len(ml.Answer) == 0 {
		t.Error("*.local ANY should return the host's records")
	}
	// Wildcard match: ANY enumerates the synthesized RRsets (the reported bug — was NODATA
	// while A/AAAA worked). Here the flattened wildcard tunnel A + AAAA.
	_, mw := ask(t, snap, view, "random.example.com.", dns.TypeANY)
	if wt := answerTypes(mw); !wt[dns.TypeA] || !wt[dns.TypeAAAA] {
		t.Errorf("wildcard ANY missing A/AAAA (got %v)", mw.Answer)
	}
	// Vhost-redirected label: ANY returns the reverse-proxy address.
	if _, mv := ask(t, snap, view, "shop.example.com.", dns.TypeANY); len(mv.Answer) == 0 {
		t.Error("vhost ANY should return the redirect address")
	}
	// Redirected apex: ANY returns the redirect address plus the real MX (zone metadata).
	_, ma := ask(t, snap, view, "example.com.", dns.TypeANY)
	if at := answerTypes(ma); !at[dns.TypeA] || !at[dns.TypeMX] {
		t.Errorf("apex vhost ANY should include redirect A + real MX (got %v)", ma.Answer)
	}
	// Forwarded/public name: ANY stays minimal (a single HINFO RFC8482), never enumerated.
	_, mf := ask(t, snap, view, "notlocal.example.org.", dns.TypeANY)
	if len(mf.Answer) != 1 {
		t.Fatalf("forwarded ANY = %d answers, want 1 (minimal)", len(mf.Answer))
	}
	if h, ok := mf.Answer[0].(*dns.HINFO); !ok || h.Cpu != "RFC8482" {
		t.Errorf("forwarded ANY should be minimal HINFO, got %v", mf.Answer[0])
	}
}

// A vhost/www label serves the reverse-proxy address for A/AAAA but INHERITS the zone's
// non-address RRsets (MX/TXT/CAA…) from the wildcard — never the wildcard's address.
func TestVHostInheritsWildcard(t *testing.T) {
	zone := &model.Zone{
		Apex: "z.test.", SOA: soa("z.test."),
		Records: map[string]map[uint16][]model.RR{},
		ENT:     map[string]bool{},
		Wildcards: map[uint16][]model.RR{
			dns.TypeMX: {{Name: "*.z.test.", Type: dns.TypeMX, Class: dns.ClassINET, TTL: 300, Priority: 10, Target: "mail.z.test."}},
			dns.TypeA:  {a("203.0.113.9")}, // wildcard address — must NOT leak to a vhost name
		},
		TunnelAddr: map[string]map[uint16][]model.RR{},
	}
	snap := &model.Snapshot{
		Zones:   map[string]*model.Zone{"z.test.": zone},
		VHosts:  map[string]bool{"app": true},
		VHostV4: netip.MustParseAddr("10.0.0.7"),
	}
	view := &model.MDNSView{}

	_, ma := ask(t, snap, view, "app.z.test.", dns.TypeA)
	if len(ma.Answer) != 1 || ma.Answer[0].(*dns.A).A.String() != "10.0.0.7" {
		t.Errorf("vhost A = %+v, want the proxy 10.0.0.7 (not the wildcard 203.0.113.9)", ma.Answer)
	}
	if _, mmx := ask(t, snap, view, "app.z.test.", dns.TypeMX); len(mmx.Answer) != 1 {
		t.Errorf("vhost MX should inherit the wildcard MX, got %+v", mmx.Answer)
	}
	_, many := ask(t, snap, view, "app.z.test.", dns.TypeANY)
	types := map[uint16]bool{}
	for _, rr := range many.Answer {
		types[rr.Header().Rrtype] = true
	}
	if !types[dns.TypeA] || !types[dns.TypeMX] {
		t.Errorf("vhost ANY should be proxy A + wildcard MX, got %+v", many.Answer)
	}
}

// Split-horizon mDNS overlay: a non-vhost, non-CF-owner subdomain that is an mDNS host
// serves its LAN address(es), inherits MX/etc from the wildcard, NODATAs a missing address
// family (never leaks the wildcard's public address), and yields to an explicit CF owner.
func TestMDNSZoneOverlay(t *testing.T) {
	zone := &model.Zone{
		Apex: "z.test.", SOA: soa("z.test."),
		Records: map[string]map[uint16][]model.RR{},
		ENT:     map[string]bool{},
		Wildcards: map[uint16][]model.RR{
			dns.TypeMX:   {{Type: dns.TypeMX, Class: dns.ClassINET, TTL: 300, Priority: 10, Target: "mail.z.test."}},
			dns.TypeA:    {a("203.0.113.9")}, // wildcard public address — must NOT win over mDNS
			dns.TypeAAAA: {aaaa("2001:db8::9")},
		},
		TunnelAddr: map[string]map[uint16][]model.RR{},
	}
	snap := &model.Snapshot{Zones: map[string]*model.Zone{"z.test.": zone}, ReverseZ: rz10()} // no vhost redirect
	view := &model.MDNSView{Forward: map[string][]model.RR{"host": {a("10.0.0.5")}}}

	if _, m := ask(t, snap, view, "host.z.test.", dns.TypeA); len(answers(m, dns.TypeA)) != 1 || answers(m, dns.TypeA)[0] != "10.0.0.5" {
		t.Errorf("mDNS-zone A = %v, want mDNS [10.0.0.5] (not wildcard 203.0.113.9)", answers(m, dns.TypeA))
	}
	if _, m := ask(t, snap, view, "host.z.test.", dns.TypeAAAA); len(m.Answer) != 0 {
		t.Errorf("mDNS-zone AAAA should be NODATA (host has no v6, never leak wildcard AAAA), got %+v", m.Answer)
	}
	if _, m := ask(t, snap, view, "host.z.test.", dns.TypeMX); len(m.Answer) != 1 {
		t.Errorf("mDNS-zone MX should inherit the wildcard, got %+v", m.Answer)
	}
	_, many := ask(t, snap, view, "host.z.test.", dns.TypeANY)
	types := map[uint16]bool{}
	for _, rr := range many.Answer {
		types[rr.Header().Rrtype] = true
	}
	if !types[dns.TypeA] || !types[dns.TypeMX] || types[dns.TypeAAAA] {
		t.Errorf("mDNS-zone ANY = %+v, want A+MX (no wildcard AAAA)", many.Answer)
	}
	// An explicit CF owner wins over the mDNS overlay.
	zone.Records["host"] = map[uint16][]model.RR{dns.TypeA: {a("203.0.113.77")}}
	if _, m := ask(t, snap, view, "host.z.test.", dns.TypeA); len(answers(m, dns.TypeA)) != 1 || answers(m, dns.TypeA)[0] != "203.0.113.77" {
		t.Errorf("explicit CF owner should win over mDNS, got %v", answers(m, dns.TypeA))
	}
}

// The mDNS overlay yields to MANAGED names: a DDNS-eligible owner is not shadowed by a raw
// mDNS announcement (it falls through to the wildcard), while a non-eligible one overlays.
func TestMDNSOverlayEligibilityGuard(t *testing.T) {
	zone := &model.Zone{
		Apex: "z.test.", SOA: soa("z.test."),
		Records: map[string]map[uint16][]model.RR{}, ENT: map[string]bool{},
		Wildcards:  map[uint16][]model.RR{dns.TypeA: {a("203.0.113.9")}},
		TunnelAddr: map[string]map[uint16][]model.RR{},
	}
	snap := &model.Snapshot{
		Zones:        map[string]*model.Zone{"z.test.": zone},
		ReverseZ:     rz10(),
		DDNSEligible: map[string]bool{"host.z.test.": true}, // managed name
	}
	view := &model.MDNSView{Forward: map[string][]model.RR{
		"host": {a("10.0.0.5")}, // eligible -> must NOT shadow
		"free": {a("10.0.0.6")}, // not eligible -> overlays
	}}
	if _, m := ask(t, snap, view, "host.z.test.", dns.TypeA); len(answers(m, dns.TypeA)) != 1 || answers(m, dns.TypeA)[0] != "203.0.113.9" {
		t.Errorf("eligible name must fall to the wildcard, not mDNS; A = %v, want 203.0.113.9", answers(m, dns.TypeA))
	}
	if _, m := ask(t, snap, view, "free.z.test.", dns.TypeA); len(answers(m, dns.TypeA)) != 1 || answers(m, dns.TypeA)[0] != "10.0.0.6" {
		t.Errorf("non-eligible mDNS host should overlay; A = %v, want 10.0.0.6", answers(m, dns.TypeA))
	}
}

// An overridden name (vhost/mDNS) never inherits the wildcard's SVCB — it would point the
// client back at the public endpoint.
func TestOverrideStripsSVCB(t *testing.T) {
	zone := &model.Zone{
		Apex: "z.test.", SOA: soa("z.test."),
		Records: map[string]map[uint16][]model.RR{}, ENT: map[string]bool{},
		Wildcards: map[uint16][]model.RR{
			dns.TypeSVCB: {{Type: dns.TypeSVCB, Class: dns.ClassINET, TTL: 300, Content: `1 . alpn="h2"`}},
			dns.TypeMX:   {{Type: dns.TypeMX, Class: dns.ClassINET, TTL: 300, Priority: 10, Target: "mail.z.test."}},
		},
		TunnelAddr: map[string]map[uint16][]model.RR{},
	}
	// Sanity: a plain wildcard name DOES serve the SVCB (so the strip assertions aren't vacuous).
	plain := &model.Snapshot{Zones: map[string]*model.Zone{"z.test.": zone}}
	if _, m := ask(t, plain, &model.MDNSView{}, "plain.z.test.", dns.TypeSVCB); len(m.Answer) != 1 {
		t.Fatalf("wildcard SVCB should serve for a plain name, got %+v (parse issue?)", m.Answer)
	}
	// vhost: SVCB stripped, ANY excludes it but keeps MX.
	snapV := &model.Snapshot{Zones: map[string]*model.Zone{"z.test.": zone}, VHosts: map[string]bool{"app": true}, VHostV4: netip.MustParseAddr("10.0.0.7")}
	if _, m := ask(t, snapV, &model.MDNSView{}, "app.z.test.", dns.TypeSVCB); len(m.Answer) != 0 {
		t.Errorf("vhost SVCB should be NODATA, got %+v", m.Answer)
	}
	if _, m := ask(t, snapV, &model.MDNSView{}, "app.z.test.", dns.TypeANY); hasType(m, dns.TypeSVCB) || !hasType(m, dns.TypeMX) {
		t.Errorf("vhost ANY should have MX but not SVCB, got %+v", m.Answer)
	}
	// mDNS: same.
	snapM := &model.Snapshot{Zones: map[string]*model.Zone{"z.test.": zone}, ReverseZ: rz10()}
	viewM := &model.MDNSView{Forward: map[string][]model.RR{"host": {a("10.0.0.5")}}}
	if _, m := ask(t, snapM, viewM, "host.z.test.", dns.TypeSVCB); len(m.Answer) != 0 {
		t.Errorf("mDNS SVCB should be NODATA, got %+v", m.Answer)
	}
	if _, m := ask(t, snapM, viewM, "host.z.test.", dns.TypeANY); hasType(m, dns.TypeSVCB) || !hasType(m, dns.TypeMX) {
		t.Errorf("mDNS ANY should have MX but not SVCB, got %+v", m.Answer)
	}
}

// The overlay serves only site-local addresses: RFC1918 v4, ULA, and routed IPv6 GUA are
// kept across ALL internal subnets (not just those with a reverse zone); public IPv4 and
// CGNAT/Tailscale (100.64/10) are dropped.
func TestOverlayLocalScopeFilter(t *testing.T) {
	zone := &model.Zone{
		Apex: "z.test.", SOA: soa("z.test."),
		Records: map[string]map[uint16][]model.RR{}, ENT: map[string]bool{},
		Wildcards:  map[uint16][]model.RR{dns.TypeA: {a("203.0.113.9")}},
		TunnelAddr: map[string]map[uint16][]model.RR{},
	}
	snap := &model.Snapshot{Zones: map[string]*model.Zone{"z.test.": zone}} // no reverse zones at all
	view := &model.MDNSView{Forward: map[string][]model.RR{"cam": {
		a("172.20.0.90"),            // internal subnet (RFC1918) w/o a reverse zone -> KEEP
		a("100.64.0.21"),            // CGNAT / Tailscale (100.64/10) -> DROP
		a("198.51.100.78"),          // public IPv4 -> DROP
		aaaa("2001:db8::114"),       // routed GUA -> KEEP
		aaaa("fd12:3456:789a::114"), // ULA -> KEEP
	}}}
	_, m := ask(t, snap, view, "cam.z.test.", dns.TypeA)
	got := answers(m, dns.TypeA)
	if len(got) != 1 || got[0] != "172.20.0.90" {
		t.Errorf("overlay A = %v, want only the internal-subnet [172.20.0.90] (public/CGNAT dropped)", got)
	}
	_, m6 := ask(t, snap, view, "cam.z.test.", dns.TypeAAAA)
	if got := answers(m6, dns.TypeAAAA); len(got) != 2 {
		t.Errorf("overlay AAAA = %v, want GUA + ULA (both site-local)", got)
	}
}
