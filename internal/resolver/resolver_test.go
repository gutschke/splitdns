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
