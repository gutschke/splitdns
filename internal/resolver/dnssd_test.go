package resolver

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

func sdView() *model.MDNSView {
	return &model.MDNSView{
		Forward: map[string][]model.RR{
			"printer": {{Type: dns.TypeA, Class: dns.ClassINET, TTL: 90, Content: "10.0.0.9"}},
		},
		Services: map[string][]model.MDNSService{
			"printer": {
				{Type: "_ipp._tcp", Port: 631, Text: []string{"rp=ipp/print", "ty=Acme LaserJet"}},
				{Type: "_http._tcp", Port: 80},
			},
		},
	}
}

func sdQuery(t *testing.T, snap *model.Snapshot, view *model.MDNSView, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	out := Resolve(snap, view, req)
	if out.Msg == nil {
		t.Fatalf("%s %s: expected a direct reply", qname, dns.TypeToString[qtype])
	}
	return out.Msg
}

func TestDNSSDInstanceSRVTXT(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan", ServeDNSSD: true}
	view := sdView()

	m := sdQuery(t, snap, view, "printer._ipp._tcp.lan.", dns.TypeSRV)
	if len(m.Answer) != 1 {
		t.Fatalf("SRV answers = %d, want 1", len(m.Answer))
	}
	srv, ok := m.Answer[0].(*dns.SRV)
	if !ok || srv.Port != 631 || srv.Target != "printer.lan." || srv.Hdr.Ttl != 90 {
		t.Errorf("SRV = %v (want port 631, target printer.lan., ttl 90)", m.Answer[0])
	}

	m = sdQuery(t, snap, view, "printer._ipp._tcp.lan.", dns.TypeTXT)
	if len(m.Answer) != 1 {
		t.Fatalf("TXT answers = %d, want 1", len(m.Answer))
	}
	if txt := m.Answer[0].(*dns.TXT); len(txt.Txt) != 2 || txt.Txt[1] != "ty=Acme LaserJet" {
		t.Errorf("TXT = %v", txt.Txt)
	}

	// ANY at an instance returns SRV + TXT.
	if m = sdQuery(t, snap, view, "printer._ipp._tcp.lan.", dns.TypeANY); len(m.Answer) != 2 {
		t.Errorf("instance ANY answers = %d, want 2 (SRV+TXT)", len(m.Answer))
	}
}

func TestDNSSDEnumeration(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan", ServeDNSSD: true}
	view := sdView()

	// Service-type enumeration: PTR -> the instance.
	m := sdQuery(t, snap, view, "_ipp._tcp.lan.", dns.TypePTR)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.PTR).Ptr != "printer._ipp._tcp.lan." {
		t.Errorf("_ipp._tcp enum = %v, want PTR printer._ipp._tcp.lan.", m.Answer)
	}
	// Meta enumeration: PTR -> each service type (sorted).
	m = sdQuery(t, snap, view, "_services._dns-sd._udp.lan.", dns.TypePTR)
	got := map[string]bool{}
	for _, rr := range m.Answer {
		got[rr.(*dns.PTR).Ptr] = true
	}
	if !got["_http._tcp.lan."] || !got["_ipp._tcp.lan."] || len(m.Answer) != 2 {
		t.Errorf("meta enum = %v, want _http._tcp.lan. + _ipp._tcp.lan.", m.Answer)
	}
	// An unadvertised service type is empty NODATA (not NXDOMAIN), and NOT an on-demand miss.
	req := new(dns.Msg)
	req.SetQuestion("_bogus._tcp.lan.", dns.TypePTR)
	out := Resolve(snap, view, req)
	if out.Msg.Rcode != dns.RcodeSuccess || len(out.Msg.Answer) != 0 {
		t.Errorf("unadvertised type: rcode=%d answers=%d, want NODATA", out.Msg.Rcode, len(out.Msg.Answer))
	}
	if out.LocalMiss {
		t.Error("a DNS-SD node must never set LocalMiss (no on-demand for browsing)")
	}
}

func TestDNSSDDisabledFallsThrough(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan", ServeDNSSD: false}
	m := sdQuery(t, snap, sdView(), "printer._ipp._tcp.lan.", dns.TypeSRV)
	// With serve_dnssd off, the service node is just an unknown host: NXDOMAIN, no records.
	if m.Rcode != dns.RcodeNameError {
		t.Errorf("serve_dnssd off: rcode=%d, want NXDOMAIN", m.Rcode)
	}
}

// LocalMiss is set only for a bare-host address miss, never for a known host, a service node,
// or a non-address type.
func TestLocalMissSignal(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan", ServeDNSSD: true}
	view := sdView()

	cases := []struct {
		qname string
		qtype uint16
		want  bool
		label string
	}{
		{"unknown.lan.", dns.TypeA, true, "unknown"},
		{"unknown.lan.", dns.TypeAAAA, true, "unknown"},
		{"unknown.local.", dns.TypeANY, true, "unknown"},
		{"printer.lan.", dns.TypeA, false, ""},          // known host, not a miss
		{"unknown.lan.", dns.TypeMX, false, ""},         // non-address type
		{"_ipp._tcp.lan.", dns.TypePTR, false, ""},      // DNS-SD node, never a miss
		{"nope._ipp._tcp.lan.", dns.TypeSRV, false, ""}, // DNS-SD instance node
	}
	for _, c := range cases {
		req := new(dns.Msg)
		req.SetQuestion(c.qname, c.qtype)
		out := Resolve(snap, view, req)
		if out.LocalMiss != c.want || (c.want && out.LocalLabel != c.label) {
			t.Errorf("%s %s: LocalMiss=%v label=%q, want %v/%q",
				c.qname, dns.TypeToString[c.qtype], out.LocalMiss, out.LocalLabel, c.want, c.label)
		}
	}
}
