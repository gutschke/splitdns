package mdns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestServiceType(t *testing.T) {
	cases := map[string]string{
		"Office Printer._ipp._tcp.local.": "_ipp._tcp",
		"host._ssh._tcp.local":            "_ssh._tcp",
		"_http._tcp.local.":               "_http._tcp",
		"printer.local.":                  "", // not a service instance
		"foo":                             "",
	}
	for in, want := range cases {
		if got := serviceType(in); got != want {
			t.Errorf("serviceType(%q) = %q, want %q", in, got, want)
		}
	}
}

// A packet carrying an A record and an SRV pointing at that host makes the host's service
// type visible in the published view (attached to the address entry, diagnostic only).
func TestServiceCaptureIntoView(t *testing.T) {
	src := NewSource(nil, func() time.Time { return time.Unix(1_000_000, 0) })
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "printer.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("10.0.0.5")},
		&dns.SRV{Hdr: dns.RR_Header{Name: "Office._ipp._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}, Target: "printer.local.", Port: 631},
		&dns.SRV{Hdr: dns.RR_Header{Name: "Office._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}, Target: "printer.local.", Port: 80},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	src.HandlePacket(b, false)

	svcs := src.View().Services["printer"]
	if len(svcs) != 2 || svcs[0] != "_http._tcp" || svcs[1] != "_ipp._tcp" {
		t.Errorf("services = %v, want [_http._tcp _ipp._tcp]", svcs)
	}
	// A service for an unknown host is dropped (never creates a host / affects resolution).
	if _, ok := src.View().Services["ghost"]; ok {
		t.Error("service for unknown host should be dropped")
	}
}

// A service query-response carries the SRV in the ADDITIONAL section; splitdnsd must still
// capture it (overhearing another client's _services._dns-sd._udp query).
func TestServiceCaptureFromAdditional(t *testing.T) {
	src := NewSource(nil, func() time.Time { return time.Unix(1_000_000, 0) })
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "cast.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("10.0.0.7")},
		&dns.PTR{Hdr: dns.RR_Header{Name: "_googlecast._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120}, Ptr: "Living Room._googlecast._tcp.local."},
	}
	m.Extra = []dns.RR{
		&dns.SRV{Hdr: dns.RR_Header{Name: "Living Room._googlecast._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}, Target: "cast.local.", Port: 8009},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	src.HandlePacket(b, false)
	if svcs := src.View().Services["cast"]; len(svcs) != 1 || svcs[0] != "_googlecast._tcp" {
		t.Errorf("services = %v, want [_googlecast._tcp] (SRV was in Additional)", svcs)
	}
}
