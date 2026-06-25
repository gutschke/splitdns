package model

import (
	"testing"

	"github.com/miekg/dns"
)

// TestSRVRecombination pins blocking issue #11 (§2.3): the CF SRV content stores
// "weight port target" with priority in a SEPARATE field; the wire RDATA must be
// the recombined "priority weight port target". Ground-truth golden from
// example.com.cf: _sip._udp => priority=1, content="1 5060 sip.example.com"
// => wire "1 1 5060 sip.example.com." (all four SRV fields).
func TestSRVRecombination(t *testing.T) {
	w, p, target, err := ParseSRVContent("1 5060 sip.example.com")
	if err != nil {
		t.Fatalf("ParseSRVContent: %v", err)
	}
	rr := RR{
		Name: "_sip._udp.example.com.", Type: dns.TypeSRV, TTL: 300,
		Priority: 1, Weight: w, Port: p, Target: target,
	}
	if got, want := rr.RDATA(), "1 1 5060 sip.example.com."; got != want {
		t.Fatalf("SRV RDATA = %q, want %q", got, want)
	}
	m, err := rr.ToMiekg()
	if err != nil {
		t.Fatalf("ToMiekg: %v", err)
	}
	srv, ok := m.(*dns.SRV)
	if !ok {
		t.Fatalf("got %T, want *dns.SRV", m)
	}
	if srv.Priority != 1 || srv.Weight != 1 || srv.Port != 5060 || srv.Target != "sip.example.com." {
		t.Fatalf("decoded SRV = %+v, want 1/1/5060/sip.example.com.", srv)
	}
}

// TestMXRecombination pins MX preference fidelity: CF content="smtp.example.com"
// with priority=10.0 => wire "10 smtp.example.com.". Includes the priority=0 edge.
func TestMXRecombination(t *testing.T) {
	cases := []struct {
		prio uint16
		want string
	}{
		{10, "10 smtp.example.com."},
		{0, "0 smtp.example.com."},
	}
	for _, c := range cases {
		rr := RR{Name: "example.com.", Type: dns.TypeMX, TTL: 300, Priority: c.prio, Target: "smtp.example.com"}
		if got := rr.RDATA(); got != c.want {
			t.Fatalf("MX RDATA = %q, want %q", got, c.want)
		}
		m, err := rr.ToMiekg()
		if err != nil {
			t.Fatalf("ToMiekg: %v", err)
		}
		mx, ok := m.(*dns.MX)
		if !ok || mx.Preference != c.prio || mx.Mx != "smtp.example.com." {
			t.Fatalf("decoded MX = %+v, want pref=%d", m, c.prio)
		}
	}
}

// TestCoercePriority pins the DEFENSIVE float->uint16 coercion (§2.3): malformed
// CF priorities are rejected (log-and-skip), never silently truncated or panicked.
func TestCoercePriority(t *testing.T) {
	good := []float64{0, 10, 65535}
	for _, f := range good {
		if v, ok := CoercePriority(f); !ok || float64(v) != f {
			t.Fatalf("CoercePriority(%v) = %d,%v; want ok", f, v, ok)
		}
	}
	bad := []float64{-1, 65536, 10.5, 1e9}
	for _, f := range bad {
		if _, ok := CoercePriority(f); ok {
			t.Fatalf("CoercePriority(%v) accepted; want rejected", f)
		}
	}
}
