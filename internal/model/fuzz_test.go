package model

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// FuzzRRToMiekg fuzzes the RR presentation builder: model.RR carries
// Cloudflare-sourced strings (Name/Content/Target) plus the recombined MX/SRV
// priority fields, and ToMiekg renders "<name> <ttl> <class> <type> <rdata>" for
// dns.NewRR. It must never panic on hostile content; an unparseable record returns
// an error (callers log-and-skip).
func FuzzRRToMiekg(f *testing.F) {
	f.Add("host", "192.0.2.1", "", uint16(dns.TypeA), uint16(0))
	f.Add("host", "2001:db8::1", "", uint16(dns.TypeAAAA), uint16(0))
	f.Add("host", "", "mail.example.com", uint16(dns.TypeMX), uint16(10))
	f.Add("host", "5 8080 sip.example.com", "sip.example.com", uint16(dns.TypeSRV), uint16(1))
	f.Add("host", "v=spf1 -all", "", uint16(dns.TypeTXT), uint16(0))
	f.Add("", "", "", uint16(0), uint16(0))

	f.Fuzz(func(t *testing.T, name, content, target string, typ, prio uint16) {
		r := RR{
			Name: name, Type: typ, Class: dns.ClassINET, TTL: 300,
			Content: content, Target: target, Priority: prio,
		}
		// Neither of these may panic regardless of input.
		_ = r.RDATA()
		rr, err := r.ToMiekg()
		if err == nil && rr == nil {
			t.Errorf("ToMiekg returned nil rr with nil error for %+v", r)
		}
		// MX/SRV priority must survive into RDATA (the §2.3 recombination contract).
		if err == nil && (typ == dns.TypeMX || typ == dns.TypeSRV) {
			if !strings.HasPrefix(r.RDATA(), itoa(prio)+" ") {
				t.Errorf("%s RDATA %q dropped priority %d", dns.TypeToString[typ], r.RDATA(), prio)
			}
		}
	})
}

func itoa(u uint16) string {
	if u == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}
