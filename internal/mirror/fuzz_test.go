package mirror

import (
	"testing"

	"github.com/gutschke/splitdns/internal/cfapi"
)

// FuzzToModelRR fuzzes the Cloudflare-Record → model.RR conversion, which parses
// the priority/weight/port/content fields (CoercePriority, ParseSRVContent) and the
// type string. Hostile CF data must never panic; any RR it accepts must render via
// ToMiekg without panicking either.
func FuzzToModelRR(f *testing.F) {
	f.Add("A", "x.example.com", "192.0.2.1", 0.0)
	f.Add("MX", "example.com", "mail.example.com", 10.0)
	f.Add("SRV", "_sip._tcp.example.com", "5 8080 sip.example.com", 1.0)
	f.Add("TXT", "example.com", "v=spf1 -all", 0.0)
	f.Add("CNAME", "www.example.com", "example.com", 0.0)
	f.Add("", "", "", 0.0)
	f.Add("AAAA", "x", "not-an-ip", -1.0)

	f.Fuzz(func(t *testing.T, typ, name, content string, prio float64) {
		rec := cfapi.Record{Type: typ, Name: name, Content: content, Priority: prio, TTL: 300}
		rr, ok := toModelRR(rec, "zone-1") // must not panic
		if !ok {
			return
		}
		_, _ = rr.ToMiekg() // accepted records must also render without panic
	})
}
