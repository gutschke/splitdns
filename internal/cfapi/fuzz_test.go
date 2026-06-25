package cfapi

import (
	"encoding/json"
	"testing"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// FuzzDecodeRecords fuzzes the Cloudflare records JSON decoder plus the post-decode
// conversion to model.RR (the same steps RecordsForHost runs on the API response).
// A malformed/hostile body must yield an error or a clean slice — never a panic.
func FuzzDecodeRecords(f *testing.F) {
	f.Add([]byte(`[{"id":"r1","type":"A","name":"x.example.com","content":"192.0.2.1","ttl":300}]`))
	f.Add([]byte(`[{"type":"AAAA","content":"2001:db8::1","priority":10.0}]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, body []byte) {
		var recs []dnsRec
		if err := json.Unmarshal(body, &recs); err != nil {
			return // a decode error is the expected outcome for junk
		}
		for _, r := range recs {
			typ, ok := abType(r.Type)
			if !ok || r.Proxied {
				continue
			}
			rr := model.RR{
				Name:    ensureDot(r.Name),
				Type:    typ,
				Class:   dns.ClassINET,
				Content: r.Content,
			}
			_, _ = rr.ToMiekg() // must not panic on fuzzed content
		}
	})
}
