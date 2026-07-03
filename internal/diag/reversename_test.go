package diag

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// The mDNS reverse panel shows the served canonical name (host.<local-domain>), not the
// mDNS-native host.local.
func TestReverseHostViewsRewrite(t *testing.T) {
	m := map[string][]model.RR{
		"5.2.0.192.in-addr.arpa.": {{Type: dns.TypePTR, Class: dns.ClassINET, TTL: 120, Content: "printer.local.", Target: "printer.local."}},
	}
	got := reverseHostViews(m, "lan")
	if len(got) != 1 || len(got[0].Records) != 1 || got[0].Records[0] != "PTR printer.lan." {
		t.Errorf("rewrite = %+v, want [PTR printer.lan.]", got)
	}
	if raw := reverseHostViews(m, ""); raw[0].Records[0] != "PTR printer.local." {
		t.Errorf("empty domain = %q, want PTR printer.local.", raw[0].Records[0])
	}
}
