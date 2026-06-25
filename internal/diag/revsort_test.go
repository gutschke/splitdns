package diag

import (
	"sort"
	"testing"
)

// Reverse-DNS names sort by address (reversed labels, numeric), not alphabetically.
// All values use RFC 5737 (192.0.2/198.51.100/203.0.113) and RFC 3849 (2001:db8::/32).
func TestLessReverseDNS(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			"v4 across networks: 192.0.2 before 198.51.100 before 203.0.113",
			[]string{"100.51.198.in-addr.arpa.", "2.0.192.in-addr.arpa.", "113.0.203.in-addr.arpa."},
			[]string{"2.0.192.in-addr.arpa.", "100.51.198.in-addr.arpa.", "113.0.203.in-addr.arpa."},
		},
		{
			"numeric octets: 2, 9, 10 (alphabetical would put 10 before 2 and 9)",
			[]string{"10.0.203.in-addr.arpa.", "9.0.203.in-addr.arpa.", "2.0.203.in-addr.arpa."},
			[]string{"2.0.203.in-addr.arpa.", "9.0.203.in-addr.arpa.", "10.0.203.in-addr.arpa."},
		},
		{
			"v4 and v6 grouped by family (in-addr sorts before ip6)",
			[]string{"8.b.d.0.1.0.0.2.ip6.arpa.", "2.0.192.in-addr.arpa."},
			[]string{"2.0.192.in-addr.arpa.", "8.b.d.0.1.0.0.2.ip6.arpa."},
		},
		{
			"v6 nibbles ordered hex-correctly under 2001:db8::/32 (1 < 8 < d)",
			[]string{"d.8.b.d.0.1.0.0.2.ip6.arpa.", "8.8.b.d.0.1.0.0.2.ip6.arpa.", "1.8.b.d.0.1.0.0.2.ip6.arpa."},
			[]string{"1.8.b.d.0.1.0.0.2.ip6.arpa.", "8.8.b.d.0.1.0.0.2.ip6.arpa.", "d.8.b.d.0.1.0.0.2.ip6.arpa."},
		},
	}
	for _, c := range cases {
		got := append([]string(nil), c.in...)
		sort.Slice(got, func(i, j int) bool { return lessReverseDNS(got[i], got[j]) })
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("%s:\n got  %v\n want %v", c.name, got, c.want)
				break
			}
		}
	}
}
