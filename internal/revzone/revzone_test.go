package revzone

import (
	"net/netip"
	"reflect"
	"testing"
)

// TestZoneFor pins exact octet/nibble reversal — the bug class to guard against
// (answering for the wrong space). Note 192.168.0.0/16 reverses to
// 168.192.in-addr.arpa., NOT 192.168.in-addr.arpa. Examples use RFC 5737 / RFC
// 3849 documentation ranges.
func TestZoneFor(t *testing.T) {
	cases := []struct {
		prefix string
		want   string
	}{
		{"10.0.0.0/8", "10.in-addr.arpa."},
		{"192.168.0.0/16", "168.192.in-addr.arpa."}, // octet-reversed!
		{"192.0.2.0/24", "2.0.192.in-addr.arpa."},
		{"203.0.113.0/24", "113.0.203.in-addr.arpa."},
		{"203.0.113.7/32", "7.113.0.203.in-addr.arpa."},
		{"203.0.113.0/28", ""}, // /28 not octet-aligned -> error (want "")
		// IPv6 nibble boundaries
		{"fd2c:1a2b:3c4d::/48", "d.4.c.3.b.2.a.1.c.2.d.f.ip6.arpa."},
		{"2001:db8:abcd:1200::/64", "0.0.2.1.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"2001:db8::/33", ""}, // /33 not nibble-aligned -> error
	}
	for _, c := range cases {
		p := netip.MustParsePrefix(c.prefix)
		got, err := ZoneFor(p)
		if c.want == "" {
			if err == nil {
				t.Errorf("ZoneFor(%s) = %q, want error (unaligned)", c.prefix, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ZoneFor(%s) error: %v", c.prefix, err)
			continue
		}
		if got != c.want {
			t.Errorf("ZoneFor(%s) = %q, want %q", c.prefix, got, c.want)
		}
	}
}

// TestDeriveDedupAndAlign covers dedup and the refuse-to-guess path that protects
// against over/under-representation.
func TestDeriveDedupAndAlign(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.5/24"),   // -> 2.0.192.in-addr.arpa.
		netip.MustParsePrefix("192.0.2.200/24"), // same /24 -> deduped
		netip.MustParsePrefix("203.0.113.9/24"), // -> 113.0.203.in-addr.arpa.
		netip.MustParsePrefix("fd2c:1a2b:3c4d::5/48"),
		netip.MustParsePrefix("192.0.2.0/23"), // NOT octet-aligned -> unaligned
	}
	zones, unaligned := Derive(in)
	wantZones := []string{
		"113.0.203.in-addr.arpa.",
		"2.0.192.in-addr.arpa.",
		"d.4.c.3.b.2.a.1.c.2.d.f.ip6.arpa.",
	}
	if !reflect.DeepEqual(zones, wantZones) {
		t.Fatalf("Derive zones = %v, want %v", zones, wantZones)
	}
	if len(unaligned) != 1 || unaligned[0].Bits() != 23 {
		t.Fatalf("Derive unaligned = %v, want one /23", unaligned)
	}
}

// TestNoOverRepresentation: a single managed /24 must yield exactly that /24 zone
// and never the enclosing /16 (which would claim addresses we don't manage).
func TestNoOverRepresentation(t *testing.T) {
	zones, unaligned := Derive([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	if len(unaligned) != 0 {
		t.Fatalf("unexpected unaligned: %v", unaligned)
	}
	if want := []string{"113.0.203.in-addr.arpa."}; !reflect.DeepEqual(zones, want) {
		t.Fatalf("zones = %v, want %v (must NOT claim the parent /16)", zones, want)
	}
}

// TestNoUnderRepresentation: every managed prefix that IS aligned must produce a
// zone; none may be silently dropped.
func TestNoUnderRepresentation(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("fd2c:1a2b:3c4d::/48"),
	}
	zones, unaligned := Derive(in)
	if len(unaligned) != 0 {
		t.Fatalf("unexpected unaligned: %v", unaligned)
	}
	if len(zones) != len(in) {
		t.Fatalf("got %d zones for %d aligned prefixes: %v", len(zones), len(in), zones)
	}
}
