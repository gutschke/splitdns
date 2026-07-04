package hostinfo

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseOUILine(t *testing.T) {
	for line, want := range map[string]struct {
		oui    uint32
		vendor string
	}{
		"52-54-00   (hex)\t\tAcme Devices": {0x525400, "Acme Devices"},
		"525400 Acme Devices":              {0x525400, "Acme Devices"},
	} {
		oui, vendor, ok := parseOUILine(line)
		if !ok || oui != want.oui || vendor != want.vendor {
			t.Errorf("parseOUILine(%q) = %#x,%q,%v; want %#x,%q", line, oui, vendor, ok, want.oui, want.vendor)
		}
	}
	if _, _, ok := parseOUILine("# comment"); ok {
		t.Error("comment line should not parse")
	}
	if _, _, ok := parseOUILine("00-1B   (hex)\t\tShort"); ok {
		t.Error("malformed prefix should not parse")
	}
}

func TestEUI64MAC(t *testing.T) {
	// 52:54:00:12:34:56 -> iid 50:54:00:ff:fe:12:34:56 (U/L bit flipped).
	if mac, ok := EUI64MAC(netip.MustParseAddr("2001:db8::5054:00ff:fe12:3456")); !ok || mac.String() != "52:54:00:12:34:56" {
		t.Errorf("EUI64MAC = %v,%v want 52:54:00:12:34:56", mac, ok)
	}
	if _, ok := EUI64MAC(netip.MustParseAddr("2001:db8::dead:beef:cafe:1234")); ok {
		t.Error("privacy address (no ff:fe) must not yield an EUI-64 MAC")
	}
	if _, ok := EUI64MAC(netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("IPv4 must not yield an EUI-64 MAC")
	}
}

func TestARPMAC(t *testing.T) {
	f := filepath.Join(t.TempDir(), "arp")
	os.WriteFile(f, []byte("IP address       HW type     Flags       HW address            Mask     Device\n"+
		"192.0.2.5        0x1         0x2         52:54:00:12:34:56     *        eth0\n"+
		"192.0.2.6        0x1         0x0         00:00:00:00:00:00     *        eth0\n"), 0o644)
	old := procNetARP
	procNetARP = f
	defer func() { procNetARP = old }()

	if mac, ok := ARPMAC(netip.MustParseAddr("192.0.2.5")); !ok || mac.String() != "52:54:00:12:34:56" {
		t.Errorf("ARPMAC(.5) = %v,%v", mac, ok)
	}
	if _, ok := ARPMAC(netip.MustParseAddr("192.0.2.6")); ok {
		t.Error("incomplete ARP entry (flags 0x0) must be a miss")
	}
	if _, ok := ARPMAC(netip.MustParseAddr("192.0.2.9")); ok {
		t.Error("absent ARP entry must be a miss")
	}
}

func TestLookupVendorAndProfile(t *testing.T) {
	oui := filepath.Join(t.TempDir(), "oui.txt")
	os.WriteFile(oui, []byte("52-54-00   (hex)\t\tAcme Devices\n"), 0o644)
	r := New(NewOUIDB(oui), Options{})
	info := r.Lookup("vm1", []netip.Addr{
		netip.MustParseAddr("2001:db8::5054:00ff:fe12:3456"), // EUI-64 -> Acme Devices
		netip.MustParseAddr("10.0.0.5"),                      // LAN
	})
	if len(info.Vendors) != 1 || info.Vendors[0] != "Acme Devices" {
		t.Errorf("vendors = %v, want [Acme Devices]", info.Vendors)
	}
	if info.Families != "IPv4+IPv6" {
		t.Errorf("families = %q, want IPv4+IPv6", info.Families)
	}
	has := map[string]bool{}
	for _, s := range info.Scopes {
		has[s] = true
	}
	if !has["LAN"] || !has["GUA"] {
		t.Errorf("scopes = %v, want to include LAN and GUA", info.Scopes)
	}
}

func TestPingProbeGating(t *testing.T) {
	f := filepath.Join(t.TempDir(), "arp")
	os.WriteFile(f, []byte("IP address\n"), 0o644) // empty table
	old := procNetARP
	procNetARP = f
	defer func() { procNetARP = old }()
	db := NewOUIDB(filepath.Join(t.TempDir(), "absent"))

	var pinged int
	r := New(db, Options{Ping: true, probe: func(netip.Addr) { pinged++ }})
	r.Lookup("h", []netip.Addr{netip.MustParseAddr("10.0.0.9")})
	if pinged != 1 {
		t.Errorf("Ping enabled + missing ARP: probes = %d, want 1", pinged)
	}
	r2 := New(db, Options{Ping: false, probe: func(netip.Addr) { t.Error("must not probe when Ping is off") }})
	r2.Lookup("h", []netip.Addr{netip.MustParseAddr("10.0.0.9")})
	// CGNAT scope classification.
	if s := scopeOf(netip.MustParseAddr("100.64.0.1")); s != "CGNAT" {
		t.Errorf("scopeOf(100.64.0.1) = %q, want CGNAT", s)
	}
}

// Regression: the ieee-data oui.txt lists each OUI twice — a "(hex)" line and a
// "(base 16)" line (plus indented address lines). Only the (hex) vendor must win; the
// (base 16) line must not overwrite it with "(base 16)  <vendor>" garbage.
func TestParseOUIFileIeeeData(t *testing.T) {
	f := filepath.Join(t.TempDir(), "oui.txt")
	os.WriteFile(f, []byte(
		"00-1B-63   (hex)\t\tApple, Inc.\n"+
			"001B63     (base 16)\t\tApple, Inc.\n"+
			"\t\t\t\t1 Infinite Loop\n"+
			"\t\t\t\tCupertino CA 95014\n"+
			"\t\t\t\tUS\n"), 0o644)
	db := NewOUIDB(f)
	mac, _ := EUI64MAC(netip.MustParseAddr("2001:db8::021b:63ff:fe00:0001"))
	if v := db.Vendor(mac); v != "Apple, Inc." {
		t.Errorf("vendor = %q, want %q (the (base 16) line must not corrupt it)", v, "Apple, Inc.")
	}
}
