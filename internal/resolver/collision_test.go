package resolver

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// ta / taaaa build a TRUSTED (notification-channel) address record; a / aaaa are self-announced.
func ta(content string) model.RR    { r := a(content); r.Trusted = true; return r }
func taaaa(content string) model.RR { r := aaaa(content); r.Trusted = true; return r }

// buildTrustSnap models the operator's world: a mirrored zone pub.test. with a PUBLIC A
// wildcard, a vhost (hestia) with a TRUSTED static allocation, a DDNS-eligible name (managed)
// with a trusted allocation, an explicit CF owner (real), and self-announced-only hosts.
func buildTrustSnap() (*model.Snapshot, *model.MDNSView) {
	zone := &model.Zone{
		Apex: "pub.test.",
		SOA:  soa("pub.test."),
		Records: map[string]map[uint16][]model.RR{
			"real": {dns.TypeA: {a("203.0.113.40")}}, // explicit CF owner (public), NOT restricted
		},
		ENT: map[string]bool{},
		Wildcards: map[uint16][]model.RR{
			dns.TypeA:  {a("203.0.113.9")}, // the public wildcard a .lan-tainted name must NEVER leak
			dns.TypeMX: {{Type: dns.TypeMX, Class: dns.ClassINET, TTL: 3600, Priority: 10, Target: "mail.pub.test."}},
		},
		TunnelAddr: map[string]map[uint16][]model.RR{},
	}
	snap := &model.Snapshot{
		Zones:        map[string]*model.Zone{"pub.test.": zone},
		LocalDomain:  "lan",
		VHosts:       map[string]bool{"hestia": true},            // hestia is a vhost => restricted
		DDNSEligible: map[string]bool{"managed.pub.test.": true}, // managed is DDNS => restricted
	}
	view := &model.MDNSView{Forward: map[string][]model.RR{
		// hestia: TRUSTED static (10.0.0.40) AND a self-announced spoof (must be ignored).
		"hestia": {ta("10.0.0.40"), a("10.0.0.66")},
		// managed: TRUSTED static only.
		"managed": {ta("10.0.0.11")},
		// asterisk: self-announced only, unrestricted.
		"asterisk": {a("10.0.0.117")},
		// real: explicit CF owner, self-announced LAN address (not restricted).
		"real": {a("10.0.0.12")},
		// pubonly: unrestricted, self-announced PUBLIC address only.
		"pubonly": {a("198.51.100.50")},
		// gua: unrestricted, self-announced IPv6 GUA (site-local per isLocalScope).
		"gua": {aaaa("2001:db8::7")},
		// spoofonly: restricted (vhost) with ONLY a self-announced address (no trusted).
		"spoofonly": {a("10.0.0.99")},
	}}
	snap.VHosts["spoofonly"] = true
	return snap, view
}

func assertNX(t *testing.T, m *dns.Msg, wantSOA bool) {
	t.Helper()
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if hasType(m, dns.TypeA) || hasType(m, dns.TypeAAAA) {
		t.Fatalf("NXDOMAIN carried address answers: %v", m.Answer)
	}
	haveSOA := len(m.Ns) > 0 && m.Ns[0].Header().Rrtype == dns.TypeSOA
	if haveSOA != wantSOA {
		t.Fatalf("NXDOMAIN SOA-in-AUTHORITY = %v, want %v (Ns=%v)", haveSOA, wantSOA, m.Ns)
	}
}

func assertA(t *testing.T, m *dns.Msg, want string) {
	t.Helper()
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	got := answers(m, dns.TypeA)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("A answers = %v, want [%s]", got, want)
	}
	for _, ip := range got {
		if ip == "203.0.113.9" {
			t.Fatal("leaked the public wildcard address for a local-tainted name")
		}
	}
}

// TestTrustHestiaVhostTrusted: hestia is a vhost (restricted) with a trusted static IP and a
// self-announced spoof. Every local spelling resolves to the TRUSTED IP — never the spoof,
// never the wildcard, never nginx (the vhost redirect is only for the bare host.example.com).
func TestTrustHestiaVhostTrusted(t *testing.T) {
	snap, view := buildTrustSnap()
	for _, qn := range []string{"hestia.lan.", "hestia.lan.pub.test.", "hestia.pub.test.lan.", "hestia.local."} {
		_, m := ask(t, snap, view, qn, dns.TypeA)
		assertA(t, m, "10.0.0.40")
	}
}

// TestTrustHestiaDown: with only the trusted static (host powered off, self-announced gone),
// the collision spelling STILL resolves — the trusted allocation persists.
func TestTrustHestiaDown(t *testing.T) {
	snap, view := buildTrustSnap()
	view.Forward["hestia"] = []model.RR{ta("10.0.0.40")} // down: trusted only
	_, m := ask(t, snap, view, "hestia.lan.pub.test.", dns.TypeA)
	assertA(t, m, "10.0.0.40")
}

// TestTrustRestrictedShadowClosed: a restricted (vhost) name with ONLY a self-announced
// address (no trusted entry) never serves it under any spelling — trusted tier only.
func TestTrustRestrictedShadowClosed(t *testing.T) {
	snap, view := buildTrustSnap()
	_, mz := ask(t, snap, view, "spoofonly.lan.pub.test.", dns.TypeA)
	assertNX(t, mz, true) // under the apex: zone SOA
	_, ml := ask(t, snap, view, "spoofonly.lan.", dns.TypeA)
	assertNX(t, ml, false) // pure .lan: no SOA
}

// TestTrustUnrestrictedAllSpellings: a non-vhost/non-DDNS host serves its self-announced LAN
// address on every spelling (the accepted mDNS collision risk).
func TestTrustUnrestrictedAllSpellings(t *testing.T) {
	snap, view := buildTrustSnap()
	for _, qn := range []string{"asterisk.lan.", "asterisk.lan.pub.test.", "asterisk.pub.test.lan."} {
		_, m := ask(t, snap, view, qn, dns.TypeA)
		assertA(t, m, "10.0.0.117")
	}
}

// TestTrustManagedDDNSTrusted: a DDNS-eligible (restricted) name serves its trusted static IP.
func TestTrustManagedDDNSTrusted(t *testing.T) {
	snap, view := buildTrustSnap()
	_, m := ask(t, snap, view, "managed.lan.pub.test.", dns.TypeA)
	assertA(t, m, "10.0.0.11")
}

// TestTrustExplicitOwnerNotRestricted: an explicit CF owner is NOT restricted (only vhost/DDNS
// are), so its collision spelling serves the self-announced LAN address, not NXDOMAIN.
func TestTrustExplicitOwnerNotRestricted(t *testing.T) {
	snap, view := buildTrustSnap()
	_, m := ask(t, snap, view, "real.lan.pub.test.", dns.TypeA)
	assertA(t, m, "10.0.0.12")
}

// TestTrustZoneSuffixLocalScopeOnly: under the managed apex a public self-announced address is
// filtered (would leak into the public namespace) => NXDOMAIN; the pure .lan plane serves it.
func TestTrustZoneSuffixLocalScopeOnly(t *testing.T) {
	snap, view := buildTrustSnap()
	_, mz := ask(t, snap, view, "pubonly.lan.pub.test.", dns.TypeA)
	assertNX(t, mz, true)
	_, ml := ask(t, snap, view, "pubonly.lan.", dns.TypeA)
	assertA(t, ml, "198.51.100.50")
}

// TestTrustGUAServed: an IPv6 GUA is site-local, so it is served for a collision AAAA.
func TestTrustGUAServed(t *testing.T) {
	snap, view := buildTrustSnap()
	_, m := ask(t, snap, view, "gua.lan.pub.test.", dns.TypeAAAA)
	if got := answers(m, dns.TypeAAAA); len(got) != 1 || got[0] != "2001:db8::7" {
		t.Fatalf("AAAA = %v, want [2001:db8::7]", got)
	}
}

// TestTrustMultiLabelNXDOMAIN: a multi-label tainted name recovers to no single host — it must
// NXDOMAIN, never fall through to the public wildcard.
func TestTrustMultiLabelNXDOMAIN(t *testing.T) {
	snap, view := buildTrustSnap()
	_, m := ask(t, snap, view, "a.b.lan.pub.test.", dns.TypeA)
	assertNX(t, m, true)
}

// TestTrustExistenceConsistency: when a host exists (trusted), a non-address qtype and a
// missing family are NODATA (NOERROR + zone SOA) — never NXDOMAIN, never the wildcard MX.
func TestTrustExistenceConsistency(t *testing.T) {
	snap, view := buildTrustSnap()
	_, mmx := ask(t, snap, view, "hestia.lan.pub.test.", dns.TypeMX)
	if mmx.Rcode != dns.RcodeSuccess || len(mmx.Answer) != 0 {
		t.Fatalf("MX: want NODATA, got rcode=%s answers=%v", dns.RcodeToString[mmx.Rcode], mmx.Answer)
	}
	if hasType(mmx, dns.TypeMX) {
		t.Fatal("leaked the public wildcard MX under a .lan collision name")
	}
	if len(mmx.Ns) == 0 || mmx.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Fatal("NODATA under the apex must carry the zone SOA")
	}
	_, m6 := ask(t, snap, view, "hestia.lan.pub.test.", dns.TypeAAAA) // hestia is v4-only
	if m6.Rcode != dns.RcodeSuccess || len(m6.Answer) != 0 {
		t.Fatalf("AAAA: want NODATA, got rcode=%s answers=%v", dns.RcodeToString[m6.Rcode], m6.Answer)
	}
}

// TestTrustAbsentHost: a host in neither tier is NXDOMAIN — zone SOA under the apex, none on
// the pure .lan plane.
func TestTrustAbsentHost(t *testing.T) {
	snap, view := buildTrustSnap()
	_, mz := ask(t, snap, view, "ghost.lan.pub.test.", dns.TypeA)
	assertNX(t, mz, true)
	_, ml := ask(t, snap, view, "ghost.lan.", dns.TypeA)
	assertNX(t, ml, false)
}

// TestTrustBoundaryNotTainted: a bare label equal to the local domain / "local" directly under
// the apex is an ordinary managed name (not a .lan-tainted artifact) and still resolves via the
// zone wildcard — only an INTERIOR .lan/.local label triggers local recovery.
func TestTrustBoundaryNotTainted(t *testing.T) {
	snap, view := buildTrustSnap()
	for _, qn := range []string{"lan.pub.test.", "local.pub.test."} {
		_, m := ask(t, snap, view, qn, dns.TypeA)
		if got := answers(m, dns.TypeA); len(got) != 1 || got[0] != "203.0.113.9" {
			t.Fatalf("%s A = %v, want the wildcard [203.0.113.9]", qn, got)
		}
	}
}
