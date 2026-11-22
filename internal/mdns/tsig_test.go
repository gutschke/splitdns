package mdns

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// signed builds an authoritative mDNS announcement for host/addr and TSIG-signs it with
// (keyName, secret, algo) exactly as splitdns-notify(8) does, returning the wire bytes.
func signed(t *testing.T, keyName, secret, algo, host string, addr netip.Addr, when int64) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.Response = true
	m.Authoritative = true
	hdr := dns.RR_Header{Name: host, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}
	m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IP(addr.AsSlice())})
	m.SetTsig(keyName, algo, 300, when)
	b, _, err := dns.TsigGenerate(m, secret, "", false)
	if err != nil {
		t.Fatalf("TsigGenerate: %v", err)
	}
	return b
}

func TestSigVerifier(t *testing.T) {
	const (
		key    = "splitdns-notify."
		secret = "aGVsbG8td29ybGQtdGhpcy1pcy1hLXRlc3Qta2V5MTIzNA==" // base64, arbitrary
	)
	v := NewSigVerifier(map[string]string{key: secret})
	now := time.Now().Unix()
	host := "edge.local."
	addr := netip.MustParseAddr("203.0.113.7")

	// A correctly-signed packet verifies regardless of source IP.
	if !v.Verify(signed(t, key, secret, dns.HmacSHA256, host, addr, now)) {
		t.Error("valid TSIG should verify")
	}

	// Wrong secret => reject.
	if v.Verify(signed(t, key, "b3RoZXItc2VjcmV0LXZhbHVlLW5vdC10aGUtc2FtZS0xMjM0", dns.HmacSHA256, host, addr, now)) {
		t.Error("wrong secret must not verify")
	}

	// Unknown key name => reject (key not in the set).
	if v.Verify(signed(t, "stranger.", secret, dns.HmacSHA256, host, addr, now)) {
		t.Error("unknown key name must not verify")
	}

	// Stale signature outside the fudge window => reject (replay bound).
	if v.Verify(signed(t, key, secret, dns.HmacSHA256, host, addr, now-3600)) {
		t.Error("signature outside the fudge window must not verify")
	}

	// An unsigned announcement => not trusted (no TSIG record).
	plain := new(dns.Msg)
	plain.Response = true
	plain.Answer = append(plain.Answer, &dns.A{Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.IP(addr.AsSlice())})
	pb, _ := plain.Pack()
	if v.Verify(pb) {
		t.Error("unsigned packet must not verify")
	}

	// A tampered payload (flip a byte after signing) => reject.
	tampered := signed(t, key, secret, dns.HmacSHA256, host, addr, now)
	tampered[len(tampered)/2] ^= 0xFF
	if v.Verify(tampered) {
		t.Error("tampered packet must not verify")
	}

	// Key-name canonicalization: a config that wrote the name without the trailing dot
	// (or mixed case) still matches a signature whose owner name is the FQDN.
	v2 := NewSigVerifier(map[string]string{"Splitdns-Notify": secret})
	if !v2.Verify(signed(t, key, secret, dns.HmacSHA256, host, addr, now)) {
		t.Error("key name should match regardless of case/trailing dot")
	}

	// Nil verifier (no keys configured) trusts nothing but never panics.
	var nilv *SigVerifier
	if nilv.Verify(signed(t, key, secret, dns.HmacSHA256, host, addr, now)) {
		t.Error("nil verifier must not verify")
	}
}

// A valid signed packet is accepted once; re-sending the exact bytes (an on-path replay
// within the fudge window) is rejected.
func TestSigVerifierReplay(t *testing.T) {
	const (
		key    = "splitdns-notify."
		secret = "aGVsbG8td29ybGQtdGhpcy1pcy1hLXRlc3Qta2V5MTIzNA=="
	)
	v := NewSigVerifier(map[string]string{key: secret})
	pkt := signed(t, key, secret, dns.HmacSHA256, "edge.local.", netip.MustParseAddr("203.0.113.7"), time.Now().Unix())
	if !v.Verify(pkt) {
		t.Fatal("first receipt of a valid signature should verify")
	}
	if v.Verify(pkt) {
		t.Error("replay of the same signed packet must be rejected")
	}
}

// NewSigVerifier returns nil for an empty key set so the hot path is a cheap nil check.
func TestNewSigVerifierEmpty(t *testing.T) {
	if NewSigVerifier(nil) != nil {
		t.Error("no keys should yield a nil verifier")
	}
	if NewSigVerifier(map[string]string{}) != nil {
		t.Error("empty map should yield a nil verifier")
	}
}

// A host-scoped key authenticates only its own hosts; unscoped keys keep the old
// any-host behavior, and VerifyKey reports which key signed.
func TestSigVerifierHostScope(t *testing.T) {
	const (
		scoped   = "edge-notify."
		shared   = "splitdns-notify."
		secretA  = "aGVsbG8td29ybGQtdGhpcy1pcy1hLXRlc3Qta2V5MTIzNA=="
		secretB  = "b3RoZXItc2VjcmV0LXZhbHVlLW5vdC10aGUtc2FtZS0xMjM0"
		hostname = "edge.local."
	)
	v := NewSigVerifier(map[string]string{scoped: secretA, shared: secretB}).
		WithHostScopes(map[string][]string{"Edge-Notify": {"edge"}})
	addr := netip.MustParseAddr("203.0.113.7")
	now := time.Now().Unix()

	key, ok := v.VerifyKey(signed(t, scoped, secretA, dns.HmacSHA256, hostname, addr, now))
	if !ok || key != scoped {
		t.Fatalf("VerifyKey = (%q, %v), want (%q, true)", key, ok, scoped)
	}
	if !v.Permits(key, "edge") || !v.Permits(key, "EDGE.local.") {
		t.Error("scoped key must permit its own host (any spelling)")
	}
	if v.Permits(key, "other") {
		t.Error("scoped key must not permit a host outside its scope")
	}
	if !v.Permits(shared, "anything") {
		t.Error("an unscoped key must keep permitting unclaimed hosts")
	}
	if v.Permits(shared, "edge") || v.Permits(shared, "Edge.local.") {
		t.Error("an unscoped key must not speak for a host another key's scope claims")
	}
	var nilv *SigVerifier
	if nilv.Permits(scoped, "edge") || nilv.WithHostScopes(map[string][]string{scoped: {"edge"}}) != nil {
		t.Error("nil verifier must permit nothing and stay nil")
	}
}

func TestHostScopesSharedClaim(t *testing.T) {
	// Two scoped keys may list the same host; both keep it, unscoped keys lose it.
	v := NewSigVerifier(map[string]string{"a.": "x", "b.": "y", "wide.": "z"}).
		WithHostScopes(map[string][]string{"a": {"gw", "nas"}, "b": {"gw"}})
	for _, tc := range []struct {
		key, host string
		want      bool
	}{
		{"a.", "gw", true}, {"b.", "gw", true}, {"a.", "nas", true}, {"b.", "nas", false},
		{"wide.", "gw", false}, {"wide.", "nas", false}, {"wide.", "laptop", true},
		{"a.", "laptop", false},
	} {
		if got := v.Permits(tc.key, tc.host); got != tc.want {
			t.Errorf("Permits(%s, %s) = %v, want %v", tc.key, tc.host, got, tc.want)
		}
	}
	// Without any scope, every key speaks for every host (unchanged default).
	open := NewSigVerifier(map[string]string{"wide.": "z"})
	if !open.Permits("wide.", "gw") {
		t.Error("no scopes configured: an unscoped key must permit every host")
	}
}
