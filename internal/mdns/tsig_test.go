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

// NewSigVerifier returns nil for an empty key set so the hot path is a cheap nil check.
func TestNewSigVerifierEmpty(t *testing.T) {
	if NewSigVerifier(nil) != nil {
		t.Error("no keys should yield a nil verifier")
	}
	if NewSigVerifier(map[string]string{}) != nil {
		t.Error("empty map should yield a nil verifier")
	}
}
