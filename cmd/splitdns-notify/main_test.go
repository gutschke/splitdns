package main

import (
	"encoding/base64"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/config"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"host1":         "host1.local.",
		"Host1":         "host1.local.",
		"router.local":  "router.local.",
		"router.local.": "router.local.",
		"  edge  ":      "edge.local.",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAddrs(t *testing.T) {
	// Space-separated within one arg and across args, mixed families.
	got, err := parseAddrs([]string{"192.0.2.10 192.0.2.11", "2001:db8::1"})
	if err != nil {
		t.Fatalf("parseAddrs: %v", err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("192.0.2.11"),
		netip.MustParseAddr("2001:db8::1"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d addrs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("addr[%d] = %v, want %v", i, got[i], want[i])
		}
	}

	if _, err := parseAddrs([]string{"not-an-ip"}); err == nil {
		t.Errorf("expected error for invalid address")
	}
	if _, err := parseAddrs(nil); err == nil {
		t.Errorf("expected error for no addresses")
	}
}

func TestBuildAnnouncement(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::1"),
	}
	m, err := buildAnnouncement("router.local.", addrs, 120, false)
	if err != nil {
		t.Fatalf("buildAnnouncement: %v", err)
	}
	if !m.Response || !m.Authoritative {
		t.Errorf("want authoritative response (QR=1 AA=1), got Response=%v AA=%v", m.Response, m.Authoritative)
	}
	if len(m.Answer) != 2 {
		t.Fatalf("want 2 answers, got %d", len(m.Answer))
	}
	if _, ok := m.Answer[0].(*dns.A); !ok {
		t.Errorf("answer[0] is %T, want *dns.A", m.Answer[0])
	}
	if _, ok := m.Answer[1].(*dns.AAAA); !ok {
		t.Errorf("answer[1] is %T, want *dns.AAAA", m.Answer[1])
	}
	if c := m.Answer[0].Header().Class; c != dns.ClassINET {
		t.Errorf("default class = %#x, want plain IN %#x", c, dns.ClassINET)
	}

	// cache-flush sets the high bit of the class.
	mf, _ := buildAnnouncement("router.local.", addrs[:1], 120, true)
	if c := mf.Answer[0].Header().Class; c&0x8000 == 0 {
		t.Errorf("cache-flush class = %#x, want high bit set", c)
	}
}

// TestSendRoundTrip packs an announcement, sends it over real UDP to a local
// listener, and verifies the exact bytes parse back into the same records — i.e.
// what an mDNS receiver would decode.
func TestSendRoundTrip(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	m, err := buildAnnouncement("router.local.", addrs, 120, false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if err := sendTo(packed, pc.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("sendTo: %v", err)
	}

	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var rec dns.Msg
	if err := rec.Unpack(buf[:n]); err != nil {
		t.Fatalf("unpack received bytes: %v", err)
	}
	if len(rec.Answer) != 1 {
		t.Fatalf("received %d answers, want 1", len(rec.Answer))
	}
	a, ok := rec.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("received %T, want *dns.A", rec.Answer[0])
	}
	if a.Hdr.Name != "router.local." || a.A.String() != "192.0.2.10" {
		t.Errorf("received %s -> %s, want router.local. -> 192.0.2.10", a.Hdr.Name, a.A)
	}
}

// TestBuildTargets confirms unicast host/host:port handling and that multicast
// adds at least the IPv4 group when enabled.
func TestBuildTargets(t *testing.T) {
	ts := buildTargets([]string{"192.0.2.53", "192.0.2.54:5300"}, 5353, false)
	if len(ts) != 2 {
		t.Fatalf("got %d unicast targets, want 2", len(ts))
	}
	if ts[0].addr.Port != 5353 {
		t.Errorf("bare host got port %d, want default 5353", ts[0].addr.Port)
	}
	if ts[1].addr.Port != 5300 {
		t.Errorf("host:port got port %d, want 5300", ts[1].addr.Port)
	}

	withM := buildTargets(nil, 5353, true)
	found4 := false
	for _, x := range withM {
		if x.addr.IP.Equal(net.ParseIP(mcast4)) {
			found4 = true
		}
	}
	if !found4 {
		t.Errorf("multicast enabled but IPv4 group %s not among targets", mcast4)
	}
}

func TestTSIGAlgorithm(t *testing.T) {
	cases := map[string]string{
		"":             dns.HmacSHA256, // default
		"hmac-sha256":  dns.HmacSHA256,
		"HMAC-SHA256.": dns.HmacSHA256, // case + trailing dot tolerated
		"hmac-sha512":  dns.HmacSHA512,
		"hmac-sha1":    dns.HmacSHA1,
		"md5":          "", // unsupported
	}
	for in, want := range cases {
		if got := tsigAlgorithm(in); got != want {
			t.Errorf("tsigAlgorithm(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEffectiveSocket(t *testing.T) {
	// Flag wins over config; config wins over the built-in default; empty => default.
	if got := effectiveSocket("/flag.sock", "/cfg.sock"); got != "/flag.sock" {
		t.Errorf("flag should win, got %q", got)
	}
	if got := effectiveSocket("", "/cfg.sock"); got != "/cfg.sock" {
		t.Errorf("config should be used when no flag, got %q", got)
	}
	if got := effectiveSocket("", ""); got != defaultNotifySocket {
		t.Errorf("empty/empty should be the default %q, got %q", defaultNotifySocket, got)
	}
	// The helper's default must match the resolver's [ddns].notify_socket default so a
	// stock setup needs no configuration on either side.
	if defaultNotifySocket != "/run/splitdns/notify.sock" {
		t.Errorf("default socket %q drifted from the resolver default", defaultNotifySocket)
	}
}

func TestResolveTSIG(t *testing.T) {
	dir := t.TempDir()
	secFile := filepath.Join(dir, "k.key")
	if err := os.WriteFile(secFile, []byte("ZmxhZy1zZWNyZXQ=\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	cfg := config.NotifyConfig{TSIGKeyName: "cfgkey", TSIGSecret: "Y2ZnLXNlY3JldA==", TSIGAlgorithm: "hmac-sha512"}

	// Config provides everything when no flags override.
	if name, secret, algo := resolveTSIG(cfg, "", "", os.Stderr); name != "cfgkey" || secret != "Y2ZnLXNlY3JldA==" || algo != "hmac-sha512" {
		t.Errorf("config-only resolveTSIG = %q/%q/%q", name, secret, algo)
	}
	// Flags override the key name and the secret (from file).
	name, secret, _ := resolveTSIG(cfg, "flagkey", secFile, os.Stderr)
	if name != "flagkey" || secret != "ZmxhZy1zZWNyZXQ=" {
		t.Errorf("flag-override resolveTSIG = %q/%q, want flagkey + file secret", name, secret)
	}
}

// TestGenKey checks the minted block is self-consistent: a valid 256-bit base64 secret
// appearing for BOTH ends, plus the two config stanzas the operator pastes.
func TestGenKey(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if rc := genTSIGKey("myhost", f, os.Stderr); rc != 0 {
		t.Fatalf("genTSIGKey rc = %d", rc)
	}
	f.Close()
	b, _ := os.ReadFile(outPath)
	out := string(b)
	for _, want := range []string{"[notify]", "tsig_key", "tsig_secret", "tsig_keys", "require_signature", `"myhost"`} {
		if !strings.Contains(out, want) {
			t.Errorf("genkey output missing %q\n%s", want, out)
		}
	}
	// Exactly one distinct secret, and it decodes to 32 random bytes.
	var secret string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "tsig_secret ") {
			if i := strings.Index(line, "\""); i >= 0 {
				secret = line[i+1 : strings.LastIndex(line, "\"")]
			}
		}
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil || len(raw) != 32 {
		t.Errorf("minted secret %q is not 32 base64 bytes (err=%v len=%d)", secret, err, len(raw))
	}
	if strings.Count(out, secret) < 2 {
		t.Errorf("secret should appear for both notifier and resolver")
	}
}

// TestSignVerifyRoundTrip proves a notify-signed announcement is accepted by the exact
// verification call splitdnsd uses (dns.TsigVerify), and rejected under the wrong key.
func TestSignVerifyRoundTrip(t *testing.T) {
	const secret = "cm91bmQtdHJpcC10ZXN0LXNlY3JldC0xMjM0NTY3OA=="
	m, err := buildAnnouncement("edge.local.", []netip.Addr{netip.MustParseAddr("203.0.113.9")}, 120, false)
	if err != nil {
		t.Fatal(err)
	}
	m.SetTsig(config.CanonicalTSIGName("edge"), tsigAlgorithm("hmac-sha256"), 300, time.Now().Unix())
	packed, _, err := dns.TsigGenerate(m, secret, "", false)
	if err != nil {
		t.Fatalf("TsigGenerate: %v", err)
	}
	if err := dns.TsigVerify(packed, secret, "", false); err != nil {
		t.Errorf("daemon-side verify rejected a valid signature: %v", err)
	}
	if err := dns.TsigVerify(packed, "d3Jvbmctc2VjcmV0LXZhbHVlLWhlcmUtMTIzNDU2", "", false); err == nil {
		t.Error("verify must fail under the wrong secret")
	}
}

// TestAnnouncerSend builds+delivers via the announcer to a mock UDP target and verifies
// the received announcement (the path shared by one-shot and relay modes).
func TestAnnouncerSend(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	tgt := pc.LocalAddr().(*net.UDPAddr)
	ann := &announcer{ttl: 120, targets: []target{{addr: tgt, label: tgt.String()}}}
	res, signed, err := ann.send("host.local.", []netip.Addr{netip.MustParseAddr("192.0.2.11")})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if signed || len(res) != 1 || res[0].err != nil {
		t.Fatalf("results=%+v signed=%v, want 1 clean unsigned delivery", res, signed)
	}
	assertReceivedA(t, pc, "host.local.", "192.0.2.11")
}

// TestRelayLoop drives the relay end to end: a "<host> <addr>" datagram to the relay
// socket must produce an announcement at the mock target. Also checks a malformed line is
// skipped without stopping the loop.
func TestRelayLoop(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	tgt := pc.LocalAddr().(*net.UDPAddr)
	ann := &announcer{ttl: 120, targets: []target{{addr: tgt, label: tgt.String()}}}

	sockPath := filepath.Join(t.TempDir(), "relay.sock")
	lpc, err := net.ListenPacket("unixgram", sockPath)
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	done := make(chan int, 1)
	go func() { done <- relayLoop(lpc, ann, func(string, ...any) {}) }()

	send := func(msg string) {
		c, err := net.Dial("unixgram", sockPath)
		if err != nil {
			t.Fatalf("dial relay: %v", err)
		}
		defer c.Close()
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("write relay: %v", err)
		}
	}
	send("garbage-with-no-address") // must be skipped, loop survives
	send("relayhost 192.0.2.7")     // must be announced
	assertReceivedA(t, pc, "relayhost.local.", "192.0.2.7")

	lpc.Close() // stop the loop
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relayLoop did not exit after socket close")
	}
}

func assertReceivedA(t *testing.T, pc *net.UDPConn, name, ip string) {
	t.Helper()
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no announcement received: %v", err)
	}
	var m dns.Msg
	if err := m.Unpack(buf[:n]); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(m.Answer))
	}
	a, ok := m.Answer[0].(*dns.A)
	if !ok || a.Hdr.Name != name || a.A.String() != ip {
		t.Errorf("got %v, want %s -> %s", m.Answer[0], name, ip)
	}
}

// TestRelayClient exercises the client mode (--relay) into a live relayLoop: run() must
// forward the args as a datagram that the relay announces to the mock target.
func TestRelayClient(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	tgt := pc.LocalAddr().(*net.UDPAddr)
	ann := &announcer{ttl: 120, targets: []target{{addr: tgt, label: tgt.String()}}}
	sockPath := filepath.Join(t.TempDir(), "relay.sock")
	lpc, err := net.ListenPacket("unixgram", sockPath)
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	defer lpc.Close()
	go relayLoop(lpc, ann, func(string, ...any) {})

	if rc := run([]string{"--relay", sockPath, "clienthost", "10.0.0.3"}, os.Stderr, os.Stderr); rc != 0 {
		t.Fatalf("relay client exit=%d, want 0", rc)
	}
	assertReceivedA(t, pc, "clienthost.local.", "10.0.0.3")
}
