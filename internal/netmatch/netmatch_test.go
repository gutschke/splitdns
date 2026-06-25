package netmatch

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAccessAllowDeny(t *testing.T) {
	allow, err := ParseSet(DefaultPrivateClients)
	if err != nil {
		t.Fatalf("ParseSet: %v", err)
	}
	refuse, _ := ParseSet([]string{"10.0.66.0/24"})
	acc := Access{Allow: allow, Refuse: refuse}

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},          // RFC1918 (10/8)
		{"192.168.1.1", true},       // RFC1918 (192.168/16) — in the default allow
		{"172.20.0.1", true},        // RFC1918 (172.16/12)
		{"fd2c:1a2b:3c4d::1", true}, // ULA
		{"127.0.0.1", true},         // loopback
		{"::1", true},               // loopback
		{"10.0.66.7", false},        // refused (deny beats allow)
		{"8.8.8.8", false},          // public v4 -> not allowed
		{"2001:db8::1", false},      // GUA -> not allowed
		{"::ffff:10.0.0.5", true},   // v4-mapped matches the v4 rule
		{"::ffff:8.8.8.8", false},   // v4-mapped public -> not allowed
	}
	for _, c := range cases {
		got := acc.Allowed(netip.MustParseAddr(c.ip))
		if got != c.want {
			t.Errorf("Allowed(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// IPv6 link-local addresses are unbindable without their interface zone
// (a bare bind fails with EINVAL). private-auto must attach it.
func TestSelectListenAddrsZonesLinkLocalV6(t *testing.T) {
	addrs, err := SelectListenAddrs("private-auto", nil, 53)
	if err != nil {
		t.Fatalf("SelectListenAddrs: %v", err)
	}
	for _, s := range addrs {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			t.Fatalf("ParseAddrPort(%q): %v", s, err)
		}
		a := ap.Addr()
		if a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "" {
			t.Errorf("link-local %s selected without an interface zone; bind would EINVAL", s)
		}
	}
}

func TestListenNetwork(t *testing.T) {
	cases := []struct {
		base, addr, want string
	}{
		{"tcp", "0.0.0.0:8080", "tcp4"},      // IPv4 wildcard -> v4 ONLY (the whole point)
		{"tcp", "127.0.0.1:53", "tcp4"},      // IPv4 literal
		{"udp", "10.0.0.1:53", "udp4"},       // IPv4 literal, udp base
		{"tcp", "[::]:8080", "tcp6"},         // IPv6 wildcard -> v6 only
		{"udp", "[::1]:53", "udp6"},          // IPv6 literal
		{"udp", "[fe80::1%eth0]:53", "udp6"}, // zoned link-local
		{"tcp", ":8080", "tcp"},              // empty host -> dual-stack on purpose
		{"tcp", "localhost:8080", "tcp"},     // hostname -> resolver decides
		{"tcp", "garbage", "tcp"},            // unparseable -> base
	}
	for _, c := range cases {
		if got := ListenNetwork(c.base, c.addr); got != c.want {
			t.Errorf("ListenNetwork(%q,%q) = %q, want %q", c.base, c.addr, got, c.want)
		}
	}
}

// The behavioral guarantee: Listen via ListenNetwork on an IPv4 wildcard must NOT
// accept IPv6, while an empty host stays dual-stack. Plain net.Listen("tcp",
// "0.0.0.0:p") fails this — Go binds a dual-stack [::] socket.
func TestListenNetworkIPv4WildcardRejectsV6(t *testing.T) {
	v6Reachable := func() bool {
		l, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			return false
		}
		l.Close()
		return true
	}()

	dialable := func(network, listenAddr string) (port string, v4ok, v6ok bool) {
		ln, err := net.Listen(network, listenAddr)
		if err != nil {
			t.Fatalf("Listen(%q,%q): %v", network, listenAddr, err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, e := ln.Accept()
				if e != nil {
					return
				}
				c.Close()
			}
		}()
		_, port, _ = net.SplitHostPort(ln.Addr().String())
		time.Sleep(10 * time.Millisecond)
		try := func(addr string) bool {
			c, e := net.DialTimeout("tcp", addr, 300*time.Millisecond)
			if e != nil {
				return false
			}
			c.Close()
			return true
		}
		return port, try("127.0.0.1:" + port), try("[::1]:" + port)
	}

	// IPv4 wildcard via the helper: reachable over v4, NOT over v6.
	addr4 := "0.0.0.0:0"
	_, v4ok, v6ok := dialable(ListenNetwork("tcp", addr4), addr4)
	if !v4ok {
		t.Errorf("0.0.0.0 via %s: not reachable over IPv4", ListenNetwork("tcp", addr4))
	}
	if v6Reachable && v6ok {
		t.Errorf("0.0.0.0 via %s: reachable over IPv6 (leak); want IPv4-only", ListenNetwork("tcp", addr4))
	}

	// Empty host stays dual-stack: reachable over both families.
	if v6Reachable {
		addrAny := ":0"
		_, v4ok, v6ok := dialable(ListenNetwork("tcp", addrAny), addrAny)
		if !v4ok || !v6ok {
			t.Errorf(":0 via %s: v4=%v v6=%v, want both", ListenNetwork("tcp", addrAny), v4ok, v6ok)
		}
	}
}

func TestIsLocalScope(t *testing.T) {
	local := []string{"10.0.0.1", "192.168.0.1", "172.16.0.1", "127.0.0.1", "fd00::1", "::1", "fe80::1", "169.254.1.1"}
	global := []string{"8.8.8.8", "1.1.1.1", "2001:db8::1", "2606:4700:4700::1111"}
	for _, s := range local {
		if !IsLocalScope(netip.MustParseAddr(s)) {
			t.Errorf("IsLocalScope(%s) = false, want true", s)
		}
	}
	for _, s := range global {
		if IsLocalScope(netip.MustParseAddr(s)) {
			t.Errorf("IsLocalScope(%s) = true, want false (would bind a global address)", s)
		}
	}
}
