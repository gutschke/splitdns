package mdns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	mcast4 = "224.0.0.251"
	mcast6 = "ff02::fb"
)

// Listener receives mDNS packets and feeds them to a Source. It binds the wildcard
// address on the mDNS port (so it also receives the UNICAST announcements
// splitdns-notify sends across subnets where multicast does not propagate) and
// joins the multicast groups on every multicast-capable interface. Both families
// are best-effort: a family that fails to initialize is skipped, not fatal.
type Listener struct {
	src        *Source
	log        func(string)
	trusted    func(netip.Addr) bool
	verify     *SigVerifier
	requireSig bool
	conns      []*net.UDPConn
}

// Listen starts the receiver on the given port (5353 for real mDNS; a test may pass
// 0 for an ephemeral port). At least one family must come up or it returns an error.
//
// An announcement may TRIGGER DDNS write-back (D7) by either of two network paths: a
// valid TSIG signature (verify, source-IP independent — cannot be spoofed), or, unless
// requireSig is set, an unsigned packet whose SOURCE address satisfies trusted. nil
// verify means no keys are configured; nil trusted means no UDP source is trusted. With
// requireSig true, only signed (or the local socket) announcements may trigger.
func Listen(src *Source, port int, trusted func(netip.Addr) bool, verify *SigVerifier, requireSig bool, log func(string)) (*Listener, error) {
	if log == nil {
		log = func(string) {}
	}
	if trusted == nil {
		trusted = func(netip.Addr) bool { return false }
	}
	l := &Listener{src: src, log: log, trusted: trusted, verify: verify, requireSig: requireSig}
	lc := net.ListenConfig{Control: reuseControl}

	if uc := bind(lc, "udp4", "0.0.0.0", port, log); uc != nil {
		joinV4(uc, log)
		l.conns = append(l.conns, uc)
		go l.readLoop(uc)
	}
	if uc := bind(lc, "udp6", "::", port, log); uc != nil {
		joinV6(uc, log)
		l.conns = append(l.conns, uc)
		go l.readLoop(uc)
	}
	if len(l.conns) == 0 {
		return nil, fmt.Errorf("mdns: no usable UDP listener")
	}
	return l, nil
}

func bind(lc net.ListenConfig, network, host string, port int, log func(string)) *net.UDPConn {
	// Socket bind/resolve is instantaneous; no request deadline applies here.
	pc, err := lc.ListenPacket(context.Background(), network, net.JoinHostPort(host, strconv.Itoa(port))) //nolint:forbidigo // one-shot bind, not a worker call
	if err != nil {
		log(fmt.Sprintf("mdns: bind %s: %v", network, err))
		return nil
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil
	}
	return uc
}

func joinV4(uc *net.UDPConn, log func(string)) {
	p := ipv4.NewPacketConn(uc)
	group := &net.UDPAddr{IP: net.ParseIP(mcast4)}
	joined := 0
	for _, ifi := range multicastIfaces() {
		ifi := ifi
		if err := p.JoinGroup(&ifi, group); err == nil {
			joined++
		}
	}
	if joined == 0 {
		log("mdns: joined no IPv4 multicast interfaces (unicast still active)")
	}
}

func joinV6(uc *net.UDPConn, log func(string)) {
	p := ipv6.NewPacketConn(uc)
	group := &net.UDPAddr{IP: net.ParseIP(mcast6)}
	joined := 0
	for _, ifi := range multicastIfaces() {
		ifi := ifi
		if err := p.JoinGroup(&ifi, group); err == nil {
			joined++
		}
	}
	if joined == 0 {
		log("mdns: joined no IPv6 multicast interfaces (unicast still active)")
	}
}

func multicastIfaces() []net.Interface {
	ifaces, _ := net.Interfaces()
	var out []net.Interface
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagMulticast != 0 {
			out = append(out, ifi)
		}
	}
	return out
}

func (l *Listener) readLoop(uc *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, src, err := uc.ReadFromUDP(buf)
		if err != nil {
			return // connection closed
		}
		// Decide whether this packet may trigger DDNS write-back (D7). A valid TSIG
		// signature is authoritative regardless of source IP (cannot be spoofed); the
		// source-IP allowlist is a weaker fallback, disabled when requireSig is set.
		// Everything else still updates the *.local view but is inert for write-back.
		trusted := l.verify.Verify(buf[:n])
		if !trusted && !l.requireSig && src != nil {
			if a, ok := netip.AddrFromSlice(src.IP); ok {
				trusted = l.trusted(a.Unmap())
			}
		}
		l.src.HandlePacket(buf[:n], trusted)
	}
}

// Port returns the bound IPv4 port (or the first conn's port), useful for tests
// that bind an ephemeral port. Returns 0 if no listener is active.
func (l *Listener) Port() int {
	if len(l.conns) == 0 {
		return 0
	}
	if ua, ok := l.conns[0].LocalAddr().(*net.UDPAddr); ok {
		return ua.Port
	}
	return 0
}

// Close stops all receivers.
func (l *Listener) Close() error {
	for _, c := range l.conns {
		c.Close()
	}
	return nil
}

// reuseControl sets SO_REUSEADDR and SO_REUSEPORT so the daemon can share the mDNS
// port with an existing responder (e.g. avahi) rather than failing to bind.
func reuseControl(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
			serr = e
			return
		}
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return serr
}
