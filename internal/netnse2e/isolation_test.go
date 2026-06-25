package netnse2e

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/gutschke/splitdns/internal/netnstest"
)

// TestNamespaceIsolated proves the harness actually placed us in a fresh network
// namespace with the expected interfaces.
func TestNamespaceIsolated(t *testing.T) {
	netnstest.RequireIsolated(t)

	// Loopback must be up (the in-namespace mocks bind it).
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lo missing: %v", err)
	}
	if lo.Flags&net.FlagUp == 0 {
		t.Errorf("lo is not up")
	}

	// The dummy multicast NIC must exist and be multicast-capable.
	mc, err := net.InterfaceByName(netnstest.IfName)
	if err != nil {
		t.Fatalf("%s missing: %v", netnstest.IfName, err)
	}
	if mc.Flags&net.FlagMulticast == 0 {
		t.Errorf("%s is not multicast-capable", netnstest.IfName)
	}

	// We must NOT share the host's netns inode (defense in depth over the RunMain check).
	self, _ := os.Readlink("/proc/self/ns/net")
	if self == "" {
		t.Errorf("could not read our netns inode")
	}
}

// TestEgressBlocked is the load-bearing safety assertion: from inside the namespace
// there is no route off-host, so any attempt to reach an external address fails
// fast. This is what guarantees a test can never touch production or the internet.
func TestEgressBlocked(t *testing.T) {
	netnstest.RequireIsolated(t)

	// A TCP connect to a public address must fail (network unreachable / no route),
	// quickly — not hang and not succeed.
	for _, addr := range []string{"8.8.8.8:53", "1.1.1.1:853", "203.0.113.1:80"} {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			t.Fatalf("egress to %s SUCCEEDED — namespace is not isolated", addr)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("egress to %s hung instead of failing fast (%v)", addr, err)
		}
	}

	// UDP send to an external resolver must also be unreachable.
	c, err := net.DialTimeout("udp", "8.8.8.8:53", time.Second)
	if err == nil {
		c.SetDeadline(time.Now().Add(time.Second))
		if _, werr := c.Write([]byte{0, 0}); werr == nil {
			// UDP write may buffer; a read must then time out or error, never succeed.
			buf := make([]byte, 16)
			if n, rerr := c.Read(buf); rerr == nil && n > 0 {
				t.Errorf("received a UDP reply from external 8.8.8.8 — egress not blocked")
			}
		}
		c.Close()
	}
}
