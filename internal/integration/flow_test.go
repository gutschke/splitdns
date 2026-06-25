// Package integration holds cross-component tests that wire the real mDNS source,
// the real DDNS writer, and the real Cloudflare client together against the shared
// mock Cloudflare — the same composition the daemon uses. It proves the end-to-end
// path a public-IP change actually travels:
//
//	splitdns-notify packet → mDNS listener → cache change → DDNS writer → Cloudflare
package integration

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gutschke/splitdns/internal/ddns"
	"github.com/gutschke/splitdns/internal/mdns"
	"github.com/gutschke/splitdns/internal/mockedge"

	"github.com/gutschke/splitdns/internal/cfapi"
)

func TestNotifyToCloudflareFlow(t *testing.T) {
	m := mockedge.NewCloudflare("edit-token")
	m.AddZone("zA", "example.com")
	seedID := m.Seed("zA", mockedge.CFRecord{Type: "A", Name: "edge.example.com", Content: "1.1.1.1"})

	srv := m.Start()
	defer srv.Close()
	client := cfapi.New(srv.URL, "edit-token", srv.Client())

	// Real DDNS writer, enabled, no dry-run, driven by the real CF client.
	w := ddns.New(ddns.Config{Enabled: true, DryRun: false, TokenID: "edit-token-id",
		Eligible: map[string]bool{"edge.example.com": true}}, client, client, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx, nil)

	// Real mDNS source whose change events feed the writer (the daemon's wiring).
	src := mdns.NewSource(func(host string, addrs []netip.Addr) {
		w.Submit(ddns.Change{Host: host, Addrs: addrs})
	}, nil)
	// Trust the loopback source so this announcement may trigger DDNS (D7); the test
	// plays the role of a trusted notifier on the local segment.
	lis, err := mdns.Listen(src, 0, func(a netip.Addr) bool { return a.IsLoopback() }, nil, false, func(string) {})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	// A trusted host announces its new PUBLIC address by unicast (as splitdns-notify
	// does cross-subnet). The 192.168.x in the same packet must be ignored by the filter.
	peer := mockedge.NewMDNSPeer(net.JoinHostPort("127.0.0.1", strconv.Itoa(lis.Port())))
	if err := peer.Announce("edge", 120, "9.9.9.9", "192.168.1.50"); err != nil {
		t.Fatalf("announce: %v", err)
	}

	// The seed record must converge to the announced public address, and the private
	// address must never be written.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Content(seedID) == "9.9.9.9" {
			for _, c := range m.ContentsForZone("zA") {
				if strings.HasPrefix(c, "192.168") {
					t.Fatalf("private address leaked to Cloudflare: %q", c)
				}
			}
			return // success
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("record did not converge to 9.9.9.9; got %q", m.Content(seedID))
}
