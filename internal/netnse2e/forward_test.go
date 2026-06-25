package netnse2e

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/mockedge"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
	"github.com/gutschke/splitdns/internal/netnstest"
	"github.com/gutschke/splitdns/internal/server"
)

// TestForwardThroughRealServer runs the real server + forwarder inside the namespace
// and forwards a query to an in-namespace mock upstream (the shared fabric). This
// proves the supported e2e path works with local mocks ONLY — there is no egress to
// fall back on.
func TestForwardThroughRealServer(t *testing.T) {
	netnstest.RequireIsolated(t)

	up, err := mockedge.NewDNS()
	if err != nil {
		t.Fatalf("mock upstream: %v", err)
	}
	defer up.Close()
	up.SetA("public.example.org", "203.0.113.5")

	fwd := forwarder.NewWithUpstreams([]forwarder.Upstream{{Addr: up.Addr(), Net: "udp"}}, nil, false, nil)
	allow, err := netmatch.ParseSet([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	snap := &model.Snapshot{} // empty zones => the name forwards
	srv := server.New(server.Config{
		Access:    netmatch.Access{Allow: allow},
		Snapshot:  func() *model.Snapshot { return snap },
		View:      func() *model.MDNSView { return &model.MDNSView{} },
		Forwarder: fwd,
	})
	if err := srv.Start([]string{"127.0.0.1:0"}, true, false); err != nil {
		t.Fatalf("server start: %v", err)
	}
	defer srv.Shutdown()
	addr := srv.BoundAddrs()[0].String()

	m := new(dns.Msg)
	m.SetQuestion("public.example.org.", dns.TypeA)
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query through real server: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("want 1 answer from the mock upstream, got %d", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "203.0.113.5" {
		t.Fatalf("unexpected answer %v", resp.Answer[0])
	}
}
