package netnse2e

import (
	"context"
	"crypto/tls"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/encrypted"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
	"github.com/gutschke/splitdns/internal/netnstest"
	"github.com/gutschke/splitdns/internal/server"
)

// ddrSnap is a snapshot advertising a DoT-only DDR designation, used by the DoT/DoH e2e.
func ddrSnap() *model.Snapshot {
	return &model.Snapshot{DDR: &model.DDRAdvert{
		ADN:     "dns.example.net.",
		V4Hints: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		DoT:     &model.DDREndpoint{Port: 853},
	}}
}

func newHandler(allowCIDR string) *server.Server {
	allow, _ := netmatch.ParseSet([]string{allowCIDR})
	snap := ddrSnap()
	return server.New(server.Config{
		Access:   netmatch.Access{Allow: allow},
		Snapshot: func() *model.Snapshot { return snap },
		View:     func() *model.MDNSView { return &model.MDNSView{} },
	})
}

// A DoT listener answers over TLS through the shared handler (here the DDR SVCB), rejects
// a wrong-ALPN handshake, and REFUSES a client outside the access policy.
func TestDoTEndToEnd(t *testing.T) {
	netnstest.RequireIsolated(t)
	certFile, keyFile, pool := testCert(t, time.Now().Add(24*time.Hour))
	rel, err := encrypted.NewCertReloader(certFile, keyFile, nil)
	if err != nil {
		t.Fatalf("reloader: %v", err)
	}
	mgr := encrypted.NewManager(newHandler("127.0.0.0/8"), rel, nil)
	if err := mgr.StartDoT([]string{"127.0.0.1:0"}); err != nil {
		t.Fatalf("StartDoT: %v", err)
	}
	defer mgr.Shutdown(context.Background())
	addr := mgr.BoundAddrs()[0].String()

	m := new(dns.Msg)
	m.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: &tls.Config{ServerName: "dns.example.net", RootCAs: pool}}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DoT exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("want 1 SVCB (DoT only) over DoT, got %d", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.SVCB); !ok {
		t.Fatalf("want SVCB answer, got %T", resp.Answer[0])
	}

	// Wrong ALPN => handshake fails (listener advertises only "dot").
	bad := &dns.Client{Net: "tcp-tls", Timeout: 2 * time.Second, TLSConfig: &tls.Config{ServerName: "dns.example.net", RootCAs: pool, NextProtos: []string{"h2"}}}
	if _, _, err := bad.Exchange(m, addr); err == nil {
		t.Error("wrong-ALPN DoT handshake should fail")
	}
}

// A client outside the access policy gets REFUSED over DoT (the shared handler's gate
// applies because the DoT ResponseWriter carries the real *net.TCPAddr peer).
func TestDoTAccessRefused(t *testing.T) {
	netnstest.RequireIsolated(t)
	certFile, keyFile, pool := testCert(t, time.Now().Add(24*time.Hour))
	rel, err := encrypted.NewCertReloader(certFile, keyFile, nil)
	if err != nil {
		t.Fatalf("reloader: %v", err)
	}
	mgr := encrypted.NewManager(newHandler("10.0.0.0/8"), rel, nil) // excludes loopback
	if err := mgr.StartDoT([]string{"127.0.0.1:0"}); err != nil {
		t.Fatalf("StartDoT: %v", err)
	}
	defer mgr.Shutdown(context.Background())
	addr := mgr.BoundAddrs()[0].String()

	m := new(dns.Msg)
	m.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: &tls.Config{ServerName: "dns.example.net", RootCAs: pool}}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DoT exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("loopback client outside allow-list: rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}
