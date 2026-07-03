package netnse2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/encrypted"
	"github.com/gutschke/splitdns/internal/netnstest"
)

func startDoH(t *testing.T) (base string, pool *x509.CertPool, stop func()) {
	t.Helper()
	certFile, keyFile, pool := testCert(t, time.Now().Add(24*time.Hour))
	rel, err := encrypted.NewCertReloader(certFile, keyFile, nil)
	if err != nil {
		t.Fatalf("reloader: %v", err)
	}
	mgr := encrypted.NewManager(newHandler("127.0.0.0/8"), rel, nil)
	if err := mgr.StartDoH([]string{"127.0.0.1:0"}, "/dns-query"); err != nil {
		t.Fatalf("StartDoH: %v", err)
	}
	addr := mgr.BoundAddrs()[0].String()
	return "https://" + addr, pool, func() { mgr.Shutdown(context.Background()) }
}

func dohClient(pool *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "dns.example.net"},
	}}
}

// DoH answers the DDR SVCB via both POST and GET, through the shared handler.
func TestDoHEndToEnd(t *testing.T) {
	netnstest.RequireIsolated(t)
	base, pool, stop := startDoH(t)
	defer stop()
	client := dohClient(pool)

	m := new(dns.Msg)
	m.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	wire, _ := m.Pack()

	// POST application/dns-message
	resp, err := client.Post(base+"/dns-query", "application/dns-message", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	assertSVCB(t, "POST", resp)

	// GET ?dns=base64url
	resp, err = client.Get(base + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(wire))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.HasPrefix(cc, "max-age=") {
		t.Errorf("GET Cache-Control = %q, want max-age=...", cc)
	}
	assertSVCB(t, "GET", resp)
}

func assertSVCB(t *testing.T, tag string, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("%s status = %d, want 200", tag, resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("%s content-type = %q", tag, ct)
	}
	body, _ := io.ReadAll(resp.Body)
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		t.Fatalf("%s unpack: %v", tag, err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("%s want 1 SVCB, got %d", tag, len(msg.Answer))
	}
	if _, ok := msg.Answer[0].(*dns.SVCB); !ok {
		t.Errorf("%s want SVCB, got %T", tag, msg.Answer[0])
	}
}

// DoH rejects abuse: oversized body, wrong method/content-type, malformed wire, bad path.
func TestDoHHardening(t *testing.T) {
	netnstest.RequireIsolated(t)
	base, pool, stop := startDoH(t)
	defer stop()
	client := dohClient(pool)
	url := base + "/dns-query"

	// 413 — body over 64 KiB.
	resp, err := client.Post(url, "application/dns-message", bytes.NewReader(make([]byte, 70000)))
	if err != nil {
		t.Fatalf("oversized POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status = %d, want 413", resp.StatusCode)
	}

	// 415 — wrong content-type.
	resp, err = client.Post(url, "text/plain", strings.NewReader("hi"))
	if err != nil {
		t.Fatalf("wrong CT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("wrong content-type: status = %d, want 415", resp.StatusCode)
	}

	// 400 — malformed wire message.
	resp, err = client.Post(url, "application/dns-message", strings.NewReader("not-a-dns-message"))
	if err != nil {
		t.Fatalf("malformed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed wire: status = %d, want 400", resp.StatusCode)
	}

	// 405 — wrong method.
	req, _ := http.NewRequest(http.MethodPut, url, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: status = %d, want 405", resp.StatusCode)
	}

	// 404 — unknown path (no other routes, no directory listing).
	resp, err = client.Get(base + "/foo")
	if err != nil {
		t.Fatalf("bad path: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path: status = %d, want 404", resp.StatusCode)
	}
}
