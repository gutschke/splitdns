package mockedge

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCloudflareFaultInjection(t *testing.T) {
	m := NewCloudflare("tok")
	m.AddZone("zA", "example.com")
	srv := m.Start()
	defer srv.Close()
	cl := srv.Client()

	get := func() (*http.Response, error) {
		req, _ := http.NewRequest("GET", srv.URL+"/zones", nil)
		req.Header.Set("Authorization", "Bearer tok")
		return cl.Do(req)
	}

	// Injected 500 for exactly one request, then auto-recovers.
	m.SetFault(Fault{Status: 500, Times: 1})
	resp, err := get()
	if err != nil {
		t.Fatalf("expected a 500 response, got transport error %v", err)
	}
	if resp.StatusCode != 500 {
		t.Errorf("want status 500, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp2, err := get() // fault cleared after 1
	if err != nil || resp2.StatusCode != 200 {
		t.Fatalf("fault should have self-cleared: status=%v err=%v", resp2, err)
	}
	resp2.Body.Close()

	// Down resets the connection: a transport error, not an HTTP status.
	m.SetFault(Fault{Down: true})
	if r, err := get(); err == nil {
		r.Body.Close()
		t.Errorf("Down should produce a transport error, got status %d", r.StatusCode)
	}
	m.SetFault(Fault{}) // clear

	// Delay: the request still succeeds but takes at least the delay.
	m.SetFault(Fault{Delay: 120 * time.Millisecond, Times: 1})
	start := time.Now()
	r, err := get()
	if err != nil {
		t.Fatalf("delayed request failed: %v", err)
	}
	r.Body.Close()
	if time.Since(start) < 100*time.Millisecond {
		t.Errorf("delay not applied: %v", time.Since(start))
	}
}

func TestDNSMockUpstreamAndSOA(t *testing.T) {
	d, err := NewDNS()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetA("public.example.org", "203.0.113.5")
	d.SetSOASerial("example.com", 2024999999)

	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}

	// A query.
	qa := new(dns.Msg)
	qa.SetQuestion("public.example.org.", dns.TypeA)
	ra, _, err := c.Exchange(qa, d.Addr())
	if err != nil {
		t.Fatalf("A exchange: %v", err)
	}
	if len(ra.Answer) != 1 {
		t.Fatalf("want 1 A answer, got %d", len(ra.Answer))
	}

	// SOA serial query (the bootstrap poller path).
	qs := new(dns.Msg)
	qs.SetQuestion("example.com.", dns.TypeSOA)
	rs, _, err := c.Exchange(qs, d.Addr())
	if err != nil {
		t.Fatalf("SOA exchange: %v", err)
	}
	if len(rs.Answer) != 1 {
		t.Fatalf("want 1 SOA answer, got %d", len(rs.Answer))
	}
	soa, ok := rs.Answer[0].(*dns.SOA)
	if !ok || soa.Serial != 2024999999 {
		t.Fatalf("unexpected SOA %v", rs.Answer[0])
	}

	// Drop fault → client times out.
	d.SetFault(true, 0, 0)
	qd := new(dns.Msg)
	qd.SetQuestion("public.example.org.", dns.TypeA)
	cFast := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	if _, _, err := cFast.Exchange(qd, d.Addr()); err == nil {
		t.Errorf("dropped query should time out")
	}
}

func TestVHostFeedMock(t *testing.T) {
	f, err := NewVHostFeed("shop.example.com", "blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	read := func() string {
		conn, err := net.Dial("tcp", f.Addr())
		if err != nil {
			t.Fatalf("dial feed: %v", err)
		}
		defer conn.Close()
		b, _ := io.ReadAll(conn)
		return string(b)
	}

	if got := read(); got != "shop.example.com\nblog.example.com\n" {
		t.Errorf("unexpected feed body %q", got)
	}
	f.Set("only.example.com")
	if got := read(); got != "only.example.com\n" {
		t.Errorf("feed Set not reflected: %q", got)
	}
}
