package chaos

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/leakcheck"
	"github.com/gutschke/splitdns/internal/mockedge"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
	"github.com/gutschke/splitdns/internal/server"
)

// TestFloodBoundedNoLeak pins S29: under a concurrent UDP+TCP query flood the server
// stays responsive, its goroutine count stays bounded (the inbound limiter caps
// concurrent work — no unbounded growth), and after shutdown nothing leaks.
func TestFloodBoundedNoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("flood test skipped in -short")
	}
	base := leakcheck.Baseline()

	up, err := mockedge.NewDNS()
	if err != nil {
		t.Fatalf("mock upstream: %v", err)
	}
	defer up.Close()
	up.SetA("fwd.example.org", "203.0.113.5")

	fwd := forwarder.NewWithUpstreams([]forwarder.Upstream{{Addr: up.Addr(), Net: "udp"}}, nil, false, nil)
	allow, err := netmatch.ParseSet([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	snap := &model.Snapshot{Static: map[string][]model.RR{
		"gw.example.test.": {{Type: dns.TypeA, Class: dns.ClassINET, TTL: 300, Content: "203.0.113.99"}},
	}}
	const maxInflight = 64
	srv := server.New(server.Config{
		Access:      netmatch.Access{Allow: allow},
		Snapshot:    func() *model.Snapshot { return snap },
		View:        func() *model.MDNSView { return &model.MDNSView{} },
		Forwarder:   fwd,
		MaxInflight: maxInflight,
	})
	if err := srv.Start([]string{"127.0.0.1:0"}, true, true); err != nil {
		t.Fatalf("server start: %v", err)
	}
	var udpAddr, tcpAddr string
	for _, a := range srv.BoundAddrs() {
		switch a.Network() {
		case "udp":
			udpAddr = a.String()
		case "tcp":
			tcpAddr = a.String()
		}
	}

	// Sample peak goroutine count while the flood runs.
	var peak int64
	stopMon := make(chan struct{})
	var monWG sync.WaitGroup
	monWG.Add(1)
	go func() {
		defer monWG.Done()
		for {
			select {
			case <-stopMon:
				return
			default:
				if n := int64(runtime.NumGoroutine()); n > atomic.LoadInt64(&peak) {
					atomic.StoreInt64(&peak, n)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	// Flood: 80 workers × 40 queries, alternating UDP/TCP and local/forwarded.
	const workers, perWorker = 80, 40
	var ok, fail int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				netw, addr := "udp", udpAddr
				if (w+i)%3 == 0 {
					netw, addr = "tcp", tcpAddr
				}
				name := "gw.example.test."
				if i%2 == 0 {
					name = "fwd.example.org."
				}
				m := new(dns.Msg)
				m.SetQuestion(name, dns.TypeA)
				c := &dns.Client{Net: netw, Timeout: 3 * time.Second}
				if resp, _, err := c.Exchange(m, addr); err == nil && resp.Rcode == dns.RcodeSuccess {
					atomic.AddInt64(&ok, 1)
				} else {
					atomic.AddInt64(&fail, 1) // UDP overflow drops are expected backpressure
				}
			}
		}(w)
	}
	wg.Wait()
	close(stopMon)
	monWG.Wait()

	// The server must remain responsive after the flood.
	m := new(dns.Msg)
	m.SetQuestion("gw.example.test.", dns.TypeA)
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	final, _, err := c.Exchange(m, udpAddr)
	if err != nil || len(final.Answer) != 1 {
		t.Fatalf("server unresponsive after flood: err=%v answers=%v", err, final)
	}

	// A meaningful fraction must have succeeded (not a total wedge).
	if ok < int64(workers*perWorker)/4 {
		t.Errorf("too few successes under flood: ok=%d fail=%d", ok, fail)
	}
	// Goroutines must stay bounded — generous ceiling catches unbounded growth, not jitter.
	if p := atomic.LoadInt64(&peak); p > int64(base)+2000 {
		t.Errorf("goroutine count exploded under flood: peak=%d baseline=%d", p, base)
	}
	t.Logf("flood: ok=%d fail=%d peak_goroutines=%d baseline=%d", ok, fail, atomic.LoadInt64(&peak), base)

	srv.Shutdown()
	up.Close()
	leakcheck.AssertNoLeak(t, base)
}
