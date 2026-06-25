package chaos

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/mockedge"
)

// TestBreakerOpenRecover pins S29: with two upstreams, a DEGRADED primary trips its
// breaker and is then skipped fast (the healthy secondary answers without paying the
// dead primary's timeout), and once the primary heals the breaker recovers and uses
// it again. This is the partial-outage win the breaker exists for.
func TestBreakerOpenRecover(t *testing.T) {
	if testing.Short() {
		t.Skip("breaker recover test skipped in -short (real timeouts)")
	}

	bad, err := mockedge.NewDNS()
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	good, err := mockedge.NewDNS()
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	bad.SetA("x.example.org", "203.0.113.1")  // primary's answer (when healthy)
	good.SetA("x.example.org", "203.0.113.2") // secondary's answer

	// Fast, deterministic-ish breaker: trip after 2 consecutive failures, 300ms cooldown.
	pol := forwarder.Policy{
		Window: 5 * time.Second, Buckets: 5, MinSamples: 1 << 30, FailRatio: 2,
		ConsecFail: 2, Cooldown: 300 * time.Millisecond, HalfOpenMax: 1,
	}
	fwd := forwarder.NewWithUpstreams(
		[]forwarder.Upstream{{Addr: bad.Addr(), Net: "udp"}, {Addr: good.Addr(), Net: "udp"}},
		nil, false, nil, forwarder.WithPolicy(pol))

	ask := func() (string, time.Duration) {
		m := new(dns.Msg)
		m.SetQuestion("x.example.org.", dns.TypeA)
		start := time.Now()
		resp, err := fwd.Forward(context.Background(), m)
		el := time.Since(start)
		if err != nil || resp == nil || len(resp.Answer) == 0 {
			return "", el
		}
		if a, ok := resp.Answer[0].(*dns.A); ok {
			return a.A.String(), el
		}
		return "", el
	}

	// Degrade the primary: it now black-holes (drops) every query.
	bad.SetFault(true, 0, 0)

	// Prime: two queries fail on the primary (paying its timeout) but still succeed via
	// the secondary; the second failure trips the primary's breaker.
	for i := 0; i < 2; i++ {
		if ip, _ := ask(); ip != "203.0.113.2" {
			t.Fatalf("priming query %d should fall through to the secondary, got %q", i, ip)
		}
	}

	// Breaker now open: the dead primary is skipped, so the answer comes from the
	// secondary FAST (no ~1.5s primary timeout paid).
	ip, el := ask()
	if ip != "203.0.113.2" {
		t.Fatalf("while primary is open, want secondary's answer, got %q", ip)
	}
	if el > 500*time.Millisecond {
		t.Errorf("breaker should skip the dead primary fast; query took %v", el)
	}

	// Heal the primary and let the cooldown pass; the half-open probe should rediscover
	// it and close the breaker, so queries use the (preferred) primary again.
	bad.SetFault(false, 0, 0)
	recovered := false
	for i := 0; i < 5; i++ {
		time.Sleep(350 * time.Millisecond) // > cooldown
		if ip, _ := ask(); ip == "203.0.113.1" {
			recovered = true
			break
		}
	}
	if !recovered {
		t.Errorf("breaker should recover and use the healed primary")
	}
}
