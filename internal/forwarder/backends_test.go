package forwarder

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Backends() reflects each upstream's circuit-breaker state for the diagnostics page.
func TestBackendsReflectsBreaker(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clk := func() time.Time { return now }
	pol := DefaultPolicy()
	pol.ConsecFail = 3
	pol.Cooldown = 10 * time.Second

	u := Upstream{Addr: "192.0.2.1:853", Net: "tcp-tls", ServerName: "resolver.example"}
	f := NewWithUpstreams([]Upstream{u}, nil, false, nil, WithClock(clk), WithPolicy(pol))

	bs := f.Backends()
	if len(bs) != 1 || bs[0].State != "closed" || !bs[0].Healthy {
		t.Fatalf("initial backends = %+v, want one closed/healthy", bs)
	}
	if bs[0].Addr != u.Addr || bs[0].Net != u.Net || bs[0].Role != "primary" {
		t.Errorf("backend identity = %+v, want addr/net/role of the configured upstream", bs[0])
	}

	// Trip the breaker with consecutive failures.
	b := f.breakerFor(u)
	for i := 0; i < 3; i++ {
		b.record(false)
	}
	bs = f.Backends()
	if bs[0].State != "open" || bs[0].Healthy {
		t.Errorf("after 3 consecutive failures: %+v, want open/unhealthy", bs[0])
	}
	if bs[0].Consec != 3 {
		t.Errorf("consecutive failures = %d, want 3", bs[0].Consec)
	}
	if bs[0].Cooldown != 10*time.Second {
		t.Errorf("cooldown remaining = %v, want 10s", bs[0].Cooldown)
	}

	// After the cooldown elapses, a probe is admitted (half-open).
	now = now.Add(11 * time.Second)
	if !b.allow() {
		t.Fatal("breaker should admit a probe after cooldown")
	}
	if bs := f.Backends(); bs[0].State != "half-open" {
		t.Errorf("post-cooldown state = %q, want half-open", bs[0].State)
	}
}

// SetBackendEnabled disables/enables an upstream on the fly; Backends reflects it.
func TestSetBackendEnabled(t *testing.T) {
	u := Upstream{Addr: "192.0.2.1:853", Net: "tcp-tls", ServerName: "r.example"}
	f := NewWithUpstreams([]Upstream{u}, nil, false, nil)

	if !f.SetBackendEnabled(u.Addr, false) {
		t.Fatal("disabling a known addr should return true")
	}
	if bs := f.Backends(); !bs[0].Disabled || bs[0].State != "disabled" || bs[0].Healthy {
		t.Errorf("disabled backend = %+v, want disabled/unhealthy", bs[0])
	}
	if f.SetBackendEnabled("9.9.9.9:853", false) {
		t.Error("disabling an unknown addr should return false")
	}
	f.ResetBackends()
	if f.Backends()[0].Disabled {
		t.Error("ResetBackends should clear the manual disable")
	}
}

// A disabled upstream is skipped by Forward (not even attempted), even under fail-open.
func TestDisabledUpstreamSkipped(t *testing.T) {
	u := Upstream{Addr: "127.0.0.1:9", Net: "udp"} // discard port; would error if attempted
	f := NewWithUpstreams([]Upstream{u}, nil, false, nil)
	f.SetBackendEnabled(u.Addr, false)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err := f.Forward(context.Background(), q)
	if err == nil || !strings.Contains(err.Error(), "manually disabled") {
		t.Errorf("err = %v, want a 'manually disabled' skip (no attempt)", err)
	}
}

// The cleartext fallbacks appear only when cleartext is enabled.
func TestBackendsFallbackVisibility(t *testing.T) {
	prim := []Upstream{{Addr: "192.0.2.1:853", Net: "tcp-tls"}}
	fb := []Upstream{{Addr: "192.0.2.1:53", Net: "udp"}}

	off := NewWithUpstreams(prim, fb, false, nil)
	if got := len(off.Backends()); got != 1 {
		t.Errorf("cleartext off: %d backends, want 1 (fallback hidden)", got)
	}
	on := NewWithUpstreams(prim, fb, true, nil)
	if got := len(on.Backends()); got != 2 {
		t.Errorf("cleartext on: %d backends, want 2 (primary + fallback)", got)
	}
}

// Backends() carries lifetime per-upstream telemetry (queries/failures/avg RTT) that
// survives breaker recovery — answering "how much traffic, how fast, how reliable".
func TestBackendsLifetimeStats(t *testing.T) {
	u := Upstream{Addr: "192.0.2.1:853", Net: "tcp-tls", ServerName: "r.example"}
	f := NewWithUpstreams([]Upstream{u}, nil, false, nil)

	// Two successes (10ms, 30ms) and one failure.
	f.noteAttempt(u, true, 10*time.Millisecond)
	f.noteAttempt(u, true, 30*time.Millisecond)
	f.noteAttempt(u, false, 2*time.Second)

	bs := f.Backends()[0]
	if bs.Queries != 3 || bs.Failures != 1 {
		t.Errorf("queries/failures = %d/%d, want 3/1", bs.Queries, bs.Failures)
	}
	// Avg is over successes only (failures must not pollute it): (10+30)/2 = 20ms.
	if bs.AvgRTT != 20*time.Millisecond {
		t.Errorf("avg RTT = %v, want 20ms (successes only)", bs.AvgRTT)
	}
	if bs.LastRTT != 30*time.Millisecond {
		t.Errorf("last RTT = %v, want 30ms (most recent success)", bs.LastRTT)
	}

	// An upstream with no traffic reports zeroes (no division by zero).
	f2 := NewWithUpstreams([]Upstream{u}, nil, false, nil)
	if z := f2.Backends()[0]; z.Queries != 0 || z.AvgRTT != 0 {
		t.Errorf("untouched upstream = %+v, want zero stats", z)
	}
}
