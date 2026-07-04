package mdns

import (
	"context"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// On-demand resolution bounds. These are deliberately conservative for a default-on posture
// on a reflected multi-segment LAN: the global cap limits total outbound (and thus the
// reflector's fan-out), the per-client cap stops one host consuming the budget, the in-flight
// cap bounds concurrent waiters, and the suppression window collapses repeat/retry misses for
// the same name into one query per window.
const (
	odGlobalRate     = 10.0 // queries/sec sustained (reflector-conservative)
	odGlobalBurst    = 20.0
	odClientRate     = 5.0 // per source address
	odClientBurst    = 10.0
	odInflightCap    = 64
	odSuppressWindow = 10 * time.Second
	odTableCap       = 4096 // bound the recent + per-client maps
)

type odInflight struct{ done chan struct{} }

// odBucket is a minimal token bucket (no external dep).
type odBucket struct {
	tokens float64
	last   time.Time
}

func (b *odBucket) allow(now time.Time, rate, burst float64) bool {
	if !b.last.IsZero() {
		b.tokens += now.Sub(b.last).Seconds() * rate
	}
	if b.tokens > burst {
		b.tokens = burst
	} else if b.last.IsZero() {
		b.tokens = burst // first use starts full
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// buildHostQuery packs one mDNS query asking for a single host's A and AAAA (both families in
// one datagram, so A+AAAA misses for the same host coalesce). Returns nil if it can't pack.
func buildHostQuery(label string) []byte {
	m := new(dns.Msg)
	name := dns.Fqdn(label + ".local")
	m.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
	}
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

// Resolve solicits an unknown local host over mDNS and blocks until it appears in the cache,
// ctx is done, or the wait elapses. The returned bool reports only whether the host appeared
// (for metrics) — the caller re-runs the pure resolver against the reloaded view regardless,
// which is the authoritative answer and erases the wake/timeout race. It is heavily gated
// (single-flight, global + per-client rate limit, in-flight cap, recently-queried
// suppression) and a no-op when on-demand is disabled or no multicast sender is wired.
func (s *Source) Resolve(ctx context.Context, label string, client netip.Addr) bool {
	if s.odPending == nil || s.sender == nil || label == "" {
		return false
	}
	now := s.now()

	s.odMu.Lock()
	// Single-flight: join an outstanding query for the same host rather than emit another.
	if fl, ok := s.odPending[label]; ok {
		s.odMu.Unlock()
		return s.odWait(ctx, fl)
	}
	// Recently queried (resolved or not): suppress a re-query this window.
	if t, ok := s.odRecent[label]; ok && now.Sub(t) < odSuppressWindow {
		s.odMu.Unlock()
		s.odSuppressed.Add(1)
		return false
	}
	if len(s.odPending) >= odInflightCap {
		s.odMu.Unlock()
		s.odCapFull.Add(1)
		return false
	}
	if !s.odGlobal.allow(now, odGlobalRate, odGlobalBurst) || !s.odClientAllow(now, client) {
		s.odMu.Unlock()
		s.odLimited.Add(1)
		return false
	}
	fl := &odInflight{done: make(chan struct{})}
	s.odPending[label] = fl
	s.odRecent[label] = now // record before sending so an immediate retry suppresses
	s.odBoundRecent()
	s.odMu.Unlock()

	s.odEmitted.Add(1)
	if pkt := buildHostQuery(label); pkt != nil {
		s.sender(pkt)
	}
	ok := s.odWait(ctx, fl)

	s.odMu.Lock()
	if s.odPending[label] == fl { // may already be gone via completeInflight
		delete(s.odPending, label)
	}
	s.odMu.Unlock()
	if ok {
		s.odHits.Add(1)
	}
	return ok
}

func (s *Source) odWait(ctx context.Context, fl *odInflight) bool {
	t := time.NewTimer(s.onDemandWait)
	defer t.Stop()
	select {
	case <-fl.done:
		return true
	case <-ctx.Done():
		return false
	case <-t.C:
		return false
	}
}

// odClientAllow rate-limits per source address; caller holds odMu.
func (s *Source) odClientAllow(now time.Time, client netip.Addr) bool {
	if !client.IsValid() {
		return true // no client key (e.g. internal caller) — global limit still applies
	}
	if len(s.odClients) > odTableCap {
		// Evict IDLE buckets rather than wiping the whole map: a wholesale reset would
		// let a flood from many (spoofable) source addresses clear every ACTIVE client's
		// throttle. An idle bucket has long since refilled, so dropping it is
		// behavior-neutral.
		cutoff := now.Add(-odSuppressWindow)
		for k, b := range s.odClients {
			if b.last.Before(cutoff) {
				delete(s.odClients, k)
			}
		}
		// Pathological case (thousands of simultaneously-active sources): trim down to
		// the cap WITHOUT wiping, so most survivors keep their throttle state.
		for k := range s.odClients {
			if len(s.odClients) <= odTableCap {
				break
			}
			delete(s.odClients, k)
		}
	}
	b := s.odClients[client]
	if b == nil {
		b = &odBucket{}
		s.odClients[client] = b
	}
	return b.allow(now, odClientRate, odClientBurst)
}

// odBoundRecent keeps the recently-queried map bounded; caller holds odMu.
func (s *Source) odBoundRecent() {
	if len(s.odRecent) <= odTableCap {
		return
	}
	cutoff := s.now().Add(-odSuppressWindow)
	for k, t := range s.odRecent {
		if t.Before(cutoff) {
			delete(s.odRecent, k)
		}
	}
	if len(s.odRecent) > odTableCap { // still over (all fresh) — hard reset
		s.odRecent = map[string]time.Time{}
	}
}

// completeInflight wakes any waiter whose host just became visible. MUST be called AFTER
// publish() so a woken waiter is guaranteed to observe the view containing the host.
func (s *Source) completeInflight(hosts []string) {
	if s.odPending == nil || len(hosts) == 0 {
		return
	}
	s.odMu.Lock()
	for _, h := range hosts {
		if fl, ok := s.odPending[h]; ok {
			close(fl.done)
			delete(s.odPending, h)
		}
	}
	s.odMu.Unlock()
}

// OnDemandStats is the diagnostics view of on-demand resolution activity.
type OnDemandStats struct {
	Enabled     bool   `json:"enabled"`
	Emitted     uint64 `json:"emitted"`
	Hits        uint64 `json:"hits"`
	Suppressed  uint64 `json:"suppressed"`
	RateLimited uint64 `json:"rate_limited"`
	CapFull     uint64 `json:"cap_full"`
	InFlight    int    `json:"in_flight"`
}

// OnDemandStats returns a snapshot of on-demand counters (for the diagnostics console).
func (s *Source) OnDemandStats() OnDemandStats {
	if s.odPending == nil {
		return OnDemandStats{}
	}
	s.odMu.Lock()
	inflight := len(s.odPending)
	s.odMu.Unlock()
	return OnDemandStats{
		Enabled: true, InFlight: inflight,
		Emitted: s.odEmitted.Load(), Hits: s.odHits.Load(), Suppressed: s.odSuppressed.Load(),
		RateLimited: s.odLimited.Load(), CapFull: s.odCapFull.Load(),
	}
}
