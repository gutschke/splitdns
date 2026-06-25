package mirror

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// SerialFetcher queries a zone's current authoritative SOA serial. Implemented by
// bootstrapSerialFetcher (real) and faked in tests.
type SerialFetcher interface {
	Serial(ctx context.Context, zone string) (uint32, error)
}

// RefreshFunc rebuilds + republishes + persists the snapshot. observed carries the
// serial just polled per zone (keyed by zone name, no trailing dot) so the refresh
// can stamp Zone.LastFetchedSerial.
type RefreshFunc func(ctx context.Context, observed map[string]uint32) error

// Poller is the SOA serial change-detector (design §2.5). On each cycle it queries
// every zone's authoritative serial and triggers a refresh iff some zone's serial is
// newer than what we last fetched (RFC 1982) — or a zone has never fetched records,
// or the forced full-refresh interval has elapsed. It owns the SerialState map.
type Poller struct {
	zones    []string
	fetcher  SerialFetcher
	states   map[string]SerialState
	refresh  RefreshFunc
	interval time.Duration // SOA poll cadence (default 60s)
	forced   time.Duration // forced full refresh (default 6h)
	log      func(string)
	now      func() time.Time
	lastFull time.Time

	// progress (nil-safe) is ticked at the end of every cycle for the supervisor.
	progress func()
	// confirm (nil-safe) marks the mirror current when a cycle reaches the upstream and
	// either finds no change or rebuilds successfully — the watchdog's freshness signal.
	confirm func()
}

func (p *Poller) noteOK() {
	if p.confirm != nil {
		p.confirm()
	}
}

// NewPoller builds a Poller. states seeds the per-zone serial state (from the warm
// cache). interval/forced<=0 take defaults; now/log may be nil.
func NewPoller(zones []string, fetcher SerialFetcher, states map[string]SerialState, refresh RefreshFunc, interval, forced time.Duration, now func() time.Time, log func(string)) *Poller {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if forced <= 0 {
		forced = 6 * time.Hour
	}
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = func(string) {}
	}
	if states == nil {
		states = map[string]SerialState{}
	}
	return &Poller{zones: zones, fetcher: fetcher, states: states, refresh: refresh, interval: interval, forced: forced, log: log, now: now}
}

// Run does an immediate cycle (so a cold start force-fetches at once) then polls on
// the interval until ctx is cancelled. A per-zone jitter avoids thundering polls.
func (p *Poller) Run(ctx context.Context) {
	p.cycle(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.cycle(ctx)
		}
	}
}

// cycle polls serials and refreshes if needed. Exposed (unexported) for tests.
func (p *Poller) cycle(ctx context.Context) {
	if p.progress != nil {
		defer p.progress()
	}
	observed := map[string]uint32{}
	need := false
	for _, z := range p.zones {
		s, err := p.fetcher.Serial(ctx, z)
		if err != nil {
			p.log(fmt.Sprintf("soa: %s serial query failed (keeping last state): %v", z, err))
			continue
		}
		observed[z] = s
		if p.states[z].ShouldFetch(s) {
			need = true
		}
	}
	firstCycle := p.lastFull.IsZero()
	forced := !firstCycle && p.now().Sub(p.lastFull) >= p.forced
	// Reconcile against Cloudflare on the first cycle even when every observed serial
	// matches the warm cache. The warm snapshot is published Stale with CFHealthy=false;
	// only a full build clears those flags and proves CF is reachable with the configured
	// token. Skipping it (the old "warm + unchanged" shortcut) left the daemon serving
	// correct-but-flagged-stale data indefinitely — until the next upstream serial bump —
	// which on a long-lived restart looked like a dead mirror. Gate on having actually
	// observed a serial, so a total serial-query outage still keeps last state (a
	// degraded warm snapshot serving is better than hammering a dead upstream).
	reconcile := firstCycle && len(observed) > 0
	if !need && !forced && !reconcile {
		// Nothing to rebuild. If we actually reached the upstream (got a serial), the
		// mirror is confirmed CURRENT — record that so the watchdog doesn't mistake a
		// quiet-but-healthy mirror for a stale one. A total serial outage (observed empty)
		// does NOT confirm: we cannot vouch for currency, so let staleness accrue.
		if len(observed) > 0 {
			p.noteOK()
		}
		return
	}
	if err := p.refresh(ctx, observed); err != nil {
		// On a failed first cycle, lastFull stays zero so the next cycle retries the
		// reconcile rather than waiting out the forced interval — keep trying until the
		// stale flags can be cleared, while the warm snapshot keeps serving meanwhile.
		p.log(fmt.Sprintf("soa: refresh failed (keeping previous snapshot): %v", err))
		return
	}
	for z, s := range observed {
		p.states[z] = SerialState{Last: s, Fetched: true}
	}
	p.lastFull = p.now()
	p.noteOK() // rebuilt successfully: current
}

// bootstrapSerialFetcher queries a zone's SOA serial via recursive bootstrap
// resolvers. NOTE: full authoritative-NS discovery (ask bootstrap for the zone NS,
// resolve them, query those) is a §2.5 refinement deferred here; a recursive query
// returns the current serial (bounded by the SOA TTL), which is sufficient for
// change-detection with the 6h forced-refresh backstop.
type bootstrapSerialFetcher struct {
	servers []string // host:port
	client  *dns.Client
}

// NewBootstrapSerialFetcher builds a fetcher over the given resolvers (host or
// host:port; default port 53). Empty falls back to 1.1.1.1.
func NewBootstrapSerialFetcher(servers []string) SerialFetcher {
	norm := make([]string, 0, len(servers))
	for _, s := range servers {
		norm = append(norm, withPort(s, "53"))
	}
	if len(norm) == 0 {
		norm = []string{"1.1.1.1:53"}
	}
	return &bootstrapSerialFetcher{servers: norm, client: &dns.Client{Timeout: 4 * time.Second}}
}

func (b *bootstrapSerialFetcher) Serial(ctx context.Context, zone string) (uint32, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	req.RecursionDesired = true
	want := dns.Fqdn(zone)
	var lastErr error
	for _, srv := range b.servers {
		resp, _, err := b.client.ExchangeContext(ctx, req, srv)
		if err != nil {
			lastErr = err
			continue
		}
		// A REFUSED/SERVFAIL/NXDOMAIN response carries no authoritative serial for us;
		// don't mine its AUTHORITY section for a parent-zone SOA (D25).
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("%s: rcode %s for %s", srv, dns.RcodeToString[resp.Rcode], zone)
			continue
		}
		// Prefer an exact-owner SOA from ANSWER, then AUTHORITY; reject a parent-zone
		// SOA (owner != the queried zone) so we never adopt the wrong serial.
		if soa := matchSOA(resp.Answer, want); soa != 0 {
			return soa, nil
		}
		if soa := matchSOA(resp.Ns, want); soa != 0 {
			return soa, nil
		}
		lastErr = fmt.Errorf("no SOA for %s in response from %s", zone, srv)
	}
	return 0, fmt.Errorf("soa: %s: %w", zone, lastErr)
}

// matchSOA returns the serial of the first SOA whose owner exactly equals want
// (case-insensitive), or 0 if none. Serial 0 is treated as "no match" — a real
// zone never serves serial 0, and the caller falls through to the next server.
func matchSOA(rrs []dns.RR, want string) uint32 {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, want) {
			return soa.Serial
		}
	}
	return 0
}

func withPort(hostport, defPort string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, defPort)
}
