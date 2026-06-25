package mirror

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/config"
	"github.com/gutschke/splitdns/internal/model"
)

// Builder owns the snapshot lifecycle and is the single publisher: warm-start from
// the cache, serial-driven refreshes via the SOAPoller, and cheap republishes when
// the vhost set changes. Each refresh rebuilds the snapshot, folds in the current
// vhost set, publishes, and persists to the warm cache.
type Builder struct {
	lister   ZoneLister
	tr       TunnelResolver
	cfg      config.Config
	revZones []string
	publish  func(*model.Snapshot)
	vhosts   func() map[string]bool
	log      func(string)

	cache   *Cache
	fetcher SerialFetcher
	now     func() time.Time

	mu   sync.Mutex
	last *model.Snapshot

	// confirmedAt (unix nanos) is the last time the mirror was confirmed CURRENT with the
	// upstream — a successful build, or a successful poll whose serials were unchanged.
	// The watchdog measures staleness from this, NOT from the snapshot's BuiltAt: a
	// healthy mirror that simply has nothing to rebuild (stable serials) is current and
	// must not be force-restarted just because it hasn't rebuilt in a while.
	confirmedAt atomic.Int64
}

// noteConfirmed marks the mirror as current as of now.
func (b *Builder) noteConfirmed() { b.confirmedAt.Store(b.now().UnixNano()) }

// ConfirmedAt returns when the mirror was last confirmed current (zero if never).
func (b *Builder) ConfirmedAt() time.Time {
	n := b.confirmedAt.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// NewBuilder constructs a Builder. lister/cache/fetcher may be nil (no mirror / no
// persistence / no serial polling). vhosts may be nil (empty set). log/now may be nil.
func NewBuilder(l ZoneLister, tr TunnelResolver, cfg config.Config, revZones []string, publish func(*model.Snapshot), cache *Cache, fetcher SerialFetcher, vhosts func() map[string]bool, log func(string), now func() time.Time) *Builder {
	if log == nil {
		log = func(string) {}
	}
	if now == nil {
		now = time.Now
	}
	if vhosts == nil {
		vhosts = func() map[string]bool { return nil }
	}
	return &Builder{lister: l, tr: tr, cfg: cfg, revZones: revZones, publish: publish, vhosts: vhosts, log: log, cache: cache, fetcher: fetcher, now: now}
}

// refresh rebuilds the snapshot, stamps each zone's serial from the latest poll,
// folds in the current vhost set, publishes, and persists to the warm cache.
func (b *Builder) refresh(ctx context.Context, observed map[string]uint32) error {
	snap, err := BuildSnapshot(ctx, b.lister, b.tr, b.cfg, b.revZones)
	if err != nil {
		return err
	}
	for apex, z := range snap.Zones {
		if s, ok := observed[strings.TrimSuffix(apex, ".")]; ok {
			z.LastFetchedSerial = s
			z.SOA = withSOASerial(z.SOA, s) // fold the polled serial into served SOA RDATA (D5)
		}
	}
	snap.VHosts = b.vhosts()
	// Publish under the lock so a concurrent ApplyVHosts() cannot interleave and
	// overwrite a newer published snapshot with an older vhost set (D6).
	b.mu.Lock()
	b.last = snap
	b.publish(snap)
	b.mu.Unlock()
	if b.cache != nil {
		if cerr := b.cache.Save(snap.Zones, b.now()); cerr != nil {
			b.log(fmt.Sprintf("mirror: cache save failed: %v", cerr))
		}
	}
	return nil
}

// ApplyVHosts cheaply republishes the last snapshot with the current vhost set,
// WITHOUT re-fetching from Cloudflare (zones are immutable, so a shallow copy is
// safe). Called by the vhost feed worker when its set changes.
func (b *Builder) ApplyVHosts() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last == nil {
		return
	}
	clone := *b.last // shallow copy; zone maps are immutable and shared
	clone.VHosts = b.vhosts()
	b.last = &clone
	b.publish(&clone)
}

// BuildOnce does a single unconditional refresh (no serials). Used when there is no
// SerialFetcher.
func (b *Builder) BuildOnce(ctx context.Context) error {
	return b.refresh(ctx, nil)
}

// Run warm-starts from the cache (publishing immediately so the hot path serves
// last-known data), then drives serial-based refreshes via the SOAPoller until ctx
// is cancelled. With no fetcher it degrades to a single build.
func (b *Builder) Run(ctx context.Context, progress func()) {
	if progress == nil {
		progress = func() {}
	}
	var seedStates map[string]SerialState
	if b.cache != nil {
		zones, states, err := b.cache.Load(b.now())
		if err != nil {
			b.log(fmt.Sprintf("mirror: warm cache load failed: %v", err))
		} else if len(zones) > 0 {
			snap := BaseSnapshot(b.cfg, b.revZones)
			for apex, z := range zones {
				snap.Zones[apex] = z
			}
			snap.VHosts = b.vhosts()
			b.mu.Lock()
			b.last = snap
			b.publish(snap)
			b.mu.Unlock()
			b.log(fmt.Sprintf("mirror: warm cache loaded (%d zones, serving stale pending refresh)", len(zones)))
		}
		seedStates = states
	}

	b.noteConfirmed() // warm/cold snapshot published: current as of startup
	progress()

	if b.fetcher == nil {
		if err := b.BuildOnce(ctx); err != nil {
			b.log(fmt.Sprintf("mirror: initial build failed (serving cold/warm snapshot): %v", err))
		} else {
			b.log("mirror: initial snapshot published")
		}
		// No serial polling (no CF mirror): there is nothing to go stale, so the mirror is
		// always current. Keep ticking progress (worker liveness) AND confirmation (snapshot
		// freshness) so the watchdog never force-restarts a perfectly healthy local mirror.
		b.noteConfirmed()
		hb := time.NewTicker(30 * time.Second)
		defer hb.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-hb.C:
				b.noteConfirmed()
				progress()
			}
		}
	}

	zoneNames := make([]string, 0, len(b.cfg.Zones.Local))
	for _, z := range b.cfg.Zones.Local {
		zoneNames = append(zoneNames, strings.ToLower(strings.TrimSuffix(z, ".")))
	}
	poller := NewPoller(zoneNames, b.fetcher, seedStates, b.refresh, 0, 0, b.now, b.log)
	poller.progress = progress
	poller.confirm = b.noteConfirmed
	poller.Run(ctx)
}

// Forwarder is the slice of the forwarder the tunnel resolver needs.
type Forwarder interface {
	Forward(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// forwarderResolver resolves tunnel owners by forwarding A/AAAA queries upstream —
// which returns the public addresses Cloudflare currently presents (the flattened
// tunnel addresses). The point is to resolve the OWNER name, not the cfargotunnel
// CNAME RDATA.
type forwarderResolver struct {
	fwd Forwarder
}

// NewForwarderResolver wires a TunnelResolver to the forwarder.
func NewForwarderResolver(fwd Forwarder) TunnelResolver { return forwarderResolver{fwd: fwd} }

func (r forwarderResolver) Resolve(ctx context.Context, fqdn string) (v4, v6 []netip.Addr, err error) {
	v4 = r.queryAddrs(ctx, fqdn, dns.TypeA)
	v6 = r.queryAddrs(ctx, fqdn, dns.TypeAAAA) // benign if empty (IPv4-only tunnels)
	if len(v4) == 0 && len(v6) == 0 {
		return nil, nil, fmt.Errorf("mirror: no tunnel addresses resolved for %s", fqdn)
	}
	return v4, v6, nil
}

func (r forwarderResolver) queryAddrs(ctx context.Context, fqdn string, qtype uint16) []netip.Addr {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(fqdn), qtype)
	resp, err := r.fwd.Forward(ctx, req)
	if err != nil || resp == nil {
		return nil
	}
	var out []netip.Addr
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
				out = append(out, a)
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

// SnapshotSource adapts the published snapshot to ddns.RecordSource, so the DDNS
// writer can read a host's current non-proxied A/AAAA records straight from the
// in-memory mirror instead of issuing extra CF API calls.
type SnapshotSource struct {
	Get func() *model.Snapshot
}

// RecordsForHost implements ddns.RecordSource.
func (s SnapshotSource) RecordsForHost(_ context.Context, shortHost string) ([]model.RR, error) {
	snap := s.Get()
	if snap == nil {
		return nil, nil
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(shortHost), "."))
	var out []model.RR
	for _, z := range snap.Zones {
		recs := z.Records[host]
		if recs == nil {
			continue
		}
		for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
			for _, rr := range recs[typ] {
				if !rr.Proxied {
					out = append(out, rr)
				}
			}
		}
	}
	return out, nil
}
