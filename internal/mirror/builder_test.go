package mirror

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gutschke/splitdns/internal/cfapi"
	"github.com/gutschke/splitdns/internal/config"
	"github.com/gutschke/splitdns/internal/model"
)

// TestWarmStartReconcilesStaleSnapshot is the observable-contract guard for the
// warm-start stale bug: after a restart that loads a warm cache whose serial has NOT
// changed upstream, the FINAL published snapshot must be fresh — CFHealthy=true and the
// zone no longer Stale. It exercises the real Run() path (warm load publishes a stale
// snapshot, then the poller's first cycle reconciles), so it catches any future change
// that reintroduces a "skip the reconcile when serials match" shortcut, regardless of
// the internal mechanism. Without the fix the first (and only) published snapshot stays
// Stale/CFHealthy=false forever and this test fails.
func TestWarmStartReconcilesStaleSnapshot(t *testing.T) {
	apex := "example.com."
	now := time.Unix(7_000_000, 0)
	cfg := config.Config{Zones: config.ZonesConfig{Local: []string{"example.com"}}}

	// Seed a warm cache: a zone with records at serial 100 (so Load marks it Stale and
	// seeds SerialState{Fetched:true}, reproducing the restart condition).
	cache := NewCache(t.TempDir(), time.Hour, nil)
	warm := &model.Zone{
		ID: "z1", Apex: apex, LastFetchedSerial: 100,
		Records:    map[string]map[uint16][]model.RR{"www": {1: {{Name: "www." + apex, Type: 1, Class: 1, TTL: 300, Content: "192.0.2.2"}}}},
		Wildcards:  map[uint16][]model.RR{},
		ENT:        map[string]bool{},
		TunnelAddr: map[string]map[uint16][]model.RR{},
	}
	if err := cache.Save(map[string]*model.Zone{apex: warm}, now); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	// The upstream serial is UNCHANGED (still 100) — the exact case the bug mishandled.
	fetcher := &ctrlFetcher{serial: 100}

	var mu sync.Mutex
	var last *model.Snapshot
	healthy := make(chan struct{}, 1)
	publish := func(s *model.Snapshot) {
		mu.Lock()
		last = s
		mu.Unlock()
		if s.CFHealthy {
			select {
			case healthy <- struct{}{}:
			default:
			}
		}
	}

	lister := fakeLister{
		zones: map[string]string{"z1": "example.com"}, // id -> name
		recs:  map[string][]cfapi.Record{"z1": {{ID: "r1", Type: "A", Name: "example.com", Content: "192.0.2.1", TTL: 300}}},
	}
	b := NewBuilder(lister, fakeTunnel{}, cfg, nil,
		publish, cache, fetcher, nil, nil, func() time.Time { return now })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { b.Run(ctx, nil); close(done) }()

	select {
	case <-healthy:
	case <-time.After(5 * time.Second):
		t.Fatal("warm start never reconciled to a healthy snapshot (still serving stale)")
	}
	cancel()
	<-done

	mu.Lock()
	got := last
	mu.Unlock()
	if got == nil || !got.CFHealthy {
		t.Fatalf("final snapshot not CFHealthy: %+v", got)
	}
	if z := got.Zones[apex]; z == nil {
		t.Fatalf("final snapshot missing zone %s", apex)
	} else if z.Stale {
		t.Errorf("zone %s still marked Stale after warm-start reconcile", apex)
	}
	// The mirror must report itself confirmed-current so the watchdog doesn't force-restart
	// it for being quiet (no rebuild) once serials settle.
	if b.ConfirmedAt().IsZero() {
		t.Error("builder never marked the mirror confirmed-current")
	}
}

// TestWithSOASerial pins D5: the polled serial replaces only the SOA serial token,
// leaving mname/rname/refresh/retry/expire/minimum intact; the default synthesized
// SOA carries serial 1 (the pre-fix served value).
func TestWithSOASerial(t *testing.T) {
	base := synthSOA("example.com.")
	if f := strings.Fields(base.Content); f[2] != "1" {
		t.Fatalf("default synthSOA serial = %q, want 1", f[2])
	}
	got := withSOASerial(base, 2404708612)
	f := strings.Fields(got.Content)
	if f[2] != "2404708612" {
		t.Fatalf("folded serial = %q, want 2404708612", f[2])
	}
	// All other RDATA fields preserved.
	if f[0] != "example.com." || f[1] != "hostmaster.example.com." ||
		f[3] != "7200" || f[4] != "3600" || f[5] != "1209600" || f[6] != "300" {
		t.Fatalf("withSOASerial altered a non-serial field: %q", got.Content)
	}
	// Malformed content is returned unchanged.
	bad := model.RR{Content: "not a soa"}
	if withSOASerial(bad, 5).Content != "not a soa" {
		t.Errorf("malformed SOA content must be returned unchanged")
	}
}

// TestBuilderFoldsAndRepublishesVHosts verifies the builder folds the current vhost
// set into the published snapshot and that ApplyVHosts republishes cheaply (without
// re-fetching) when the set changes.
func TestBuilderFoldsAndRepublishesVHosts(t *testing.T) {
	cfg := config.Config{Zones: config.ZonesConfig{Local: []string{"example.com"}}}

	var mu sync.Mutex
	var published *model.Snapshot
	publish := func(s *model.Snapshot) { mu.Lock(); published = s; mu.Unlock() }

	vhostSet := map[string]bool{"shop": true}
	provider := func() map[string]bool {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]bool{}
		for k := range vhostSet {
			out[k] = true
		}
		return out
	}

	b := NewBuilder(nil, nil, cfg, nil, publish, nil, nil, provider, nil, nil)
	if err := b.BuildOnce(context.Background()); err != nil {
		t.Fatalf("BuildOnce: %v", err)
	}
	mu.Lock()
	got := published
	mu.Unlock()
	if got == nil || !got.VHosts["shop"] {
		t.Fatalf("first publish missing vhost 'shop': %+v", got)
	}

	// Change the vhost set and republish via ApplyVHosts (no rebuild).
	mu.Lock()
	vhostSet = map[string]bool{"blog": true}
	mu.Unlock()
	b.ApplyVHosts()
	mu.Lock()
	got = published
	mu.Unlock()
	if got.VHosts["shop"] || !got.VHosts["blog"] {
		t.Fatalf("ApplyVHosts did not republish the new set: %+v", got.VHosts)
	}
}
