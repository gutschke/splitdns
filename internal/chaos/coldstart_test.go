// Package chaos holds adversarial reliability tests (design S29): the daemon must
// degrade predictably — SERVFAIL within deadline on a hung upstream, fail-static on
// a cold start with every dependency down, and stay bounded (no goroutine leak)
// under flood. They run against the shared mockedge fabric over loopback.
package chaos

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/gutschke/splitdns/internal/cfapi"
	"github.com/gutschke/splitdns/internal/config"
	"github.com/gutschke/splitdns/internal/mirror"
	"github.com/gutschke/splitdns/internal/mockedge"
	"github.com/gutschke/splitdns/internal/model"
)

// soaSerial extracts the serial (3rd token) from an SOA RDATA string.
func soaSerial(content string) string {
	f := strings.Fields(content)
	if len(f) < 3 {
		return ""
	}
	return f[2]
}

// TestColdStartBaseSnapshotValidSerial proves the cold-start snapshot — the one the
// daemon serves before any dependency is reachable — carries a valid, non-zero SOA
// serial for the zones it is authoritative for (fail-static, §2.4d).
func TestColdStartBaseSnapshotValidSerial(t *testing.T) {
	revZones := []string{"2.0.192.in-addr.arpa."}
	snap := mirror.BaseSnapshot(config.Default(), revZones)
	if snap == nil {
		t.Fatal("BaseSnapshot returned nil")
	}
	rz := snap.ReverseZ["2.0.192.in-addr.arpa."]
	if rz == nil {
		t.Fatal("cold-start snapshot is missing its reverse zone")
	}
	if s := soaSerial(rz.SOA.Content); s == "" || s == "0" {
		t.Errorf("cold-start reverse SOA serial = %q, want non-zero (fail-static)", s)
	}
	// The liveness record must also be answerable on a cold box.
	if len(snap.Static["health.splitdnsd.local."]) == 0 {
		t.Errorf("cold-start snapshot missing the liveness record")
	}
}

// failResolver is a TunnelResolver that always fails (the upstreams are down too).
type failResolver struct{}

func (failResolver) Resolve(context.Context, string) (v4, v6 []netip.Addr, err error) {
	return nil, nil, context.DeadlineExceeded
}

// TestColdStartBuilderFailStatic drives the real mirror builder with EVERY dependency
// down (Cloudflare API connection-reset, tunnel resolver failing). It must not panic
// and must not clobber the already-published valid snapshot — the daemon keeps
// serving the cold-start data.
func TestColdStartBuilderFailStatic(t *testing.T) {
	cf := mockedge.NewCloudflare("tok")
	cf.AddZone("zA", "example.com")
	cf.SetFault(mockedge.Fault{Down: true}) // every request resets the connection
	srv := cf.Start()
	defer srv.Close()

	lister := cfapi.New(srv.URL, "tok", srv.Client())
	cfg := config.Default()
	cfg.Zones.Local = []string{"example.com"}
	revZones := []string{"2.0.192.in-addr.arpa."}

	// Pre-publish the cold-start snapshot exactly as cmd/splitdnsd/main.go does.
	var mu sync.Mutex
	published := mirror.BaseSnapshot(cfg, revZones)
	publish := func(s *model.Snapshot) { mu.Lock(); published = s; mu.Unlock() }

	builder := mirror.NewBuilder(lister, failResolver{}, cfg, revZones, publish, nil, nil, nil, func(string) {}, nil)

	// BuildOnce must surface an error (not panic) when CF is unreachable.
	if err := builder.BuildOnce(context.Background()); err == nil {
		t.Error("expected BuildOnce to fail with all dependencies down")
	}

	mu.Lock()
	got := published
	mu.Unlock()
	if got == nil {
		t.Fatal("fail-static violated: the published snapshot was cleared")
	}
	if got.ReverseZ["2.0.192.in-addr.arpa."] == nil {
		t.Error("fail-static violated: retained snapshot lost its authoritative reverse zone")
	}
	if len(got.Static["health.splitdnsd.local."]) == 0 {
		t.Error("fail-static violated: retained snapshot lost the liveness record")
	}
}
