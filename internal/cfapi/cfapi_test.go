package cfapi

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/ddns"
	"github.com/gutschke/splitdns/internal/mockedge"
)

func TestRecordsForHostAcrossZones(t *testing.T) {
	m := mockedge.NewCloudflare("test-token")
	m.AddZone("zA", "example.com")
	m.AddZone("zB", "example.net")
	m.Seed("zA", mockedge.CFRecord{Type: "A", Name: "edge.example.com", Content: "1.1.1.1"})
	m.Seed("zA", mockedge.CFRecord{Type: "AAAA", Name: "edge.example.com", Content: "2001:4860:4860::8888"})
	m.Seed("zA", mockedge.CFRecord{Type: "A", Name: "edge.example.com", Content: "1.2.3.4", Proxied: true}) // excluded
	m.Seed("zA", mockedge.CFRecord{Type: "A", Name: "other.example.com", Content: "5.5.5.5"})               // wrong name
	m.Seed("zB", mockedge.CFRecord{Type: "A", Name: "edge.example.net", Content: "9.9.9.9"})

	srv := m.Start()
	defer srv.Close()
	c := New(srv.URL, "test-token", srv.Client())

	recs, err := c.RecordsForHost(context.Background(), "edge")
	if err != nil {
		t.Fatalf("RecordsForHost: %v", err)
	}
	got := map[string]bool{}
	for _, r := range recs {
		got[r.Content] = true
		if r.Proxied {
			t.Errorf("proxied record leaked: %+v", r)
		}
		if r.Type != dns.TypeA && r.Type != dns.TypeAAAA {
			t.Errorf("non-A/AAAA leaked: %+v", r)
		}
	}
	for _, want := range []string{"1.1.1.1", "2001:4860:4860::8888", "9.9.9.9"} {
		if !got[want] {
			t.Errorf("missing expected record %s; got %v", want, got)
		}
	}
	if got["1.2.3.4"] || got["5.5.5.5"] {
		t.Errorf("returned a record it should have excluded: %v", got)
	}
}

func TestEditorCRUD(t *testing.T) {
	m := mockedge.NewCloudflare("test-token")
	m.AddZone("zA", "example.com")
	srv := m.Start()
	defer srv.Close()
	c := New(srv.URL, "test-token", srv.Client())
	ctx := context.Background()

	id, err := c.Create(ctx, "zA", "edge.example.com.", dns.TypeA, "1.1.1.1")
	if err != nil || id == "" {
		t.Fatalf("Create: id=%q err=%v", id, err)
	}
	if err := c.Update(ctx, "zA", id, "edge.example.com.", dns.TypeA, "9.9.9.9"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if cs := m.ContentsForZone("zA"); len(cs) != 1 || cs[0] != "9.9.9.9" {
		t.Fatalf("after update want [9.9.9.9], got %v", cs)
	}
	if err := c.Delete(ctx, "zA", id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if cs := m.ContentsForZone("zA"); len(cs) != 0 {
		t.Fatalf("after delete want empty, got %v", cs)
	}
	// The mutation log records exactly the create/update/delete sequence.
	muts := m.Mutations()
	if len(muts) != 3 || muts[0].Op != "create" || muts[1].Op != "update" || muts[2].Op != "delete" {
		t.Errorf("unexpected mutation log: %+v", muts)
	}
}

func TestBadTokenSurfacesError(t *testing.T) {
	m := mockedge.NewCloudflare("good")
	m.AddZone("zA", "example.com")
	srv := m.Start()
	defer srv.Close()
	c := New(srv.URL, "wrong", srv.Client())
	if _, err := c.Zones(context.Background()); err == nil {
		t.Fatal("expected error for bad token")
	}
}

// TestAllRecordsPagination drives the real client's page-drain loop against the
// mock's genuine pagination (the old mock hardcoded total_pages=1, so this path was
// never exercised — see finding D28).
func TestAllRecordsPagination(t *testing.T) {
	m := mockedge.NewCloudflare("tok")
	m.AddZone("zA", "example.com")
	const n = 250 // > the client's per_page=100 → 3 pages
	for i := 0; i < n; i++ {
		m.Seed("zA", mockedge.CFRecord{Type: "A", Name: fmt.Sprintf("h%d.example.com", i), Content: "192.0.2.1"})
	}
	srv := m.Start()
	defer srv.Close()
	c := New(srv.URL, "tok", srv.Client())

	recs, err := c.AllRecords(context.Background(), "zA")
	if err != nil {
		t.Fatalf("AllRecords: %v", err)
	}
	if len(recs) != n {
		t.Fatalf("pagination drain returned %d records, want %d", len(recs), n)
	}
}

// TestWriterEndToEndAgainstMockCF exercises the REAL ddns.Writer driving the REAL
// cfapi.Client against the mock Cloudflare: a change is applied, the store reflects
// it, and a second identical change is a no-op (read-after-write idempotency).
func TestWriterEndToEndAgainstMockCF(t *testing.T) {
	m := mockedge.NewCloudflare("edit-token")
	m.AddZone("zA", "example.com")
	m.Seed("zA", mockedge.CFRecord{Type: "A", Name: "edge.example.com", Content: "1.1.1.1"})

	srv := m.Start()
	defer srv.Close()
	c := New(srv.URL, "edit-token", srv.Client())

	now := time.Unix(2_000_000, 0)
	w := ddns.New(
		ddns.Config{Enabled: true, DryRun: false, Rate: 0, TokenID: "edit-token-id",
			Eligible: map[string]bool{"edge.example.com": true}},
		c, c, nil, func() time.Time { return now }, nil,
	)

	out, err := w.Reconcile(context.Background(), ddns.Change{Host: "edge", Addrs: mustAddrs("9.9.9.9")})
	if err != nil || out != ddns.OutcomeApplied {
		t.Fatalf("first reconcile: out=%v err=%v", out, err)
	}
	if cs := m.ContentsForZone("zA"); len(cs) != 1 || cs[0] != "9.9.9.9" {
		t.Fatalf("store after apply: want [9.9.9.9], got %v", cs)
	}

	out2, err := w.Reconcile(context.Background(), ddns.Change{Host: "edge", Addrs: mustAddrs("9.9.9.9")})
	if err != nil || out2 != ddns.OutcomeUnchanged {
		t.Fatalf("second reconcile should be unchanged: out=%v err=%v", out2, err)
	}
}

func mustAddrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}
