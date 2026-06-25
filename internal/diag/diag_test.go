package diag

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

func testSnap() *model.Snapshot {
	z := &model.Zone{
		Apex:              "example.com.",
		LastFetchedSerial: 12345,
		Stale:             true,
		SyntheticStale:    true,
		Records: map[string]map[uint16][]model.RR{
			// Records carry the CF object IDs that MUST be redacted from diag.
			"sip": {dns.TypeA: {{Type: dns.TypeA, Class: dns.ClassINET, TTL: 300, Content: "203.0.113.20", ZoneID: "SECRETZONE", RecordID: "SECRETREC"}}},
		},
		Wildcards: map[uint16][]model.RR{},
		ENT:       map[string]bool{},
		TunnelAddr: map[string]map[uint16][]model.RR{
			"": {dns.TypeA: {{Type: dns.TypeA, Class: dns.ClassINET, TTL: 300, Content: "203.0.113.10", Synthetic: true}}},
		},
	}
	return &model.Snapshot{
		Zones:     map[string]*model.Zone{"example.com.": z},
		ReverseZ:  map[string]*model.RevZone{"2.0.192.in-addr.arpa.": {Apex: "2.0.192.in-addr.arpa."}},
		StubZones: map[string]*model.StubZone{"sub.example.com.": {Apex: "sub.example.com.", Target: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}}},
		VHosts:    map[string]bool{"shop": true},
		VHostV4:   netip.MustParseAddr("198.51.100.7"),
		CFHealthy: false,
		BuiltAt:   time.Unix(1_700_000_000, 0),
	}
}

func startTest(t *testing.T) (string, func()) {
	t.Helper()
	snap := testSnap()
	view := &model.MDNSView{Forward: map[string][]model.RR{"edge": {{Type: dns.TypeA, Content: "192.0.2.50"}}}}
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return view }, "test-1.0", nil)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return "http://" + s.Addr(), func() { s.Shutdown(context.Background()) }
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRedactsCFObjectIDs(t *testing.T) {
	base, stop := startTest(t)
	defer stop()
	for _, path := range []string{"/", "/diag.json"} {
		_, body := get(t, base+path)
		if strings.Contains(body, "SECRETZONE") || strings.Contains(body, "SECRETREC") {
			t.Errorf("%s leaked a CF object ID:\n%s", path, body)
		}
		// But the data R10 needs IS present.
		if !strings.Contains(body, "203.0.113.20") || !strings.Contains(body, "sip") {
			t.Errorf("%s missing expected record data", path)
		}
	}
}

func TestShowsStalenessAndHealth(t *testing.T) {
	base, stop := startTest(t)
	defer stop()
	_, html := get(t, base+"/")
	if !strings.Contains(html, "STALE") || !strings.Contains(html, "SYNTHETIC-STALE") {
		t.Errorf("staleness flags not surfaced:\n%s", html)
	}
	if !strings.Contains(html, "degraded") {
		t.Errorf("degraded CF health not surfaced")
	}
	code, health := get(t, base+"/healthz")
	if code != 200 || !strings.Contains(health, "degraded") {
		t.Errorf("/healthz = %d %q", code, health)
	}
}

func TestJSONShape(t *testing.T) {
	base, stop := startTest(t)
	defer stop()
	_, body := get(t, base+"/diag.json")
	var p map[string]any
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// No ID keys anywhere in the serialized form.
	if strings.Contains(body, "zone_id") || strings.Contains(body, "record_id") {
		t.Errorf("JSON exposes an ID field")
	}
	if p["cf_healthy"] != false {
		t.Errorf("cf_healthy wrong: %v", p["cf_healthy"])
	}
}

func TestReadOnlyRejectsMutations(t *testing.T) {
	base, stop := startTest(t)
	defer stop()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(method, base+"/", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s returned %d, want 405", method, resp.StatusCode)
		}
	}
}

func TestNilSnapshotSafe(t *testing.T) {
	s := New("127.0.0.1:0", func() *model.Snapshot { return nil }, func() *model.MDNSView { return nil }, "t", nil)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	if code, _ := get(t, "http://"+s.Addr()+"/"); code != 200 {
		t.Errorf("nil snapshot must still render, got %d", code)
	}
}
