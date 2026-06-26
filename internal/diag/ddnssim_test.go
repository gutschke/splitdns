package diag

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gutschke/splitdns/internal/anscache"
	"github.com/gutschke/splitdns/internal/ddns"
	"github.com/gutschke/splitdns/internal/model"
)

func TestDDNSSimulateEndpoint(t *testing.T) {
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	var gotHost string
	var gotAddrs []netip.Addr
	var gotExplore bool
	s.WithDDNSSimulate(func(_ context.Context, host string, addrs []netip.Addr, ignoreEligible bool) ddns.SimResult {
		gotHost, gotAddrs, gotExplore = host, addrs, ignoreEligible
		return ddns.SimResult{Host: host, Outcome: "would-apply", Override: ignoreEligible, Calls: []ddns.SimCall{{Op: "update", Name: "edge.example.", Type: "A", Content: "8.8.8.8", Old: "1.1.1.1"}}}
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	base := "http://" + s.Addr()

	if code, _ := get(t, base+"/ddns-simulate"); code != http.StatusBadRequest {
		t.Errorf("missing host: status = %d, want 400", code)
	}
	code, body := get(t, base+"/ddns-simulate?host=edge&addr=8.8.8.8")
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.Contains(body, "would-apply") || !strings.Contains(body, "8.8.8.8") {
		t.Errorf("body missing outcome/call: %s", body)
	}
	if gotHost != "edge" || len(gotAddrs) != 1 || gotAddrs[0] != netip.MustParseAddr("8.8.8.8") {
		t.Errorf("provider got host=%q addrs=%v, want edge / [8.8.8.8]", gotHost, gotAddrs)
	}
	if gotExplore {
		t.Error("default (no explore param) must NOT be explore mode")
	}
	// Explore mode: param threads through; JSON marks it; HTML shows the banner.
	clearRate := func() { s.ctlMu.Lock(); s.ctlLast = map[string]time.Time{}; s.ctlMu.Unlock() }
	clearRate()
	_, exJSON := get(t, base+"/ddns-simulate?host=edge&addr=8.8.8.8&explore=1")
	if !gotExplore {
		t.Error("explore=1 must reach the provider as ignoreEligible=true")
	}
	if !strings.Contains(exJSON, `"override": true`) {
		t.Errorf("explore JSON missing override flag: %s", exJSON)
	}
	clearRate()
	req, _ := http.NewRequest("GET", base+"/ddns-simulate?host=edge&addr=8.8.8.8&explore=1", nil)
	req.Header.Set("Accept", "text/html")
	resp, _ := http.DefaultClient.Do(req)
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	resp.Body.Close()
	exHTML := string(buf[:n])
	if !strings.Contains(exHTML, "EXPLORE mode") || !strings.Contains(exHTML, "not what runs today") {
		t.Errorf("explore HTML missing the EXPLORE banner: %s", exHTML)
	}
	// The calls table explains execution order + why deletes happen.
	if !strings.Contains(exHTML, "no NXDOMAIN gap") || !strings.Contains(exHTML, "converges") {
		t.Errorf("explore HTML missing the order/convergence explanation: %s", exHTML)
	}
	// The page advertises both modes as explicit buttons.
	_, html := get(t, base+"/")
	for _, want := range []string{`action="/ddns-simulate"`, `value=""`, `value="1"`, "As configured", "ignore allowlist"} {
		if !strings.Contains(html, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

// The page ships the live-update machinery (polls /diag.json, tags live regions).
func TestLiveUpdateMarkup(t *testing.T) {
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	s.WithCacheStats(func() (anscache.Stats, bool) { return anscache.Stats{Capacity: 10}, true })
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	_, html := get(t, "http://"+s.Addr()+"/")
	for _, want := range []string{`fetch('/diag.json'`, `visibilitychange`, `getSelection`, `data-live="answer_cache"`, `data-f="hits"`, `data-live="mdns_forward"`, `data-live="mdns_reverse"`} {
		if !strings.Contains(html, want) {
			t.Errorf("live-update markup missing %q", want)
		}
	}
	// Reorganized layout: sticky health strip + in-page nav, sectioned bands, and a
	// collapsed reference band. These guard the restructure against silent flattening.
	for _, want := range []string{`class="topbar"`, `id="health"`, `id="chip-mirror"`, `<nav class="toc">`, `<section id="cache">`, `<section id="reference">`, `<details>`} {
		if !strings.Contains(html, want) {
			t.Errorf("reorganized layout missing %q", want)
		}
	}
}
