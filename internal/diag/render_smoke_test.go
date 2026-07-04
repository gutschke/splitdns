package diag

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/gutschke/splitdns/internal/model"
	"github.com/miekg/dns"
)

func TestRootRendersConfigPanelAndBadge(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan"}
	view := &model.MDNSView{Forward: map[string][]model.RR{"56442ef43e60884b27a10de08f8fa439": {{Type: 1, Content: "192.0.2.9"}}}}
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return view }, "t", nil).WithConfigFile("/dev/null")
	rec := httptest.NewRecorder()
	s.handleRoot(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "cfgpanel") {
		t.Error("config panel missing from render")
	}
	if !strings.Contains(body, `<span class="badge">id</span>`) {
		t.Error("id badge missing for a machine-id host")
	}
}

// The mDNS-forward panel folds vendor + friendly service labels into a sub-line under the
// host name (no separate columns, no lazy "identify"), with MAC/scope on hover.
func TestMDNSForwardEnrichmentInline(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan"}
	view := &model.MDNSView{
		Forward: map[string][]model.RR{"printer": {{Type: dns.TypeA, Content: "192.0.2.9"}}},
		Services: map[string][]model.MDNSService{"printer": {
			{Type: "_ipp._tcp", Port: 631, Text: []string{"rp=ipp/print", "ty=HP LaserJet MFP M281fdw"}},
			{Type: "_uscan._tcp"},
		}},
		Info: map[string]string{"printer": "HP LaserJet MFP M281fdw"},
	}
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return view }, "t", nil).
		WithMDNSEnrich(func(name string, addrs []netip.Addr) (string, string, []model.MDNSService, string) {
			return "HP", view.Info[name], view.Services[name], "aa:bb:cc:dd:ee:ff · IPv4 · LAN"
		})
	rec := httptest.NewRecorder()
	s.handleRoot(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	body := rec.Body.String()
	// model (TXT) + friendly labels with PORTS on a FULL-WIDTH (colspan) meta row; the
	// whole row carries a hover title with MAC/scope AND the raw TXT key=values.
	for _, want := range []string{
		`class="hostrow"`, `class="hostmeta" data-f="meta" colspan="2"`,
		"HP LaserJet MFP M281fdw", "IPP/AirPrint:631", "AirScan (eSCL)",
		`data-tip="aa:bb:cc:dd:ee:ff`, "rp=ipp/print",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("mDNS-forward render missing %q", want)
		}
	}
	// raw service types on the visible line and the old columns / identify link must be gone.
	for _, gone := range []string{"_ipp._tcp", "_uscan._tcp", `data-f="services"`, `data-f="vendor"`, `class="hi"`, ">identify<"} {
		if strings.Contains(body, gone) {
			t.Errorf("mDNS-forward render should not contain %q", gone)
		}
	}
}
