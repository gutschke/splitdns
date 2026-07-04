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
		Forward:  map[string][]model.RR{"printer": {{Type: dns.TypeA, Content: "192.0.2.9"}}},
		Services: map[string][]string{"printer": {"_ipp._tcp", "_uscan._tcp"}},
	}
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return view }, "t", nil).
		WithMDNSEnrich(func(name string, addrs []netip.Addr) (string, []string, string) {
			return "HP", view.Services[name], "aa:bb:cc:dd:ee:ff · IPv4 · LAN"
		})
	rec := httptest.NewRecorder()
	s.handleRoot(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	body := rec.Body.String()
	// vendor + FRIENDLY labels (not raw types) in a hostmeta sub-line, detail on hover.
	for _, want := range []string{`class="hostmeta"`, "HP", "IPP/AirPrint", "AirScan (eSCL)", `title="aa:bb:cc:dd:ee:ff`} {
		if !strings.Contains(body, want) {
			t.Errorf("mDNS-forward render missing %q", want)
		}
	}
	// raw service types and the old separate columns / identify link must be gone.
	for _, gone := range []string{"_ipp._tcp", "_uscan._tcp", `data-f="services"`, `data-f="vendor"`, `class="hi"`, ">identify<"} {
		if strings.Contains(body, gone) {
			t.Errorf("mDNS-forward render should not contain %q", gone)
		}
	}
}
