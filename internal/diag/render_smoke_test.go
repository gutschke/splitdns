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

// The mDNS-forward panel shows vendor + services inline (no click), and the old lazy
// "identify" link is gone.
func TestMDNSForwardEnrichmentInline(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan"}
	view := &model.MDNSView{
		Forward:  map[string][]model.RR{"printer": {{Type: dns.TypeA, Content: "192.0.2.9"}}},
		Services: map[string][]string{"printer": {"_ipp._tcp"}},
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
	for _, want := range []string{`data-f="vendor"`, ">HP<", `data-f="services"`, "_ipp._tcp", "aa:bb:cc:dd:ee:ff"} {
		if !strings.Contains(body, want) {
			t.Errorf("mDNS-forward render missing %q", want)
		}
	}
	if strings.Contains(body, `class="hi"`) || strings.Contains(body, ">identify<") {
		t.Error("the lazy identify link should be gone")
	}
}
