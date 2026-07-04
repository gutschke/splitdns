package diag

import (
	"testing"

	"github.com/gutschke/splitdns/internal/model"
)

func TestLookupHostServices(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan"}
	view := &model.MDNSView{Services: map[string][]model.MDNSService{
		"printer": {{Type: "_ipp._tcp", Port: 631, Text: []string{"ty=Acme"}}},
	}}
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return view }, "t", nil)

	got := s.lookupHostServices("printer.lan")
	if len(got) != 1 || got[0].Name != "printer._ipp._tcp.lan" || got[0].Port != 631 || got[0].Label != "IPP/AirPrint" {
		t.Errorf("services = %+v, want IPP/AirPrint at printer._ipp._tcp.lan:631", got)
	}
	// .local suffix works too
	if g := s.lookupHostServices("printer.local"); len(g) != 1 || g[0].Name != "printer._ipp._tcp.local" {
		t.Errorf("local suffix = %+v", g)
	}
	// no clutter for non-local names or hosts with no services
	if s.lookupHostServices("example.com") != nil {
		t.Error("non-local name should return nil")
	}
	if s.lookupHostServices("unknown.lan") != nil {
		t.Error("host with no services should return nil")
	}
}
