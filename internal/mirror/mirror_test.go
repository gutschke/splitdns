package mirror

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/cfapi"
	"github.com/gutschke/splitdns/internal/config"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/resolver"
)

type fakeLister struct {
	zones map[string]string
	recs  map[string][]cfapi.Record
}

func (f fakeLister) Zones(context.Context) (map[string]string, error) { return f.zones, nil }
func (f fakeLister) AllRecords(_ context.Context, id string) ([]cfapi.Record, error) {
	return f.recs[id], nil
}

// fakeTunnel returns fixed flattened addresses for any owner/sentinel.
type fakeTunnel struct{}

func (fakeTunnel) Resolve(context.Context, string) ([]netip.Addr, []netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		[]netip.Addr{netip.MustParseAddr("2001:db8::10")}, nil
}

func exampleRecords() []cfapi.Record {
	return []cfapi.Record{
		{ID: "r1", Type: "CNAME", Name: "example.com", Content: "tunnel.cfargotunnel.com", Proxied: true},
		{ID: "r2", Type: "MX", Name: "example.com", Content: "mail.example.com", Priority: 10, TTL: 3600},
		{ID: "r3", Type: "NS", Name: "example.com", Content: "ns.example.com", TTL: 86400},
		{ID: "r4", Type: "CNAME", Name: "*.example.com", Content: "tunnel.cfargotunnel.com", Proxied: true},
		{ID: "r5", Type: "A", Name: "sip.example.com", Content: "203.0.113.20", TTL: 300},
		{ID: "r6", Type: "A", Name: "smtp.example.com", Content: "203.0.113.30", TTL: 300},
		{ID: "r7", Type: "TLSA", Name: "_25._tcp.smtp.example.com", Content: "3 1 1 0123456789abcdef", TTL: 300},
		{ID: "r8", Type: "TXT", Name: "example.com", Content: "v=spf1 -all", TTL: 300},
	}
}

func buildExample(t *testing.T) *model.Zone {
	t.Helper()
	return BuildZone(context.Background(), "example.com", "zE", exampleRecords(), fakeTunnel{}, []string{".cfargotunnel.com."})
}

func TestBuildZoneFlattensTunnel(t *testing.T) {
	z := buildExample(t)
	// Apex tunnel CNAME flattened to TunnelAddr, never stored as a CNAME.
	if len(z.TunnelAddr[""][dns.TypeA]) != 1 || z.TunnelAddr[""][dns.TypeA][0].Content != "203.0.113.10" {
		t.Fatalf("apex tunnel A not flattened: %+v", z.TunnelAddr[""])
	}
	if len(z.TunnelAddr["*"][dns.TypeAAAA]) != 1 {
		t.Fatalf("wildcard tunnel AAAA not flattened: %+v", z.TunnelAddr["*"])
	}
	if _, ok := z.Records[""][dns.TypeCNAME]; ok {
		t.Errorf("flattened apex CNAME must not be stored in Records")
	}
	if _, ok := z.Wildcards[dns.TypeCNAME]; ok {
		t.Errorf("flattened wildcard CNAME must not be stored in Wildcards")
	}
}

func TestBuildZoneMXRecombine(t *testing.T) {
	z := buildExample(t)
	mx := z.Records[""][dns.TypeMX]
	if len(mx) != 1 {
		t.Fatalf("want 1 apex MX, got %d", len(mx))
	}
	rr, err := mx[0].ToMiekg()
	if err != nil {
		t.Fatalf("MX render: %v", err)
	}
	if m, ok := rr.(*dns.MX); !ok || m.Preference != 10 || m.Mx != "mail.example.com." {
		t.Errorf("MX recombine wrong: %v", rr)
	}
}

func TestBuildZoneENT(t *testing.T) {
	z := buildExample(t)
	// smtp is a real owner; _tcp.smtp is an interior node => ENT.
	if !z.ENT["_tcp.smtp"] {
		t.Errorf("_tcp.smtp should be an ENT, ENT set = %v", z.ENT)
	}
	if z.ENT["smtp"] {
		t.Errorf("smtp is a real owner, must NOT be an ENT")
	}
}

func TestBuildZoneTXTAndSOA(t *testing.T) {
	z := buildExample(t)
	if z.SOA.Type != dns.TypeSOA {
		t.Errorf("zone must carry a synthesized SOA")
	}
	txt := z.Records[""][dns.TypeTXT]
	if len(txt) != 1 {
		t.Fatalf("want 1 apex TXT")
	}
	if _, err := txt[0].ToMiekg(); err != nil {
		t.Errorf("TXT must render (quoting): %v", err)
	}
}

func TestBuildSnapshotAndResolve(t *testing.T) {
	cfg := config.Config{Zones: config.ZonesConfig{Local: []string{"example.com"}}}
	l := fakeLister{zones: map[string]string{"zE": "example.com"}, recs: map[string][]cfapi.Record{"zE": exampleRecords()}}

	snap, err := BuildSnapshot(context.Background(), l, fakeTunnel{}, cfg, nil)
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}
	if !snap.CFHealthy {
		t.Errorf("snapshot should be marked CFHealthy after a successful build")
	}
	view := &model.MDNSView{Forward: map[string][]model.RR{}, Reverse: map[string][]model.RR{}}

	// Run the real resolver against the mirror-built snapshot.
	ask := func(name string, qtype uint16) *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(name), qtype)
		return resolver.Resolve(snap, view, req).Msg
	}
	// Exact owner.
	if m := ask("sip.example.com.", dns.TypeA); len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "203.0.113.20" {
		t.Errorf("sip A from mirror snapshot = %v", m.Answer)
	}
	// Wildcard synthesizes the flattened tunnel address.
	if m := ask("randomlabel.example.com.", dns.TypeA); len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "203.0.113.10" {
		t.Errorf("wildcard A from mirror snapshot = %v", m.Answer)
	}
	// ENT suppresses the wildcard => NODATA.
	if m := ask("_tcp.smtp.example.com.", dns.TypeA); m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Errorf("ENT _tcp.smtp should be NODATA, got rcode=%d ans=%v", m.Rcode, m.Answer)
	}
}

func TestSnapshotSourceForDDNS(t *testing.T) {
	cfg := config.Config{Zones: config.ZonesConfig{Local: []string{"example.com"}}}
	l := fakeLister{zones: map[string]string{"zE": "example.com"}, recs: map[string][]cfapi.Record{"zE": exampleRecords()}}
	snap, _ := BuildSnapshot(context.Background(), l, fakeTunnel{}, cfg, nil)

	src := SnapshotSource{Get: func() *model.Snapshot { return snap }}
	recs, err := src.RecordsForHost(context.Background(), "sip")
	if err != nil {
		t.Fatalf("RecordsForHost: %v", err)
	}
	if len(recs) != 1 || recs[0].Content != "203.0.113.20" || recs[0].ZoneID != "zE" || recs[0].RecordID != "r5" {
		t.Fatalf("snapshot DDNS source wrong: %+v", recs)
	}
}
