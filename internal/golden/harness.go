// Package golden is the golden-parity harness (design S26/S27). A fixture describes a
// zone's Cloudflare records plus a list of queries with their EXPECTED answers (as
// canonical RR-presentation strings). The harness feeds the records through the REAL
// pipeline — mockedge Cloudflare → cfapi client → mirror.BuildSnapshot → resolver.Resolve
// — and asserts the produced answer/authority RRsets match the golden byte-for-byte. This
// is what pins behavioral parity across changes: the synthetic fixtures in testdata/ lock
// the resolution quirks the design must preserve, and an operator can drop real captured
// goldens in local/goldens/ (gitignored) for true production-parity checks.
//
// Set SPLITDNS_GOLDEN_UPDATE=1 to regenerate a fixture's expected fields from the
// current resolver output (then review the diff before committing).
package golden

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/cfapi"
	"github.com/gutschke/splitdns/internal/config"
	"github.com/gutschke/splitdns/internal/mirror"
	"github.com/gutschke/splitdns/internal/mockedge"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/resolver"
)

// Fixture is one golden case.
type Fixture struct {
	Description  string                `json:"description"`
	Config       FixtureConfig         `json:"config"`
	Zones        []FixtureZone         `json:"zones"`
	TunnelAddrs  map[string]TunnelAddr `json:"tunnel_addrs,omitempty"`
	ReverseZones []string              `json:"reverse_zones,omitempty"`
	Queries      []Query               `json:"queries"`
}

type FixtureConfig struct {
	LocalZones     []string `json:"local_zones"`
	VHostV4        string   `json:"vhost_v4,omitempty"`
	VHostV6        string   `json:"vhost_v6,omitempty"`
	VHosts         []string `json:"vhosts,omitempty"`          // known single-label vhost owners
	ExcludeZones   []string `json:"exclude_zones,omitempty"`   // apexes not subject to vhost redirect
	TunnelSuffixes []string `json:"tunnel_suffixes,omitempty"` // CNAME-target suffixes to flatten
}

type FixtureZone struct {
	Name    string          `json:"name"`
	ID      string          `json:"id"`
	Records []FixtureRecord `json:"records"`
}

type FixtureRecord struct {
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Content  string  `json:"content"`
	Proxied  bool    `json:"proxied,omitempty"`
	TTL      int     `json:"ttl,omitempty"`
	Priority float64 `json:"priority,omitempty"`
}

type TunnelAddr struct {
	V4 []string `json:"v4,omitempty"`
	V6 []string `json:"v6,omitempty"`
}

// Query is one question and its expected outcome. Outcome defaults to "answer"
// (the resolver replies directly); "forward"/"stub" assert the routing decision.
type Query struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Outcome   string   `json:"outcome,omitempty"`
	Rcode     string   `json:"rcode,omitempty"`
	AA        bool     `json:"aa,omitempty"`
	Answer    []string `json:"answer,omitempty"`
	Authority []string `json:"authority,omitempty"`
}

// Run executes every query in the fixture at path and asserts (or, in update mode,
// records) the expected output.
func Run(t *testing.T, path string) {
	t.Helper()
	fx := load(t, path)
	snap := buildSnapshot(t, fx)
	view := &model.MDNSView{}
	update := os.Getenv("SPLITDNS_GOLDEN_UPDATE") == "1"
	changed := false

	for i := range fx.Queries {
		q := &fx.Queries[i]
		qtype, ok := dns.StringToType[strings.ToUpper(q.Type)]
		if !ok {
			t.Errorf("%s: unknown qtype %q", q.Name, q.Type)
			continue
		}
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(q.Name), qtype)
		out := resolver.Resolve(snap, view, req)

		outcome := q.Outcome
		if outcome == "" {
			outcome = "answer"
		}
		switch outcome {
		case "forward":
			if !out.Forward {
				t.Errorf("%s %s: expected FORWARD, got %s", q.Name, q.Type, describe(out))
			}
			continue
		case "stub":
			if len(out.Stub) == 0 {
				t.Errorf("%s %s: expected STUB, got %s", q.Name, q.Type, describe(out))
			}
			continue
		}
		if out.Msg == nil {
			t.Errorf("%s %s: expected a direct answer, got %s", q.Name, q.Type, describe(out))
			continue
		}
		gotRcode := dns.RcodeToString[out.Msg.Rcode]
		gotAns := renderRRs(out.Msg.Answer)
		gotNs := renderRRs(out.Msg.Ns)

		if update {
			q.Rcode, q.AA, q.Answer, q.Authority = gotRcode, out.Msg.Authoritative, gotAns, gotNs
			changed = true
			continue
		}
		if gotRcode != q.Rcode {
			t.Errorf("%s %s: rcode = %s, want %s", q.Name, q.Type, gotRcode, q.Rcode)
		}
		if out.Msg.Authoritative != q.AA {
			t.Errorf("%s %s: AA = %v, want %v", q.Name, q.Type, out.Msg.Authoritative, q.AA)
		}
		if want := sortedCopy(q.Answer); !reflect.DeepEqual(gotAns, want) {
			t.Errorf("%s %s: ANSWER mismatch\n  want %v\n  got  %v", q.Name, q.Type, want, gotAns)
		}
		if want := sortedCopy(q.Authority); !reflect.DeepEqual(gotNs, want) {
			t.Errorf("%s %s: AUTHORITY mismatch\n  want %v\n  got  %v", q.Name, q.Type, want, gotNs)
		}
	}

	if update && changed {
		writeFixture(t, path, fx)
		t.Logf("%s: updated golden expectations", path)
	}
}

// buildSnapshot runs the fixture's records through the real mirror pipeline.
func buildSnapshot(t *testing.T, fx Fixture) *model.Snapshot {
	t.Helper()
	cf := mockedge.NewCloudflare("tok")
	for _, z := range fx.Zones {
		cf.AddZone(z.ID, z.Name)
		for _, r := range z.Records {
			cf.Seed(z.ID, mockedge.CFRecord{
				Type: r.Type, Name: r.Name, Content: r.Content,
				Proxied: r.Proxied, TTL: r.TTL, Priority: r.Priority,
			})
		}
	}
	srv := cf.Start()
	t.Cleanup(srv.Close)

	lister := cfapi.New(srv.URL, "tok", srv.Client())
	cfg := config.Default()
	cfg.Zones.Local = fx.Config.LocalZones
	cfg.VHost.ProxyV4 = fx.Config.VHostV4
	cfg.VHost.ProxyV6 = fx.Config.VHostV6
	cfg.VHost.ExcludeZones = fx.Config.ExcludeZones
	cfg.Cloudflare.TunnelSuffixes = fx.Config.TunnelSuffixes

	snap, err := mirror.BuildSnapshot(context.Background(), lister, fixtureResolver(fx.TunnelAddrs), cfg, fx.ReverseZones)
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}
	// VHost owners arrive via the feed worker in production; set them from the fixture.
	snap.VHosts = map[string]bool{}
	for _, v := range fx.Config.VHosts {
		snap.VHosts[v] = true
	}
	return snap
}

// fixtureResolver answers tunnel flattening from the fixture's map (keyed by owner
// fqdn, with or without the trailing dot).
type fixtureResolver map[string]TunnelAddr

func (f fixtureResolver) Resolve(_ context.Context, fqdn string) (v4, v6 []netip.Addr, err error) {
	ta, ok := f[fqdn]
	if !ok {
		ta, ok = f[strings.TrimSuffix(fqdn, ".")]
	}
	if !ok {
		return nil, nil, fmt.Errorf("golden: no tunnel addrs for %s", fqdn)
	}
	for _, s := range ta.V4 {
		if a, e := netip.ParseAddr(s); e == nil {
			v4 = append(v4, a)
		}
	}
	for _, s := range ta.V6 {
		if a, e := netip.ParseAddr(s); e == nil {
			v6 = append(v6, a)
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		return nil, nil, fmt.Errorf("golden: empty tunnel addrs for %s", fqdn)
	}
	return v4, v6, nil
}

func renderRRs(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if rr != nil {
			out = append(out, rr.String())
		}
	}
	sort.Strings(out)
	return out
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func describe(o resolver.Outcome) string {
	switch {
	case o.Msg != nil:
		return "answer rcode=" + dns.RcodeToString[o.Msg.Rcode]
	case o.Forward:
		return "forward"
	case len(o.Stub) > 0:
		return "stub"
	default:
		return "none"
	}
}

func load(t *testing.T, path string) Fixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx Fixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	return fx
}

func writeFixture(t *testing.T, path string, fx Fixture) {
	t.Helper()
	data, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
