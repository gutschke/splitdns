package ddns

import (
	"context"
	"strings"
	"testing"

	"github.com/gutschke/splitdns/internal/model"
)

func sim(src RecordSource, host string, cfg Config, addrList ...string) SimResult {
	return Simulate(context.Background(), cfg, src, Change{Host: host, Addrs: addrs(addrList...)}, false)
}

func simExplore(src RecordSource, host string, cfg Config, addrList ...string) SimResult {
	return Simulate(context.Background(), cfg, src, Change{Host: host, Addrs: addrs(addrList...)}, true)
}

// Current records already match the announcement => no calls.
func TestSimulateUnchanged(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "8.8.8.8")}}}
	res := sim(src, "edge", Config{}, "8.8.8.8")
	if res.Outcome != "unchanged" || len(res.Calls) != 0 {
		t.Errorf("res = %+v, want unchanged with no calls", res)
	}
}

// A changed address => one update call carrying old->new (no CF IDs leaked).
func TestSimulateUpdate(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	res := sim(src, "edge", Config{Enabled: true, DryRun: true}, "8.8.8.8")
	if res.Outcome != "would-apply" || len(res.Calls) != 1 {
		t.Fatalf("res = %+v, want would-apply with one call", res)
	}
	c := res.Calls[0]
	if c.Op != "update" || c.Type != "A" || c.Content != "8.8.8.8" || c.Old != "1.1.1.1" {
		t.Errorf("call = %+v, want update A 1.1.1.1->8.8.8.8", c)
	}
	if !res.Enabled || !res.DryRun {
		t.Errorf("flags = enabled:%v dryrun:%v, want true/true", res.Enabled, res.DryRun)
	}
}

// A new address family => a create call.
func TestSimulateCreate(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	res := sim(src, "edge", Config{}, "1.1.1.1", "2606:4700:4700::1111")
	if res.Outcome != "would-apply" {
		t.Fatalf("outcome = %s, want would-apply", res.Outcome)
	}
	var creates int
	for _, c := range res.Calls {
		if c.Op == "create" {
			creates++
			if c.Type != "AAAA" {
				t.Errorf("create type = %s, want AAAA", c.Type)
			}
		}
	}
	if creates != 1 {
		t.Errorf("creates = %d, want 1", creates)
	}
}

// A purely-private announcement is a no-op (never deletes existing records).
func TestSimulateNoPublic(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	res := sim(src, "edge", Config{}, "192.168.1.5")
	if res.Outcome != "no-public-addrs" || len(res.Calls) != 0 {
		t.Errorf("res = %+v, want no-public-addrs", res)
	}
}

// No eligible records (host unknown, or filtered by the allowlist) => not-eligible.
func TestSimulateNotEligible(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	ghost := sim(src, "ghost", Config{}, "8.8.8.8")
	if ghost.Outcome != "not-eligible" {
		t.Errorf("unknown host outcome = %s, want not-eligible", ghost.Outcome)
	}
	// The note must teach the update-only / A-AAAA-only model (no host creation, no MX).
	if !strings.Contains(ghost.Note, "UPDATES") || !strings.Contains(ghost.Note, "MX") {
		t.Errorf("no-records note should explain DDNS only updates existing A/AAAA (not MX/creation): %q", ghost.Note)
	}
	// Even in Explore, a host with no records stays not-eligible (creation is not a thing).
	if res := simExplore(src, "ghost", Config{}, "8.8.8.8"); res.Outcome != "not-eligible" {
		t.Errorf("explore of a record-less host = %s, want not-eligible (DDNS never creates hostnames)", res.Outcome)
	}
	// Allowlist excludes the host's records.
	cfg := Config{Eligible: map[string]bool{"other.example.com": true}}
	if res := sim(src, "edge", cfg, "8.8.8.8"); res.Outcome != "not-eligible" {
		t.Errorf("allowlist-excluded outcome = %s, want not-eligible", res.Outcome)
	}
}

// Explore mode bypasses the eligibility allowlist so an admin can see the plan before
// the host is allowlisted; "as configured" still reports not-eligible for the same host.
func TestSimulateExploreBypassesAllowlist(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	cfg := Config{Eligible: map[string]bool{"other.example.com": true}} // edge NOT allowlisted

	// As configured: not-eligible (and the note points at Explore).
	asConf := sim(src, "edge", cfg, "8.8.8.8")
	if asConf.Outcome != "not-eligible" || asConf.Override {
		t.Fatalf("as-configured = %+v, want not-eligible / not override", asConf)
	}
	if !strings.Contains(asConf.Note, "Explore") {
		t.Errorf("as-configured note should point at Explore: %q", asConf.Note)
	}

	// Explore: would-apply, marked Override, with a clear what-if note.
	ex := simExplore(src, "edge", cfg, "8.8.8.8")
	if ex.Outcome != "would-apply" || !ex.Override || len(ex.Calls) != 1 {
		t.Fatalf("explore = %+v, want would-apply / override / 1 call", ex)
	}
	if !strings.Contains(ex.Note, "EXPLORE ONLY") || !strings.Contains(ex.Note, "eligible") {
		t.Errorf("explore note should flag it as a what-if: %q", ex.Note)
	}
}

// The public-address safety filter is NEVER bypassed, even in explore mode.
func TestSimulateExploreStillDropsPrivate(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "8.8.8.8")}}}
	res := simExplore(src, "edge", Config{}, "192.168.1.5")
	if res.Outcome != "no-public-addrs" {
		t.Errorf("explore with a private addr = %s, want no-public-addrs (filter never bypassed)", res.Outcome)
	}
}

// An empty allowlist reports effective dry-run + a note telling the admin nothing real
// happens until they populate eligible (the exact pre-setup situation).
func TestSimulateEmptyAllowlistEffectiveDryRun(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	res := sim(src, "edge", Config{Enabled: true, DryRun: false}, "8.8.8.8") // eligible empty
	if res.Outcome != "would-apply" || !res.DryRun {
		t.Fatalf("res = %+v, want would-apply with effective dry-run", res)
	}
	if !strings.Contains(res.Note, "empty") || !strings.Contains(res.Note, "eligible") {
		t.Errorf("note should explain the empty-allowlist forced dry-run: %q", res.Note)
	}
}

// Simulate never writes, even with an Editor available — it only reads the source.
func TestSimulateDoesNotWrite(t *testing.T) {
	src := &fakeSource{recs: map[string][]model.RR{"edge": {rr("z1", "r1", "edge.example.com.", "1.1.1.1")}}}
	// (Simulate takes no Editor at all — this just asserts the read-only outcome shape.)
	res := sim(src, "edge", Config{Enabled: false}, "8.8.8.8")
	if res.Outcome != "would-apply" || res.Enabled {
		t.Errorf("res = %+v, want would-apply with enabled=false (works while disabled)", res)
	}
}
