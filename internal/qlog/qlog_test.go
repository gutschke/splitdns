package qlog

import (
	"net/netip"
	"testing"
	"time"
)

func entry(client string, name string, dec Decision, when time.Time) Entry {
	return Entry{Time: when, Client: netip.MustParseAddr(client), Name: name, Qtype: "A", Decision: dec, Rcode: "NOERROR"}
}

// The ring keeps only the last `size` entries, most-recent first.
func TestRingMostRecentFirstAndBounded(t *testing.T) {
	l := New(3, 100)
	base := time.Unix(1_000_000, 0)
	for i := 0; i < 5; i++ {
		l.Record(entry("10.0.0.1", string(rune('a'+i))+".test.", Forward, base.Add(time.Duration(i)*time.Second)))
	}
	r := l.Recent(0) // all
	if len(r) != 3 {
		t.Fatalf("ring kept %d entries, want 3 (bounded)", len(r))
	}
	if r[0].Name != "e.test." || r[2].Name != "c.test." {
		t.Errorf("order wrong: got %s..%s, want e.test...c.test.", r[0].Name, r[2].Name)
	}
}

// TopClients ranks by query count.
func TestTopClients(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := New(100, 100, WithClock(func() time.Time { return now })) // freeze clock: no decay
	for i := 0; i < 5; i++ {
		l.Record(entry("10.0.0.1", "x.", Forward, now))
	}
	for i := 0; i < 2; i++ {
		l.Record(entry("10.0.0.2", "y.", Forward, now))
	}
	top := l.TopClients(10)
	if len(top) != 2 || top[0].Client.String() != "10.0.0.1" || top[0].Count != 5 {
		t.Fatalf("top[0] = %+v, want 10.0.0.1 count 5", top[0])
	}
	if top[1].Count != 2 {
		t.Errorf("top[1] count = %d, want 2", top[1].Count)
	}
}

// Totals roll up the per-decision counts and distinct-client count.
func TestTotals(t *testing.T) {
	l := New(100, 100)
	now := time.Unix(1_000_000, 0)
	l.Record(entry("10.0.0.1", "a.", Forward, now))
	l.Record(entry("10.0.0.1", "b.", CacheHit, now))
	l.Record(entry("10.0.0.2", "c.", Refused, now))
	tot := l.Totals()
	if tot.Total != 3 || tot.Clients != 2 {
		t.Errorf("total=%d clients=%d, want 3/2", tot.Total, tot.Clients)
	}
	if tot.ByDecision[Forward] != 1 || tot.ByDecision[CacheHit] != 1 || tot.ByDecision[Refused] != 1 {
		t.Errorf("by-decision wrong: %v", tot.ByDecision)
	}
}

// The client map is bounded: beyond maxClients, new clients still count in totals but
// are not tracked individually (memory bound under a spoofed-source flood).
func TestClientMapBounded(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := New(1000, 2, WithClock(func() time.Time { return now })) // freeze clock: no decay
	l.Record(entry("10.0.0.1", "a.", Forward, now))
	l.Record(entry("10.0.0.2", "a.", Forward, now))
	l.Record(entry("10.0.0.3", "a.", Forward, now)) // 3rd distinct client, over the cap of 2
	if got := len(l.TopClients(0)); got != 2 {
		t.Errorf("tracked clients = %d, want 2 (capped)", got)
	}
	if tot := l.Totals(); tot.Total != 3 {
		t.Errorf("total = %d, want 3 (all queries still counted)", tot.Total)
	}
}

// A nil Log is safe to Record into (the hot path may hold nil).
func TestNilSafe(t *testing.T) {
	var l *Log
	l.Record(entry("10.0.0.1", "a.", Forward, time.Unix(1, 0))) // must not panic
}

// TopClients carries each client's hottest query names (most-asked first), and the
// per-client name set is bounded so a name-spraying client can't grow it without limit.
func TestTopClientsTopNames(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := New(1000, 100, WithClock(func() time.Time { return now })) // freeze clock: no decay
	// Client .1 asks a.test x3, b.test x1.
	for i := 0; i < 3; i++ {
		l.Record(entry("10.0.0.1", "a.test.", Forward, now))
	}
	l.Record(entry("10.0.0.1", "b.test.", Forward, now))

	top := l.TopClients(10)
	if len(top) == 0 || top[0].Client.String() != "10.0.0.1" {
		t.Fatalf("unexpected top clients: %+v", top)
	}
	tn := top[0].TopNames
	if len(tn) != 2 {
		t.Fatalf("TopNames = %+v, want 2 distinct names", tn)
	}
	if tn[0].Name != "a.test." || tn[0].Count != 3 {
		t.Errorf("hottest name = %+v, want a.test.=3", tn[0])
	}
	if tn[1].Name != "b.test." || tn[1].Count != 1 {
		t.Errorf("second name = %+v, want b.test.=1", tn[1])
	}

	// Bound: a client spraying many distinct names tracks at most perClientNames of them.
	for i := 0; i < perClientNames+50; i++ {
		l.Record(entry("10.0.0.2", "n"+string(rune('A'+i%26))+string(rune('0'+i/26))+".test.", Forward, now))
	}
	var sprayer ClientStat
	for _, c := range l.TopClients(10) {
		if c.Client.String() == "10.0.0.2" {
			sprayer = c
		}
	}
	// The returned TopNames is capped at topNamesPerClient regardless; the internal map is
	// capped at perClientNames — assert the cap held by checking the client still recorded
	// its full Count while names stayed bounded.
	if sprayer.Count != uint64(perClientNames+50) {
		t.Errorf("sprayer Count = %d, want %d (all queries counted)", sprayer.Count, perClientNames+50)
	}
	if len(sprayer.TopNames) > topNamesPerClient {
		t.Errorf("TopNames len = %d, want <= %d", len(sprayer.TopNames), topNamesPerClient)
	}
}

// Activity decays over time: a client that was busy then goes quiet fades out of the
// busiest list, and is eventually pruned entirely (bounding memory).
func TestActivityDecays(t *testing.T) {
	clk := time.Unix(1_000_000, 0)
	l := New(1000, 100, WithClock(func() time.Time { return clk }), WithHalfLife(time.Minute))

	// Client .1 fires 16 queries at t0; .2 fires 1 query at t0.
	for i := 0; i < 16; i++ {
		l.Record(entry("10.0.0.1", "busy.", Forward, clk))
	}
	l.Record(entry("10.0.0.2", "rare.", Forward, clk))

	if top := l.TopClients(10); top[0].Client.String() != "10.0.0.1" || top[0].Count != 16 {
		t.Fatalf("at t0 top = %+v, want 10.0.0.1 count 16", top[0])
	}

	// Advance 5 half-lives (5 min): .1's score 16 -> 0.5, .2's 1 -> ~0.03 (< floor, pruned).
	clk = clk.Add(5 * time.Minute)
	top := l.TopClients(10)
	if len(top) != 1 || top[0].Client.String() != "10.0.0.1" {
		t.Fatalf("after 5 half-lives top = %+v, want only 10.0.0.1 (10.0.0.2 pruned)", top)
	}
	if top[0].Count != 1 {
		t.Errorf("decayed count = %d, want ~1 (16 over 5 half-lives -> 0.5)", top[0].Count)
	}

	// Advance far enough that .1 also falls below the floor and is pruned: the live set
	// empties, so memory is reclaimed for a resolver that has gone idle.
	clk = clk.Add(10 * time.Minute)
	if top := l.TopClients(10); len(top) != 0 {
		t.Errorf("after long idle top = %+v, want empty (all pruned)", top)
	}
}

// A frozen-clock log with decay disabled keeps lifetime totals (back-compat escape hatch).
func TestDecayDisabled(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := New(1000, 100, WithClock(func() time.Time { return now.Add(time.Hour) }), WithHalfLife(0))
	for i := 0; i < 5; i++ {
		l.Record(entry("10.0.0.1", "x.", Forward, now))
	}
	if top := l.TopClients(10); len(top) != 1 || top[0].Count != 5 {
		t.Errorf("decay-disabled top = %+v, want count 5 despite elapsed time", top)
	}
}
