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
	l := New(100, 100)
	now := time.Unix(1_000_000, 0)
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
	l := New(1000, 2)
	now := time.Unix(1_000_000, 0)
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
