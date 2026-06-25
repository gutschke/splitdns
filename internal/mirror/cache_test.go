package mirror

import (
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

func sampleZones() map[string]*model.Zone {
	z := &model.Zone{
		ID:   "zE",
		Apex: "example.com.",
		SOA:  synthSOA("example.com."),
		Records: map[string]map[uint16][]model.RR{
			"sip": {dns.TypeA: {{Type: dns.TypeA, Class: dns.ClassINET, TTL: 300, Content: "203.0.113.20", ZoneID: "zE", RecordID: "r5"}}},
		},
		TunnelAddr: map[string]map[uint16][]model.RR{
			"": {dns.TypeA: {{Type: dns.TypeA, Class: dns.ClassINET, TTL: 300, Content: "203.0.113.10", Synthetic: true}}},
		},
		Wildcards:         map[uint16][]model.RR{},
		ENT:               map[string]bool{},
		LastFetchedSerial: 100,
	}
	return map[string]*model.Zone{"example.com.": z}
}

func TestCacheSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir, time.Hour, nil)
	t0 := time.Unix(1_000_000, 0)

	if err := c.Save(sampleZones(), t0); err != nil {
		t.Fatalf("Save: %v", err)
	}
	zones, states, err := c.Load(t0.Add(10 * time.Minute))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	z, ok := zones["example.com."]
	if !ok {
		t.Fatalf("zone not loaded")
	}
	if !z.Stale {
		t.Errorf("loaded zone must be marked Stale (serve while refreshing)")
	}
	if z.SyntheticStale {
		t.Errorf("synthetic data within ceiling must NOT be flagged stale")
	}
	rr := z.Records["sip"][dns.TypeA]
	if len(rr) != 1 || rr[0].Content != "203.0.113.20" || rr[0].RecordID != "r5" || rr[0].ZoneID != "zE" {
		t.Fatalf("record (incl. RecordID for DDNS) did not round-trip: %+v", rr)
	}
	st := states["example.com"]
	if st.Last != 100 || !st.Fetched {
		t.Errorf("serial state = %+v, want {100,true}", st)
	}

	// Files must be 0600.
	fi, _ := os.Stat(c.zonePath("example.com"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("zone file mode = %v, want 0600 (contains plaintext record IDs)", fi.Mode().Perm())
	}
}

func TestCacheSyntheticStale(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir, time.Hour, nil)
	t0 := time.Unix(2_000_000, 0)
	c.Save(sampleZones(), t0)

	zones, _, _ := c.Load(t0.Add(2 * time.Hour)) // past the 1h synthetic ceiling
	if !zones["example.com."].SyntheticStale {
		t.Errorf("synthetic data older than the ceiling must be flagged SyntheticStale")
	}
}

func TestCachePoisonPill(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir, time.Hour, func(string) {})
	t0 := time.Unix(3_000_000, 0)
	c.Save(sampleZones(), t0)

	// Corrupt the zone file but leave the index intact.
	if err := os.WriteFile(c.zonePath("example.com"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	zones, states, err := c.Load(t0)
	if err != nil {
		t.Fatalf("Load must not error on a poison pill: %v", err)
	}
	if _, ok := zones["example.com."]; ok {
		t.Errorf("corrupt zone must be skipped, not served")
	}
	// Serial kept from the index, but Fetched forced false so the poller refetches.
	st := states["example.com"]
	if st.Last != 100 || st.Fetched {
		t.Errorf("poison-pill state = %+v, want {100,false}", st)
	}
}

func TestCacheMissingIsColdStart(t *testing.T) {
	c := NewCache(t.TempDir(), time.Hour, nil)
	zones, states, err := c.Load(time.Unix(4_000_000, 0))
	if err != nil {
		t.Fatalf("missing cache must not error: %v", err)
	}
	if len(zones) != 0 || len(states) != 0 {
		t.Errorf("missing cache must yield empty maps")
	}
}
