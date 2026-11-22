package mdns

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// persistSource returns a Source persisting to a fresh temp file, with a controllable clock.
func persistSource(t *testing.T, path string, now *time.Time, opts ...Option) *Source {
	t.Helper()
	opts = append([]Option{WithTrustedPersistence(path, func(m string) { t.Log(m) })}, opts...)
	return NewSource(nil, func() time.Time { return *now }, opts...)
}

func keepAll(string, string) bool { return true }

// TestPersistRoundTrip: a strong entry saved by one Source is served as Trusted by the next,
// with its authenticator and original last-seen time intact.
func TestPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mdns-trusted.json")
	now := time.Unix(10_000, 0)
	a := persistSource(t, path, &now)
	a.cache.ApplyBy(ann("hestia", 120, "10.0.0.40", "fd00::40"), now, TrustStrong, "tsig:k1.")
	a.cache.ApplyBy(ann("guest", 120, "10.0.0.99"), now, TrustWeak, "") // weak: never persisted
	a.saveTrusted()

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}

	now = now.Add(time.Hour)
	b := persistSource(t, path, &now)
	n, err := b.LoadTrusted(keepAll)
	if err != nil || n != 1 {
		t.Fatalf("LoadTrusted = %d, %v; want 1, nil", n, err)
	}
	got := fwd(b.View(), "hestia")
	if !got["10.0.0.40"] || !got["fd00::40"] || len(got) != 2 {
		t.Fatalf("restored view %v", got)
	}
	if len(fwd(b.View(), "guest")) != 0 {
		t.Fatal("weak entry must not be persisted")
	}
	entries, _ := b.cache.snapshotTrusted()
	if entries[0].By != "tsig:k1." || !entries[0].Seen.Equal(time.Unix(10_000, 0)) {
		t.Fatalf("provenance/seen not preserved: %+v", entries[0])
	}
}

// TestPersistKeepPolicy: entries whose authenticator the current config rejects are dropped.
func TestPersistKeepPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	now := time.Unix(20_000, 0)
	a := persistSource(t, path, &now)
	a.cache.ApplyBy(ann("hestia", 120, "10.0.0.40"), now, TrustStrong, "tsig:old.")
	a.cache.ApplyBy(ann("nas", 120, "10.0.0.41"), now, TrustStrong, "socket")
	a.cache.ApplyBy(ann("nobody", 120, "10.0.0.42"), now, TrustStrong, "") // unknown provenance
	a.saveTrusted()

	v := NewSigVerifier(map[string]string{"new.": "c2VjcmV0"})
	b := persistSource(t, path, &now)
	if n, _ := b.LoadTrusted(TrustedKeeper(v, true)); n != 1 {
		t.Fatalf("restored %d, want 1 (socket only)", n)
	}
	if len(fwd(b.View(), "hestia")) != 0 || len(fwd(b.View(), "nobody")) != 0 {
		t.Fatal("removed key / unknown provenance must not be restored")
	}
	if !fwd(b.View(), "nas")["10.0.0.41"] {
		t.Fatal("socket entry should survive while the socket is enabled")
	}
	c := persistSource(t, path, &now)
	if n, _ := c.LoadTrusted(TrustedKeeper(v, false)); n != 0 {
		t.Fatalf("socket disabled: restored %d, want 0", n)
	}
	// Dropped entries are purged from the file, so re-enabling the socket cannot revive them.
	c.saveTrusted()
	d := persistSource(t, path, &now)
	if n, _ := d.LoadTrusted(keepAll); n != 0 {
		t.Fatalf("dropped entries resurrected: %d", n)
	}
}

// TestTrustedKeeperScope: a key that no longer covers the host loses the entry.
func TestTrustedKeeperScope(t *testing.T) {
	v := NewSigVerifier(map[string]string{"k.": "c2VjcmV0"}).WithHostScopes(map[string][]string{"k.": {"gateway"}})
	keep := TrustedKeeper(v, false)
	if !keep("tsig:k.", "gateway") || keep("tsig:k.", "hestia") || keep("tsig:K", "hestia") {
		t.Fatal("scope not enforced")
	}
	if !keep("tsig:K", "gateway") {
		t.Fatal("key name must be canonicalized")
	}
	if keep("bogus", "gateway") || keep("socket", "gateway") {
		t.Fatal("unknown authenticator or disabled socket must be rejected")
	}
}

// TestPersistGraceNotExtended: a restart neither revives an entry past trusted_grace nor
// extends one inside it.
func TestPersistGraceNotExtended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	t0 := time.Unix(30_000, 0)
	now := t0
	grace := WithTrustedStore(time.Hour, 0)
	a := persistSource(t, path, &now, grace)
	a.cache.ApplyBy(ann("old", 120, "10.0.0.1"), t0, TrustStrong, "socket")
	a.cache.ApplyBy(ann("young", 120, "10.0.0.2"), t0.Add(50*time.Minute), TrustStrong, "socket")
	a.saveTrusted()

	now = t0.Add(61 * time.Minute)
	b := persistSource(t, path, &now, grace)
	if n, _ := b.LoadTrusted(keepAll); n != 1 {
		t.Fatalf("restored %d, want 1 (old is past grace)", n)
	}
	b.cache.Expire(t0.Add(111 * time.Minute)) // young: seen at 50m + 60m grace
	if len(fwd(b.cache.View(t0.Add(111*time.Minute)), "young")) != 0 {
		t.Fatal("restored entry must expire on its ORIGINAL last-seen clock")
	}
}

// TestPersistFutureSeenClamped: an entry stamped in the future (clock step back) is treated
// as seen now, so it cannot outlive its grace.
func TestPersistFutureSeenClamped(t *testing.T) {
	c := NewCache(nil)
	c.trustedGrace = time.Hour
	now := time.Unix(40_000, 0)
	n := c.restoreTrusted([]trustedFileEntry{{Host: "h", Addrs: []string{"10.0.0.1"}, Seen: now.Add(1000 * time.Hour), By: "socket"}}, now, keepAll)
	if n != 1 {
		t.Fatal("entry not restored")
	}
	c.Expire(now.Add(61 * time.Minute))
	if len(fwd(c.View(now.Add(61*time.Minute)), "h")) != 0 {
		t.Fatal("future-stamped entry outlived its grace")
	}
}

// TestPersistRejectsMalformed: bad hosts, addresses, and duplicates are skipped one by one.
func TestPersistRejectsMalformed(t *testing.T) {
	c := NewCache(nil)
	now := time.Unix(50_000, 0)
	n := c.restoreTrusted([]trustedFileEntry{
		{Host: "Upper", Addrs: []string{"10.0.0.1"}, Seen: now, By: "socket"},    // not canonical
		{Host: "a.b", Addrs: []string{"10.0.0.1"}, Seen: now, By: "socket"},      // dotted
		{Host: "linklocal", Addrs: []string{"fe80::1"}, Seen: now, By: "socket"}, // nothing servable
		{Host: "junk", Addrs: []string{"not-an-ip"}, Seen: now, By: "socket"},    // unparsable
		{Host: "nosince", Addrs: []string{"10.0.0.1"}, By: "socket"},             // zero seen
		{Host: "ok", Addrs: []string{"10.0.0.7", "::ffff:10.0.0.8"}, Seen: now, By: "socket"},
		{Host: "ok", Addrs: []string{"10.0.0.9"}, Seen: now, By: "socket"}, // duplicate host
	}, now, keepAll)
	if n != 1 {
		t.Fatalf("restored %d, want 1", n)
	}
	got := fwd(c.View(now), "ok")
	if !got["10.0.0.7"] || !got["10.0.0.8"] || len(got) != 2 {
		t.Fatalf("ok host: %v (want mapped v4 unmapped, duplicate ignored)", got)
	}
}

// TestPersistMaxKeepsFreshest: the maxTrusted bound keeps the most recently refreshed entries.
func TestPersistMaxKeepsFreshest(t *testing.T) {
	c := NewCache(nil)
	c.maxTrusted = 2
	now := time.Unix(60_000, 0)
	var in []trustedFileEntry
	for i, h := range []string{"a", "b", "c"} {
		in = append(in, trustedFileEntry{Host: h, Addrs: []string{netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}).String()}, Seen: now.Add(time.Duration(i) * time.Minute), By: "socket"})
	}
	if n := c.restoreTrusted(in, now.Add(time.Hour), keepAll); n != 2 {
		t.Fatalf("restored %d, want 2", n)
	}
	v := c.View(now.Add(time.Hour))
	if len(fwd(v, "a")) != 0 || len(fwd(v, "b")) == 0 || len(fwd(v, "c")) == 0 {
		t.Fatal("bound must drop the stalest entry")
	}
}

// TestPersistBadFiles: missing, corrupt, wrong-schema and oversized files are cold starts.
func TestPersistBadFiles(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(70_000, 0)
	cases := map[string][]byte{
		"corrupt": []byte("{not json"),
		"schema":  []byte(`{"schema":99,"entries":[{"host":"h","addrs":["10.0.0.1"],"seen":"2026-01-01T00:00:00Z","by":"socket"}]}`),
		"huge":    append([]byte(`{"schema":1,"entries":[`), make([]byte, maxTrustedFile+1)...),
	}
	for name, body := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if n, err := persistSource(t, p, &now).LoadTrusted(keepAll); n != 0 || err != nil {
			t.Fatalf("%s: LoadTrusted = %d, %v; want 0, nil", name, n, err)
		}
	}
	if n, err := persistSource(t, filepath.Join(dir, "missing"), &now).LoadTrusted(keepAll); n != 0 || err != nil {
		t.Fatalf("missing: %d, %v", n, err)
	}
}

// TestPersistSavesOnlyOnChange: no write without a trusted mutation; a withdrawal is saved.
func TestPersistSavesOnlyOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	now := time.Unix(80_000, 0)
	s := persistSource(t, path, &now)
	s.saveTrusted()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("empty, unchanged store must not be written")
	}
	s.cache.ApplyBy(ann("h", 120, "10.0.0.1"), now, TrustStrong, "socket")
	s.saveTrusted()
	st1, _ := os.Stat(path)
	if err := os.Chtimes(path, time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	s.cache.ApplyBy(ann("v", 120, "10.0.0.2"), now, TrustNone, "") // untrusted: no store change
	s.saveTrusted()
	if st2, _ := os.Stat(path); !st2.ModTime().Equal(time.Unix(1, 0)) || st1 == nil {
		t.Fatal("untrusted traffic must not rewrite the file")
	}
	s.cache.ApplyBy(ann("h", 0, "10.0.0.1"), now.Add(time.Minute), TrustStrong, "socket") // withdrawal
	s.saveTrusted()
	var tf trustedFile
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &tf); err != nil || len(tf.Entries) != 0 {
		t.Fatalf("withdrawal not persisted: %v %+v", err, tf)
	}
}

// TestPersistRestoreFiresNoChange: restoring must not drive DDNS write-back.
func TestPersistRestoreFiresNoChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	now := time.Unix(90_000, 0)
	a := persistSource(t, path, &now)
	a.cache.ApplyBy(ann("h", 120, "10.0.0.1"), now, TrustStrong, "socket")
	a.saveTrusted()
	fired := 0
	b := NewSource(func(string, []netip.Addr) { fired++ }, func() time.Time { return now }, WithTrustedPersistence(path, nil))
	if n, _ := b.LoadTrusted(keepAll); n != 1 || fired != 0 {
		t.Fatalf("restored %d, onChange fired %d times; want 1, 0", n, fired)
	}
}

// TestHandlePacketByRecordsAuthenticator: the authenticator passed with a packet lands on the
// trusted entry (and an empty one never overwrites a known one).
func TestHandlePacketByRecordsAuthenticator(t *testing.T) {
	now := time.Unix(100_000, 0)
	s := NewSource(nil, func() time.Time { return now })
	pkt := announce(t, "hestia.local.", "10.0.0.40")
	s.HandlePacketBy(pkt, TrustStrong, "tsig:k.")
	now = now.Add(time.Second)
	s.HandlePacket(pkt, TrustStrong)
	e, _ := s.cache.snapshotTrusted()
	if len(e) != 1 || e[0].By != "tsig:k." {
		t.Fatalf("entries %+v", e)
	}
}

// TestRunFlushesOnShutdown: cancelling Run writes pending trusted changes.
func TestRunFlushesOnShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	now := time.Unix(110_000, 0)
	s := persistSource(t, path, &now)
	s.expireEvery = time.Hour // only the shutdown path can save
	s.cache.ApplyBy(ann("h", 120, "10.0.0.1"), now, TrustStrong, "socket")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx, nil); close(done) }()
	cancel()
	<-done
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("not flushed on shutdown: %v", err)
	}
}
