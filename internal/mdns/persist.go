package mdns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// trustedSchema versions the persisted trusted store; any other schema is ignored (cold
// start) rather than mis-parsed.
const trustedSchema = 1

// maxTrustedFile bounds how much is read back, so a damaged or hostile file cannot make
// startup allocate without limit (the store itself holds at most maxTrusted entries).
const maxTrustedFile = 4 << 20

type trustedFileEntry struct {
	Host  string    `json:"host"`
	Addrs []string  `json:"addrs"`
	Seen  time.Time `json:"seen"`
	By    string    `json:"by"`
}

type trustedFile struct {
	Schema  int                `json:"schema"`
	SavedAt time.Time          `json:"saved_at"`
	Entries []trustedFileEntry `json:"entries"`
}

// WithTrustedPersistence keeps the trusted store in path across restarts. Without it the
// store is memory-only: after a restart, trusted names (e.g. internal names under a managed
// apex) fall back to their public answers until the notifiers re-announce. log may be nil.
// Load the file with LoadTrusted before the listeners start; Run saves on change and once
// more on shutdown.
func WithTrustedPersistence(path string, log func(string)) Option {
	return func(s *Source) {
		s.persistPath = path
		s.persistLog = log
		if s.persistLog == nil {
			s.persistLog = func(string) {}
		}
	}
}

// LoadTrusted restores the persisted trusted store and republishes the view. keep decides,
// per entry, whether its authenticator ("tsig:<key>" or "socket") may still vouch for the
// host under the CURRENT configuration; entries it rejects, entries past trusted_grace, and
// malformed entries are dropped. Restored entries keep their original last-seen time (a
// restart never extends their life) and fire no change events: DDNS already reflects them.
// A missing file is a cold start, not an error. Returns how many entries were restored.
func (s *Source) LoadTrusted(keep func(by, host string) bool) (int, error) {
	if s.persistPath == "" {
		return 0, nil
	}
	f, err := os.Open(s.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("trusted store: %w", err)
	}
	defer f.Close()
	var tf trustedFile
	dec := json.NewDecoder(&limitedReader{r: f, n: maxTrustedFile})
	if err := dec.Decode(&tf); err != nil || tf.Schema != trustedSchema {
		s.persistLog(fmt.Sprintf("trusted store %s unreadable or old schema — starting empty", s.persistPath))
		return 0, nil
	}
	now := s.now()
	n := s.cache.restoreTrusted(tf.Entries, now, keep)
	s.persistMu.Lock()
	s.savedGen = s.cache.gen()
	if n != len(tf.Entries) {
		// Something was dropped (revoked, expired, malformed, over the bound): rewrite the
		// file on the next save, so a later config change cannot resurrect it.
		s.savedGen = ^s.savedGen
	}
	s.persistMu.Unlock()
	s.publish()
	return n, nil
}

// TrustedKeeper returns the LoadTrusted policy for the current configuration: a "tsig:<key>"
// entry survives only while that key is configured and still covers the host; a "socket"
// entry only while the notify socket is enabled. Anything else is dropped.
func TrustedKeeper(v *SigVerifier, socketEnabled bool) func(by, host string) bool {
	return func(by, host string) bool {
		if by == "socket" {
			return socketEnabled
		}
		if key, ok := strings.CutPrefix(by, "tsig:"); ok {
			return v.HasKey(key) && v.Permits(key, host)
		}
		return false
	}
}

// saveTrusted writes the trusted store if it changed since the last save. Errors are logged
// (the in-memory store keeps working); the next change retries.
func (s *Source) saveTrusted() {
	if s.persistPath == "" {
		return
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	entries, gen := s.cache.snapshotTrusted()
	if gen == s.savedGen {
		return
	}
	tf := trustedFile{Schema: trustedSchema, SavedAt: s.now().UTC(), Entries: entries}
	if err := writeFileAtomic(s.persistPath, tf); err != nil {
		s.persistLog(fmt.Sprintf("trusted store: save %s: %v", s.persistPath, err))
		return
	}
	s.savedGen = gen
}

func (c *Cache) gen() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.trustedGen
}

// snapshotTrusted returns the trusted store in a stable order plus the mutation count it
// reflects.
func (c *Cache) snapshotTrusted() ([]trustedFileEntry, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]trustedFileEntry, 0, len(c.trusted))
	for h, te := range c.trusted {
		set := make([]netip.Addr, 0, len(te.addrs))
		for a := range te.addrs {
			set = append(set, a)
		}
		sortAddrs(set)
		addrs := make([]string, len(set))
		for i, a := range set {
			addrs[i] = a.String()
		}
		out = append(out, trustedFileEntry{Host: h, Addrs: addrs, Seen: te.seen.UTC(), By: te.by})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, c.trustedGen
}

// restoreTrusted folds persisted entries into the (normally empty) trusted store under the
// same rules live announcements obey; existing entries win. Caller supplies keep (see
// LoadTrusted). Returns the number restored.
func (c *Cache) restoreTrusted(entries []trustedFileEntry, now time.Time, keep func(by, host string) bool) int {
	valid := make([]*trustedEntry, 0, len(entries))
	hosts := make([]string, 0, len(entries))
	seenHost := map[string]bool{}
	for _, e := range entries {
		if e.Host == "" || canonHost(e.Host) != e.Host || seenHost[e.Host] || e.By == "" || e.Seen.IsZero() {
			continue
		}
		if keep == nil || !keep(e.By, e.Host) {
			continue
		}
		seen := e.Seen
		if seen.After(now) {
			seen = now // a clock step must not make an entry outlive its grace
		}
		if c.trustedGrace > 0 && now.Sub(seen) > c.trustedGrace {
			continue
		}
		te := &trustedEntry{addrs: map[netip.Addr]struct{}{}, seen: seen, by: e.By}
		for _, s := range e.Addrs {
			a, err := netip.ParseAddr(s)
			if err != nil {
				continue
			}
			a = a.Unmap()
			if a.IsLinkLocalUnicast() || a.Zone() != "" {
				continue
			}
			te.addrs[a] = struct{}{}
		}
		if len(te.addrs) == 0 {
			continue
		}
		seenHost[e.Host] = true
		valid = append(valid, te)
		hosts = append(hosts, e.Host)
	}
	// Most recently refreshed first, so the maxTrusted bound keeps the freshest entries.
	idx := make([]int, len(valid))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return valid[idx[a]].seen.After(valid[idx[b]].seen) })

	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, i := range idx {
		if _, exists := c.trusted[hosts[i]]; exists {
			continue
		}
		if c.maxTrusted > 0 && len(c.trusted) >= c.maxTrusted {
			break
		}
		c.trusted[hosts[i]] = valid[i]
		n++
	}
	return n
}

// limitedReader is io.LimitReader that fails (instead of silently truncating) past n bytes,
// so an oversized file is rejected as a whole.
type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, fmt.Errorf("file larger than %d bytes", maxTrustedFile)
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// writeFileAtomic writes v as JSON to path via a temp file + fsync + rename, mode 0600, so
// a crash never leaves a torn file. The directory must exist (the daemon's state dir).
func writeFileAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-trusted-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
