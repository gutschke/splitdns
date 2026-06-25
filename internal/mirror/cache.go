package mirror

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// cacheSchema is the warm-cache JSON schema version; a file with a different schema
// is treated as a poison pill (degraded, not loaded) rather than mis-parsed.
const cacheSchema = 1

// Cache is the versioned-JSON warm-start store (design §2.6/§2.5 persistence). Files
// hold CF ZoneID/RecordID in plaintext (needed for precise DDNS edits), so the
// directory and files are mode 0600/0700, owner == the daemon uid. A corrupt zone
// file degrades that one zone (force-refetch), never wedges the process.
type Cache struct {
	dir          string
	synthCeiling time.Duration
	log          func(string)
}

// NewCache returns a Cache rooted at dir. synthCeiling<=0 defaults to 1h. log nil ok.
func NewCache(dir string, synthCeiling time.Duration, log func(string)) *Cache {
	if synthCeiling <= 0 {
		synthCeiling = time.Hour
	}
	if log == nil {
		log = func(string) {}
	}
	return &Cache{dir: dir, synthCeiling: synthCeiling, log: log}
}

type zoneFile struct {
	Schema    int         `json:"schema"`
	FetchedAt time.Time   `json:"fetched_at"`
	Serial    uint32      `json:"serial"`
	Zone      *model.Zone `json:"zone"`
}

type indexFile struct {
	Schema int                   `json:"schema"`
	Zones  map[string]indexEntry `json:"zones"`
}

type indexEntry struct {
	Serial     uint32 `json:"serial"`
	HasRecords bool   `json:"has_records"`
}

func (c *Cache) zonesDir() string  { return filepath.Join(c.dir, "zones") }
func (c *Cache) indexPath() string { return filepath.Join(c.dir, "zones.json") }
func (c *Cache) zonePath(name string) string {
	return filepath.Join(c.zonesDir(), name+".json")
}

// Save persists each zone (keyed by apex FQDN) plus the index, atomically. The
// per-zone serial is taken from Zone.LastFetchedSerial.
func (c *Cache) Save(zones map[string]*model.Zone, now time.Time) error {
	if err := os.MkdirAll(c.zonesDir(), 0o700); err != nil {
		return fmt.Errorf("cache: mkdir: %w", err)
	}
	idx := indexFile{Schema: cacheSchema, Zones: map[string]indexEntry{}}
	for apex, z := range zones {
		name := strings.TrimSuffix(apex, ".")
		zf := zoneFile{Schema: cacheSchema, FetchedAt: now, Serial: z.LastFetchedSerial, Zone: z}
		if err := writeAtomicJSON(c.zonePath(name), zf); err != nil {
			return fmt.Errorf("cache: write %s: %w", name, err)
		}
		idx.Zones[name] = indexEntry{Serial: z.LastFetchedSerial, HasRecords: zoneHasRecords(z)}
	}
	if err := writeAtomicJSON(c.indexPath(), idx); err != nil {
		return fmt.Errorf("cache: write index: %w", err)
	}
	return nil
}

// Load reads the warm cache. It returns the loaded zones (keyed by apex FQDN, marked
// Stale, with SyntheticStale set if tunnel/synthetic data is older than the ceiling)
// and the per-zone SerialState seeds for the SOAPoller. A missing cache is not an
// error (cold start). A corrupt zone file is skipped and its state forced to
// Fetched=false so the poller refetches it.
func (c *Cache) Load(now time.Time) (map[string]*model.Zone, map[string]SerialState, error) {
	data, err := os.ReadFile(c.indexPath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]*model.Zone{}, map[string]SerialState{}, nil
		}
		return nil, nil, fmt.Errorf("cache: read index: %w", err)
	}
	var idx indexFile
	if jerr := json.Unmarshal(data, &idx); jerr != nil || idx.Schema != cacheSchema {
		c.log("cache: index unreadable/old schema — ignoring warm cache")
		return map[string]*model.Zone{}, map[string]SerialState{}, nil
	}

	zones := map[string]*model.Zone{}
	states := map[string]SerialState{}
	for name, entry := range idx.Zones {
		states[name] = SerialState{Last: entry.Serial, Fetched: entry.HasRecords}
		z, ok := c.loadZone(name, now)
		if !ok {
			// Poison pill: keep the serial but force a refetch (records absent).
			states[name] = SerialState{Last: entry.Serial, Fetched: false}
			continue
		}
		zones[dns.Fqdn(name)] = z
	}
	return zones, states, nil
}

func (c *Cache) loadZone(name string, now time.Time) (*model.Zone, bool) {
	data, err := os.ReadFile(c.zonePath(name))
	if err != nil {
		c.log(fmt.Sprintf("cache: zone %s unreadable: %v", name, err))
		return nil, false
	}
	var zf zoneFile
	if jerr := json.Unmarshal(data, &zf); jerr != nil || zf.Schema != cacheSchema || zf.Zone == nil {
		c.log(fmt.Sprintf("cache: zone %s corrupt/old schema — degrading", name))
		return nil, false
	}
	z := zf.Zone
	z.Stale = true // serve immediately; a refresh is scheduled
	if len(z.TunnelAddr) > 0 && now.Sub(zf.FetchedAt) > c.synthCeiling {
		z.SyntheticStale = true // synthetic (tunnel/SVCB) data past its ceiling
	}
	return z, true
}

func zoneHasRecords(z *model.Zone) bool {
	return len(z.Records) > 0 || len(z.Wildcards) > 0 || len(z.TunnelAddr) > 0
}

// writeAtomicJSON marshals v and writes it to path via a temp file + rename, mode
// 0600, so a crash mid-write never leaves a torn file.
func writeAtomicJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
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
	return os.Rename(tmpName, path)
}
