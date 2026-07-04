// Package hostinfo derives best-effort, diagnostic-only facts about a LAN host — the
// hardware vendor from a MAC OUI, and the MAC itself from an EUI-64 IPv6 address (passive)
// or the kernel ARP table (v4). It performs NO network I/O of its own beyond an optional,
// caller-driven ARP-populating ping, and never sends any host data off the box.
package hostinfo

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// ouiPaths are candidate local OUI databases, best first. The ieee-data package
// (Debian/Ubuntu; Recommended by splitdnsd, so present on a normal install) is preferred;
// nmap's prefix list is a fallback. Lookups are always local — no per-MAC online query.
var ouiPaths = []string{
	"/usr/share/ieee-data/oui.txt",
	"/var/lib/ieee-data/oui.txt",
	"/var/lib/splitdns/oui.txt", // optional runtime-fetched copy (config-gated)
	"/usr/share/nmap/nmap-mac-prefixes",
	"/usr/share/hwdata/oui.txt",
}

// refreshEvery bounds how often the DB re-stats its source file (cheap, but not per-lookup).
const refreshEvery = 10 * time.Minute

// OUIDB maps a 24-bit OUI to a vendor name, loaded lazily from the first available local
// file and reloaded when that file changes. Safe for concurrent use; a missing database
// simply yields empty vendors (graceful degradation).
type OUIDB struct {
	paths []string

	mu       sync.RWMutex
	table    map[uint32]string
	src      string
	mtime    time.Time
	checked  time.Time
	checking sync.Mutex
}

// NewOUIDB builds a lazily-loaded database. Pass paths to override the default search list
// (tests). The file is not read until the first Vendor call.
func NewOUIDB(paths ...string) *OUIDB {
	if len(paths) == 0 {
		paths = ouiPaths
	}
	return &OUIDB{paths: paths}
}

// Source reports the loaded database path (or "" if none is available).
func (d *OUIDB) Source() string {
	d.ensure(time.Now())
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.src
}

// Vendor returns the manufacturer for a MAC's OUI, or "" when unknown or no DB is present.
func (d *OUIDB) Vendor(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	d.ensure(time.Now())
	d.mu.RLock()
	defer d.mu.RUnlock()
	oui := uint32(mac[0])<<16 | uint32(mac[1])<<8 | uint32(mac[2])
	return d.table[oui]
}

// ensure loads (or reloads) the table when never loaded or the source mtime changed, but at
// most once per refreshEvery. Cheap stat on the hot path; a full parse only on change.
func (d *OUIDB) ensure(now time.Time) {
	d.mu.RLock()
	fresh := d.table != nil && now.Sub(d.checked) < refreshEvery
	d.mu.RUnlock()
	if fresh {
		return
	}
	d.checking.Lock()
	defer d.checking.Unlock()
	// Re-check under the load lock (another goroutine may have just loaded). Capture every
	// field we need under the RLock — never read d.table/d.src outside a lock (data race).
	d.mu.RLock()
	loaded := d.table != nil
	fresh = loaded && now.Sub(d.checked) < refreshEvery
	prevSrc, prevMtime := d.src, d.mtime
	d.mu.RUnlock()
	if fresh {
		return
	}

	src, mtime := d.locate()
	if src == "" { // no database available: remember an empty table, degrade gracefully
		d.store(map[uint32]string{}, "", time.Time{}, now)
		return
	}
	if loaded && src == prevSrc && mtime.Equal(prevMtime) {
		d.mu.Lock()
		d.checked = now
		d.mu.Unlock()
		return
	}
	if tbl := parseOUIFile(src); tbl != nil {
		d.store(tbl, src, mtime, now)
	}
}

func (d *OUIDB) locate() (string, time.Time) {
	for _, p := range d.paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, fi.ModTime()
		}
	}
	return "", time.Time{}
}

func (d *OUIDB) store(tbl map[uint32]string, src string, mtime, now time.Time) {
	d.mu.Lock()
	d.table, d.src, d.mtime, d.checked = tbl, src, mtime, now
	d.mu.Unlock()
}

// parseOUIFile reads an ieee-data oui.txt ("XX-XX-XX   (hex)\t\tVendor") or an
// nmap-mac-prefixes ("XXXXXX Vendor") file into an OUI->vendor map. Unrecognized lines are
// skipped. Returns nil only on open error (so a transient failure keeps the old table).
func parseOUIFile(path string) map[uint32]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	tbl := make(map[uint32]string, 40000)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if oui, vendor, ok := parseOUILine(sc.Text()); ok {
			tbl[oui] = vendor
		}
	}
	return tbl
}

// parseOUILine parses one line of either supported format.
func parseOUILine(line string) (uint32, string, bool) {
	// ieee-data: "00-1B-63   (hex)\t\tApple, Inc."
	if i := strings.Index(line, "(hex)"); i > 0 {
		pfx := strings.TrimSpace(line[:i])
		vendor := strings.TrimSpace(line[i+len("(hex)"):])
		if oui, ok := parseOUIHex(strings.ReplaceAll(pfx, "-", "")); ok && vendor != "" {
			return oui, vendor, true
		}
		return 0, "", false
	}
	// ieee-data repeats each OUI as a "001B63     (base 16)  <vendor>" line (plus indented
	// address lines). Skip them: the "(hex)" line above already carried the vendor, and
	// parsing this line as nmap-format would set the vendor to "(base 16)  <vendor>" and
	// overwrite the correct entry.
	if strings.Contains(line, "(base 16)") {
		return 0, "", false
	}
	// nmap-mac-prefixes: "001B63 Apple" (6 hex, ONE space, vendor); skip comments.
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return 0, "", false
	}
	sp := strings.IndexByte(line, ' ')
	if sp != 6 || (len(line) > 7 && line[7] == ' ') { // one space only — not an indented/aligned line
		return 0, "", false
	}
	if oui, ok := parseOUIHex(line[:6]); ok {
		if vendor := strings.TrimSpace(line[sp+1:]); vendor != "" {
			return oui, vendor, true
		}
	}
	return 0, "", false
}

func parseOUIHex(s string) (uint32, bool) {
	if len(s) != 6 {
		return 0, false
	}
	var v uint32
	for i := 0; i < 6; i++ {
		c := s[i]
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}
