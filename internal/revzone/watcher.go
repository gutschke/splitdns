package revzone

import (
	"context"
	"net/netip"
	"time"
)

// Watcher periodically re-detects the locally-managed prefix set and invokes a
// callback whenever it changes. This is what lets the server track a DYNAMIC,
// ISP-assigned GUA prefix (which can change): when the prefix set changes, the
// control plane re-derives the reverse-zone set and rebuilds the snapshot.
//
// The scan function is injected so the watcher is fully testable without touching
// real interfaces; production wiring passes a closure over DetectPrefixes(scope).
type Watcher struct {
	scan     func() ([]netip.Prefix, error)
	interval time.Duration
	onChange func([]netip.Prefix)
	onError  func(error)
}

// NewWatcher builds a Watcher. interval must be > 0.
func NewWatcher(scan func() ([]netip.Prefix, error), interval time.Duration,
	onChange func([]netip.Prefix), onError func(error)) *Watcher {
	return &Watcher{scan: scan, interval: interval, onChange: onChange, onError: onError}
}

// Run scans immediately, then every interval, until ctx is cancelled. It calls
// onChange on the first successful scan and on every subsequent change. A scan
// error invokes onError (if set) and keeps the last known good set — a transient
// enumeration failure never drops the managed prefixes. Respecting ctx on every
// blocking wait is the anti-hang contract (design §3).
func (w *Watcher) Run(ctx context.Context) {
	var last []netip.Prefix
	have := false
	check := func() {
		cur, err := w.scan()
		if err != nil {
			if w.onError != nil {
				w.onError(err)
			}
			return
		}
		sortPrefixes(cur)
		if !have || PrefixSetChanged(last, cur) {
			last = cur
			have = true
			w.onChange(cur)
		}
	}
	check()
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

// PrefixSetChanged reports whether two prefix slices differ as sets. Both are
// assumed sorted (sortPrefixes). Pure; the core of the watcher's change test.
func PrefixSetChanged(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return true
		}
	}
	return false
}
