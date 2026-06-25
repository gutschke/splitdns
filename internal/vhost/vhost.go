// Package vhost is the reverse-proxy virtual-host feed worker (requirement R3, design §2.5).
// It periodically dials the reverse-proxy feed (host:port, e.g. the reverse proxy's :818),
// reads a newline-separated list of vhost names, normalizes each to a bare label
// (stripping any configured local-zone suffix, trailing dot optional), validates it,
// and publishes the resulting set. The set feeds Snapshot.VHosts, which the resolver
// consults for the naked/www/vhost → reverse-proxy redirect.
//
// Hardening: a hard connect+read deadline, and a 64 KB TRUNCATE-AND-REJECT cap — if
// the feed returns more than the cap the whole read is rejected and the previous set
// kept, never a partially-parsed set that would silently drop redirects. Any failure
// keeps the previous set.
package vhost

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxBytes = 64 << 10 // 64 KB total cap (truncate-and-reject)
	defaultInterval = 5 * time.Minute
	defaultDeadline = 10 * time.Second
)

// label is a single DNS hostname label (lowercased): the normalized vhost form.
var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Feed fetches and publishes the vhost set.
type Feed struct {
	addr     string
	suffixes []string // local-zone suffixes to strip (lowercased, no trailing dot)
	maxBytes int64
	interval time.Duration
	deadline time.Duration
	log      func(string)
	dial     func(ctx context.Context, addr string) (net.Conn, error)

	mu      sync.Mutex
	current map[string]bool
}

// New builds a Feed for addr, stripping the given local-zone suffixes. log may be nil.
func New(addr string, suffixes []string, log func(string)) *Feed {
	if log == nil {
		log = func(string) {}
	}
	norm := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
		if s != "" {
			norm = append(norm, s)
		}
	}
	d := &net.Dialer{}
	return &Feed{
		addr: addr, suffixes: norm, maxBytes: defaultMaxBytes,
		interval: defaultInterval, deadline: defaultDeadline, log: log,
		dial:    func(ctx context.Context, a string) (net.Conn, error) { return d.DialContext(ctx, "tcp", a) },
		current: map[string]bool{},
	}
}

// Current returns a copy of the most recently published set.
func (f *Feed) Current() map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]bool, len(f.current))
	for k := range f.current {
		out[k] = true
	}
	return out
}

// Fetch dials the feed once and returns the normalized vhost set. It enforces the
// connect+read deadline and the truncate-and-reject byte cap.
func (f *Feed) Fetch(ctx context.Context) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, f.deadline)
	defer cancel()

	conn, err := f.dial(ctx, f.addr)
	if err != nil {
		return nil, fmt.Errorf("vhost: dial %s: %w", f.addr, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// Read at most maxBytes+1 so we can DETECT an over-cap feed and reject the whole
	// read (never publish a partially-parsed set).
	data, err := io.ReadAll(io.LimitReader(conn, f.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("vhost: read %s: %w", f.addr, err)
	}
	if int64(len(data)) > f.maxBytes {
		return nil, fmt.Errorf("vhost: feed exceeded %d-byte cap — rejecting whole read", f.maxBytes)
	}

	set := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		if name, ok := f.normalize(sc.Text()); ok {
			set[name] = true
		}
	}
	return set, nil
}

// normalize lowercases a feed line, strips any configured local-zone suffix (trailing
// dot optional), and validates that the result is a single hostname label. Anything
// else (apex, multi-label outside a known zone, invalid chars) is dropped.
func (f *Feed) normalize(line string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(line))
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.HasPrefix(s, "#") {
		return "", false
	}
	for _, sfx := range f.suffixes {
		if s == sfx {
			return "", false // the apex itself is not a vhost label
		}
		if strings.HasSuffix(s, "."+sfx) {
			s = strings.TrimSuffix(s, "."+sfx)
			break
		}
	}
	if !label.MatchString(s) {
		return "", false
	}
	return s, true
}

// Run fetches immediately, then on the interval, calling onChange whenever the
// published set actually changes. A failed fetch keeps the previous set (no publish).
// progress (nil-safe) is ticked each poll for the supervisor's stall-detector.
func (f *Feed) Run(ctx context.Context, onChange, progress func()) {
	if progress == nil {
		progress = func() {}
	}
	f.poll(ctx, onChange)
	progress()
	t := time.NewTicker(f.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.poll(ctx, onChange)
			progress()
		}
	}
}

func (f *Feed) poll(ctx context.Context, onChange func()) {
	set, err := f.Fetch(ctx)
	if err != nil {
		f.log(err.Error() + " (keeping previous vhost set)")
		return
	}
	f.mu.Lock()
	changed := !setsEqual(f.current, set)
	if changed {
		f.current = set
	}
	f.mu.Unlock()
	if changed {
		f.log(fmt.Sprintf("vhost: published %d names", len(set)))
		if onChange != nil {
			onChange()
		}
	}
}

func setsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
