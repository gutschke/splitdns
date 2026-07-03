package mdns

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/gutschke/splitdns/internal/model"
)

// Source owns the cache and the published MDNSView. It feeds received packets into
// the cache, periodically expires stale hosts, and republishes the view. Change
// events flow through the cache's ChangeFunc (wired by the caller to the DDNS
// writer). Construct with NewSource, feed bytes via HandlePacket (the listener does
// this), and call Run to drive expiry/publish.
type Source struct {
	cache *Cache
	view  atomic.Pointer[model.MDNSView]
	now   func() time.Time

	expireEvery time.Duration
}

// Option customizes a Source at construction.
type Option func(*Source)

// WithServeStale keeps a record served for stale past its announced TTL, and retains it for
// goodbye after an explicit mDNS goodbye (a cushion against an avahi bounce). Zero values
// leave the passive-expiry default (no serve-stale; goodbye coerced to 120s).
func WithServeStale(stale, goodbye time.Duration) Option {
	return func(s *Source) {
		s.cache.staleGrace = stale
		s.cache.goodbyeGrace = goodbye
	}
}

// NewSource builds a Source. onChange/now may be nil (now defaults to time.Now).
func NewSource(onChange ChangeFunc, now func() time.Time, opts ...Option) *Source {
	if now == nil {
		now = time.Now
	}
	s := &Source{
		cache:       NewCache(onChange),
		now:         now,
		expireEvery: 30 * time.Second,
	}
	for _, o := range opts {
		o(s)
	}
	s.publish()
	return s
}

// HandlePacket parses raw mDNS bytes and folds every announcement into the cache,
// republishing the view if anything changed. trusted controls whether these
// announcements may trigger DDNS write-back (D7); the view is updated either way.
// Safe for concurrent callers.
func (s *Source) HandlePacket(b []byte, trusted bool) {
	now := s.now()
	changed := false
	for _, a := range ParsePacket(b) {
		if s.cache.Apply(a, now, trusted) {
			changed = true
		}
	}
	// DNS-SD service types (diagnostic fingerprint) attach to known hosts; parsed after
	// addresses so a host announced in the same packet already exists.
	for _, svc := range ParseServices(b) {
		if s.cache.ApplyService(svc.Host, svc.Type, now) {
			changed = true
		}
	}
	if changed {
		s.publish()
	}
}

// View returns the current immutable MDNSView (one atomic load; never nil).
func (s *Source) View() *model.MDNSView { return s.view.Load() }

func (s *Source) publish() { s.view.Store(s.cache.View(s.now())) }

// Run drives periodic expiry + republish until ctx is cancelled. The receive loop
// lives in the listener; this is the housekeeping ticker. progress (nil-safe) is
// ticked each cycle for the supervisor's stall-detector.
func (s *Source) Run(ctx context.Context, progress func()) {
	if progress == nil {
		progress = func() {}
	}
	t := time.NewTicker(s.expireEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.cache.Expire(s.now())
			s.publish() // republish so TTLs in the view decay toward expiry
			progress()
		}
	}
}
