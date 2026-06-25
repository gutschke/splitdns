// Package loglimit provides a slog.Handler middleware that rate-limits floods of an
// identical log message while letting distinct messages through unimpeded.
//
// The motivating failure: a tight loop logging the same WARN every iteration buries
// every other line in the journal. Suppressing by message TYPE — the level, message
// text, and attributes, but NOT the timestamp — collapses such a flood to one line per
// interval (carrying a "suppressed=N" count of what was dropped) while a different
// message emitted in the middle of the flood still appears immediately, because it
// keys to a different bucket. That keeps the log scannable under load.
package loglimit

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// defaultMaxKeys bounds how many distinct message types are tracked at once, so a
// stream of ever-changing messages cannot grow the dedup map without limit.
const defaultMaxKeys = 2048

// Handler wraps an inner slog.Handler, emitting at most one copy of each distinct
// message type per interval. Derived handlers from WithAttrs/WithGroup share one
// rate-limit state so the limit is global across the logger tree, not per-branch.
type Handler struct {
	inner  slog.Handler
	every  time.Duration
	max    int
	now    func() time.Time
	preset string // key fragment accumulated from WithAttrs/WithGroup

	mu   *sync.Mutex
	seen map[string]*entry
}

type entry struct {
	emitted    bool
	lastEmit   time.Time
	lastSeen   time.Time
	suppressed int
}

// New wraps inner so identical messages are emitted at most once per every. every<=0
// disables limiting (inner is returned wrapped but pass-through). maxKeys<=0 uses a
// default. The clock is time.Now; tests inject one via WithClock.
func New(inner slog.Handler, every time.Duration, maxKeys int) *Handler {
	if maxKeys <= 0 {
		maxKeys = defaultMaxKeys
	}
	return &Handler{
		inner: inner, every: every, max: maxKeys, now: time.Now,
		mu: &sync.Mutex{}, seen: map[string]*entry{},
	}
}

// WithClock overrides the clock (for deterministic tests) and returns h.
func (h *Handler) WithClock(now func() time.Time) *Handler {
	h.now = now
	return h
}

// Enabled defers to the inner handler.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

// Handle emits r unless an identical message type was already emitted within the
// interval, in which case it is counted and dropped. The first emission after a
// suppressed run carries a "suppressed" attribute with the drop count.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.every <= 0 {
		return h.inner.Handle(ctx, r)
	}
	key := h.key(r)
	now := h.now()

	h.mu.Lock()
	e, ok := h.seen[key]
	if !ok {
		if len(h.seen) >= h.max {
			h.evictLocked(now)
		}
		e = &entry{}
		h.seen[key] = e
	}
	e.lastSeen = now
	if e.emitted && now.Sub(e.lastEmit) < h.every {
		e.suppressed++
		h.mu.Unlock()
		return nil // within the window: drop, already counted
	}
	n := e.suppressed
	e.suppressed = 0
	e.emitted = true
	e.lastEmit = now
	h.mu.Unlock()

	if n > 0 {
		r = r.Clone()
		r.AddAttrs(slog.Int("suppressed", n))
	}
	return h.inner.Handle(ctx, r)
}

// WithAttrs returns a handler that shares this one's rate-limit state but folds the
// preset attributes into the dedup key (so messages differing only by handler-level
// attrs are distinct types).
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	var b strings.Builder
	for _, a := range as {
		writeAttr(&b, a)
	}
	return h.derive(h.inner.WithAttrs(as), b.String())
}

// WithGroup mirrors the inner grouping and records it in the key prefix.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return h.derive(h.inner.WithGroup(name), "\x1egroup="+name)
}

func (h *Handler) derive(inner slog.Handler, extra string) *Handler {
	return &Handler{
		inner: inner, every: h.every, max: h.max, now: h.now,
		preset: h.preset + extra,
		mu:     h.mu, seen: h.seen, // shared state
	}
}

// key builds the dedup identity: level + message + preset + per-record attributes.
// r.Time is deliberately excluded — two otherwise-identical records logged at
// different instants are the same TYPE and must rate-limit together.
func (h *Handler) key(r slog.Record) string {
	var b strings.Builder
	b.WriteString(r.Level.String())
	b.WriteByte('\x1f')
	b.WriteString(r.Message)
	b.WriteString(h.preset)
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, a)
		return true
	})
	return b.String()
}

func writeAttr(b *strings.Builder, a slog.Attr) {
	b.WriteByte('\x1f')
	b.WriteString(a.Key)
	b.WriteByte('=')
	b.WriteString(a.Value.Resolve().String())
}

// evictLocked drops entries idle for at least one interval; if the map is still at
// capacity (an unusually large set of simultaneously-active message types) it resets,
// trading a one-time re-emit of each live type for a bounded footprint. Caller holds mu.
func (h *Handler) evictLocked(now time.Time) {
	for k, e := range h.seen {
		if now.Sub(e.lastSeen) >= h.every {
			delete(h.seen, k)
		}
	}
	if len(h.seen) >= h.max {
		h.seen = make(map[string]*entry, h.max)
	}
}
