package loglimit

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestLogger returns a logger whose rate-limiter uses a controllable clock, plus
// the buffer the underlying text handler writes to and a pointer to advance the clock.
func newTestLogger(every time.Duration) (*slog.Logger, *bytes.Buffer, *time.Time) {
	buf := &bytes.Buffer{}
	clk := time.Unix(1_000_000, 0)
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	h := New(inner, every, 0).WithClock(func() time.Time { return clk })
	return slog.New(h), buf, &clk
}

func countLines(buf *bytes.Buffer) int {
	s := strings.TrimRight(buf.String(), "\n")
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// A flood of one identical message collapses to a single line per interval, and the
// emission after a suppressed run reports how many were dropped.
func TestRepeatedMessageRateLimited(t *testing.T) {
	log, buf, clk := newTestLogger(5 * time.Second)

	for i := 0; i < 100; i++ { // all at the same instant
		log.Warn("notify: accept: use of closed network connection")
	}
	if n := countLines(buf); n != 1 {
		t.Fatalf("flood of 100 identical messages produced %d lines, want 1", n)
	}
	if strings.Contains(buf.String(), "suppressed=") {
		t.Errorf("first emission must not carry a suppressed count: %q", buf.String())
	}

	*clk = clk.Add(5 * time.Second) // past the interval
	buf.Reset()
	log.Warn("notify: accept: use of closed network connection")
	out := buf.String()
	if countLines(buf) != 1 {
		t.Fatalf("post-interval emission produced %d lines, want 1", countLines(buf))
	}
	if !strings.Contains(out, "suppressed=99") {
		t.Errorf("post-interval emission must report suppressed=99, got %q", out)
	}
}

// A distinct message emitted in the middle of a flood must still appear immediately —
// the whole point: floods don't bury the lines you care about.
func TestDistinctMessagePassesThroughFlood(t *testing.T) {
	log, buf, _ := newTestLogger(time.Minute)

	for i := 0; i < 50; i++ {
		log.Warn("flood line")
	}
	log.Warn("a different, important line")
	for i := 0; i < 50; i++ {
		log.Warn("flood line")
	}

	out := buf.String()
	if got := strings.Count(out, "flood line"); got != 1 {
		t.Errorf("flood line emitted %d times, want 1", got)
	}
	if !strings.Contains(out, "a different, important line") {
		t.Errorf("distinct message was suppressed by the flood: %q", out)
	}
}

// Messages with the same text but different attribute VALUES are different types and
// both pass; timestamps are excluded from the identity so they never differentiate.
func TestAttributesDifferentiateButTimeDoesNot(t *testing.T) {
	log, buf, clk := newTestLogger(time.Minute)

	log.Warn("forward failed", "zone", "a.example")
	log.Warn("forward failed", "zone", "b.example") // different attr value => distinct
	if got := strings.Count(buf.String(), "forward failed"); got != 2 {
		t.Fatalf("distinct attr values should both pass, got %d", got)
	}

	// Same message + same attrs, only the clock advanced (but within the interval):
	// must be treated as the SAME type and suppressed.
	buf.Reset()
	*clk = clk.Add(time.Second)
	log.Warn("forward failed", "zone", "a.example")
	if n := countLines(buf); n != 0 {
		t.Errorf("identical message at a later timestamp must be suppressed, got %d lines", n)
	}
}

// every<=0 disables limiting entirely (pass-through).
func TestDisabledPassesEverything(t *testing.T) {
	buf := &bytes.Buffer{}
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	log := slog.New(New(inner, 0, 0))
	for i := 0; i < 10; i++ {
		log.Warn("same line")
	}
	if n := countLines(buf); n != 10 {
		t.Errorf("disabled limiter dropped lines: got %d, want 10", n)
	}
}

// Handler-level attrs (WithAttrs) participate in the identity, and a derived handler
// shares the parent's rate-limit state so the limit is global across the tree.
func TestWithAttrsSharedStateAndKeying(t *testing.T) {
	buf := &bytes.Buffer{}
	clk := time.Unix(2_000_000, 0)
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	root := New(inner, time.Minute, 0).WithClock(func() time.Time { return clk })

	a := slog.New(root.WithAttrs([]slog.Attr{slog.String("comp", "a")}))
	b := slog.New(root.WithAttrs([]slog.Attr{slog.String("comp", "b")}))

	a.Warn("tick") // distinct preset (comp=a) => passes
	b.Warn("tick") // distinct preset (comp=b) => passes
	a.Warn("tick") // same as the first => suppressed (shared state)

	if got := strings.Count(buf.String(), "tick"); got != 2 {
		t.Errorf("WithAttrs keying/shared-state wrong: %d emissions, want 2:\n%s", got, buf.String())
	}
}

// Concurrent logging across derived handlers must be race-free (run with -race).
func TestConcurrentNoRace(t *testing.T) {
	buf := &bytes.Buffer{}
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	root := New(inner, time.Millisecond, 0)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			l := slog.New(root.WithAttrs([]slog.Attr{slog.Int("g", g)}))
			for i := 0; i < 200; i++ {
				l.Warn("hot loop", "i", i%5)
			}
		}(g)
	}
	wg.Wait()
}

func TestEnabledDefersToInner(t *testing.T) {
	buf := &bytes.Buffer{}
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := New(inner, time.Minute, 0)
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Enabled should defer to inner (Info below Warn threshold)")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Enabled should allow Error")
	}
}
