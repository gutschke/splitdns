package mdns

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAllowUIDFunc pins the peer-uid predicate: root and the daemon uid are always
// allowed, configured extras are allowed, everything else is rejected.
func TestAllowUIDFunc(t *testing.T) {
	f := AllowUIDFunc(1000, []int{1234})
	for _, uid := range []uint32{0, 1000, 1234} {
		if !f(uid) {
			t.Errorf("uid %d should be allowed", uid)
		}
	}
	if f(9999) {
		t.Errorf("unlisted uid 9999 must be rejected")
	}
}

// TestNotifySocketAuthenticatedDelivery proves the authenticated channel (D7): a
// connection from an allowed peer uid delivers an announcement that DOES fire the
// DDNS trigger (trusted), and updates the view.
func TestNotifySocketAuthenticatedDelivery(t *testing.T) {
	rec := &changeRec{}
	src := NewSource(rec.fn, nil)
	path := filepath.Join(t.TempDir(), "notify.sock")

	ns, err := ListenNotify(path, src, AllowUIDFunc(uint32(os.Getuid()), nil), nil)
	if err != nil {
		t.Fatalf("ListenNotify: %v", err)
	}
	defer ns.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ns.Run(ctx, nil)

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := c.Write(announce(t, "edge.local.", "9.9.9.9")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.Close()

	// The authenticated announcement must both update the view and fire the trigger.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec.count() == 1 && len(src.View().Forward["edge"]) == 1 {
			if rec.last() != "edge:9.9.9.9" {
				t.Fatalf("unexpected trigger event %q", rec.last())
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("authenticated announcement did not converge; events=%d view=%v",
		rec.count(), src.View().Forward)
}

// TestNotifySocketRejectsUID proves a disallowed peer uid is not fed to the Source.
// We cannot easily fake a different peer uid in-process, so we configure the allow
// predicate to reject our OWN uid and assert nothing is delivered.
func TestNotifySocketRejectsUID(t *testing.T) {
	rec := &changeRec{}
	src := NewSource(rec.fn, nil)
	path := filepath.Join(t.TempDir(), "notify.sock")

	// Deny everything (predicate returns false for all uids).
	ns, err := ListenNotify(path, src, func(uint32) bool { return false }, nil)
	if err != nil {
		t.Fatalf("ListenNotify: %v", err)
	}
	defer ns.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ns.Run(ctx, nil)

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Write(announce(t, "edge.local.", "9.9.9.9"))
	c.Close()

	// Give the server a moment; nothing should be delivered.
	time.Sleep(200 * time.Millisecond)
	if rec.count() != 0 {
		t.Errorf("rejected peer must not deliver an announcement, got %d events", rec.count())
	}
	if len(src.View().Forward["edge"]) != 0 {
		t.Errorf("rejected peer must not update the view")
	}
}

// TestNotifySocketCloseStopsRunWithoutSpam is the regression guard for the accept-loop
// spin: when the listener is closed via Close() (NOT via ctx cancellation — the second,
// independent closer), Run must return promptly and must NOT log a flood of
// "use of closed network connection" warnings. Before the fix the loop logged the
// terminal ErrClosed and looped straight back into Accept, spamming the journal.
// TestNotifySocketIdleHeartbeat guards against the false stall in the log: an idle
// notify worker (no connections at all) must still tick progress() periodically, so the
// supervisor's stall detector does not needlessly restart it.
func TestNotifySocketIdleHeartbeat(t *testing.T) {
	orig := acceptHeartbeat
	acceptHeartbeat = 20 * time.Millisecond
	defer func() { acceptHeartbeat = orig }()

	src := NewSource(nil, nil)
	path := filepath.Join(t.TempDir(), "notify.sock")
	ns, err := ListenNotify(path, src, AllowUIDFunc(uint32(os.Getuid()), nil), nil)
	if err != nil {
		t.Fatalf("ListenNotify: %v", err)
	}
	defer ns.Close()

	var ticks atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ns.Run(ctx, func() { ticks.Add(1) })

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && ticks.Load() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if ticks.Load() < 3 {
		t.Errorf("idle notify worker ticked progress %d times; want >=3 (heartbeat absent)", ticks.Load())
	}
}

func TestNotifySocketCloseStopsRunWithoutSpam(t *testing.T) {
	src := NewSource(nil, nil)
	path := filepath.Join(t.TempDir(), "notify.sock")

	var mu sync.Mutex
	var logs int
	logf := func(string) { mu.Lock(); logs++; mu.Unlock() }

	ns, err := ListenNotify(path, src, AllowUIDFunc(uint32(os.Getuid()), nil), logf)
	if err != nil {
		t.Fatalf("ListenNotify: %v", err)
	}

	// A context that is NEVER cancelled: shutdown must come solely from Close(), so the
	// loop cannot rely on ctx.Done() to recognize the closed listener.
	ctx := context.Background()
	returned := make(chan struct{})
	go func() { ns.Run(ctx, nil); close(returned) }()

	time.Sleep(50 * time.Millisecond) // let Accept block
	ns.Close()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Close() (accept loop spinning on a closed listener)")
	}

	mu.Lock()
	n := logs
	mu.Unlock()
	if n > 0 {
		t.Errorf("Close() produced %d accept-error log lines; want 0 (no shutdown spam)", n)
	}
}
