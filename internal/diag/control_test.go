package diag

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gutschke/splitdns/internal/model"
)

func ctlServer(t *testing.T, c Controls, loopback bool) (base string, flushed *atomic.Int32, stop func()) {
	t.Helper()
	var n atomic.Int32
	if c.FlushCache == nil {
		c.FlushCache = func() { n.Add(1) }
	}
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	s.WithControls(c)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	s.loopback = loopback // override for the gating matrix (Start saw 127.0.0.1 => true)
	return "http://" + s.Addr(), &n, func() { s.Shutdown(context.Background()) }
}

func post(t *testing.T, base, path string, form url.Values, header map[string]string) int {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req, _ := http.NewRequest(http.MethodPost, base+path, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	// Don't auto-follow the HTML redirect so we observe the raw status.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// When controls are disabled, the route does not even exist (404), and nothing fires.
func TestControlDisabledNotRegistered(t *testing.T) {
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	if code := post(t, "http://"+s.Addr(), "/control/flush-cache", nil, nil); code != http.StatusNotFound {
		t.Errorf("disabled controls: status = %d, want 404", code)
	}
}

// Loopback + no password: allowed.
func TestControlLoopbackNoPassword(t *testing.T) {
	base, flushed, stop := ctlServer(t, Controls{AllowControl: true}, true)
	defer stop()
	if code := post(t, base, "/control/flush-cache", nil, nil); code != http.StatusOK {
		t.Fatalf("loopback control: status = %d, want 200", code)
	}
	if flushed.Load() != 1 {
		t.Errorf("flush callback fired %d times, want 1", flushed.Load())
	}
}

// Non-loopback + no password: REFUSED (the key safety rule).
func TestControlNonLoopbackNoPasswordRefused(t *testing.T) {
	base, flushed, stop := ctlServer(t, Controls{AllowControl: true}, false)
	defer stop()
	if code := post(t, base, "/control/flush-cache", nil, nil); code != http.StatusForbidden {
		t.Errorf("non-loopback no-password: status = %d, want 403", code)
	}
	if flushed.Load() != 0 {
		t.Errorf("flush must not fire when refused")
	}
}

// Password set: wrong/missing => 401, correct => 200 and the action fires. Works even
// on a non-loopback bind (password is the auth).
func TestControlPasswordGate(t *testing.T) {
	base, flushed, stop := ctlServer(t, Controls{AllowControl: true, Password: "s3cret"}, false)
	defer stop()

	if code := post(t, base, "/control/flush-cache", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("no password: status = %d, want 401", code)
	}
	if code := post(t, base, "/control/flush-cache", nil, map[string]string{"X-Diag-Password": "wrong"}); code != http.StatusUnauthorized {
		t.Errorf("wrong password: status = %d, want 401", code)
	}
	if code := post(t, base, "/control/flush-cache", nil, map[string]string{"X-Diag-Password": "s3cret"}); code != http.StatusOK {
		t.Errorf("correct password (header): status = %d, want 200", code)
	}
	if code := post(t, base, "/control/flush-cache", url.Values{"password": {"s3cret"}}, nil); code != http.StatusOK {
		t.Errorf("correct password (form): status = %d, want 200", code)
	}
	if flushed.Load() != 2 {
		t.Errorf("flush fired %d times, want 2 (the two authorized calls)", flushed.Load())
	}
}

// Control actions are POST-only.
func TestControlPostOnly(t *testing.T) {
	base, _, stop := ctlServer(t, Controls{AllowControl: true}, true)
	defer stop()
	resp, err := http.Get(base + "/control/flush-cache")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET control: status = %d, want 405", resp.StatusCode)
	}
}

// A cross-site browser request (Fetch Metadata) is refused even on a no-password
// loopback bind — the CSRF guard.
func TestControlCSRFRejected(t *testing.T) {
	base, flushed, stop := ctlServer(t, Controls{AllowControl: true}, true)
	defer stop()
	if code := post(t, base, "/control/flush-cache", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
		t.Errorf("cross-site POST: status = %d, want 403", code)
	}
	if flushed.Load() != 0 {
		t.Errorf("cross-site request must not run the action")
	}
	// same-origin (the in-page form) is allowed.
	if code := post(t, base, "/control/flush-cache", nil, map[string]string{"Sec-Fetch-Site": "same-origin"}); code != http.StatusOK {
		t.Errorf("same-origin POST: status = %d, want 200", code)
	}
}

// The disruptive actions are rate-limited so an authorized client can't loop them.
func TestControlRateLimited(t *testing.T) {
	var refreshed atomic.Int32
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	s.WithControls(Controls{AllowControl: true, RefreshMirror: func() { refreshed.Add(1) }})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	base := "http://" + s.Addr()

	if code := post(t, base, "/control/refresh-mirror", nil, nil); code != http.StatusOK {
		t.Fatalf("first refresh: status = %d, want 200", code)
	}
	if code := post(t, base, "/control/refresh-mirror", nil, nil); code != http.StatusTooManyRequests {
		t.Errorf("immediate second refresh: status = %d, want 429", code)
	}
	if refreshed.Load() != 1 {
		t.Errorf("refresh fired %d times, want 1 (second was rate-limited)", refreshed.Load())
	}
}

// The on-the-fly backend control disables/enables/resets via the gated endpoint.
func TestControlBackend(t *testing.T) {
	var lastAddr string
	var lastEnabled, reset bool
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	s.WithControls(Controls{
		AllowControl:  true,
		SetBackend:    func(addr string, enabled bool) bool { lastAddr, lastEnabled = addr, enabled; return addr != "" },
		ResetBackends: func() { reset = true },
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	base := "http://" + s.Addr()

	if code := post(t, base, "/control/backend?op=disable&addr=1.1.1.1:853", nil, nil); code != http.StatusOK {
		t.Fatalf("disable: status = %d, want 200", code)
	}
	if lastAddr != "1.1.1.1:853" || lastEnabled {
		t.Errorf("disable wired wrong: addr=%q enabled=%v", lastAddr, lastEnabled)
	}
	if code := post(t, base, "/control/backend?op=enable&addr=1.1.1.1:853", nil, nil); code != http.StatusOK || !lastEnabled {
		t.Errorf("enable: status=%d enabled=%v", code, lastEnabled)
	}
	if code := post(t, base, "/control/backend?op=reset", nil, nil); code != http.StatusOK || !reset {
		t.Errorf("reset: status=%d reset=%v", code, reset)
	}
	if code := post(t, base, "/control/backend?op=disable&addr=", nil, nil); code != http.StatusNotFound {
		t.Errorf("unknown addr: status = %d, want 404", code)
	}
	if code := post(t, base, "/control/backend?op=bogus&addr=x", nil, nil); code != http.StatusBadRequest {
		t.Errorf("bad op: status = %d, want 400", code)
	}
}

// An unwired action reports 404 even when authorized.
func TestControlUnknownAction(t *testing.T) {
	base, _, stop := ctlServer(t, Controls{AllowControl: true}, true)
	defer stop()
	if code := post(t, base, "/control/nope", nil, nil); code != http.StatusNotFound {
		t.Errorf("unknown action: status = %d, want 404", code)
	}
}

// postBody is like post but returns the response body too (for oracle-hygiene checks).
func postBody(t *testing.T, base, path string, header map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(""))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// /control/verify is a side-effect-free auth probe so the UI can confirm "unlocked"
// immediately: correct => 200, wrong => 401, and it runs NO action.
func TestControlVerify(t *testing.T) {
	base, flushed, stop := ctlServer(t, Controls{AllowControl: true, Password: "s3cret"}, false)
	defer stop()
	if code := post(t, base, "/control/verify", nil, map[string]string{"X-Diag-Password": "s3cret"}); code != http.StatusOK {
		t.Errorf("verify correct: %d, want 200", code)
	}
	if code := post(t, base, "/control/verify", nil, map[string]string{"X-Diag-Password": "wrong"}); code != http.StatusUnauthorized {
		t.Errorf("verify wrong: %d, want 401", code)
	}
	if flushed.Load() != 0 {
		t.Errorf("verify must have NO side effect; flush fired %d", flushed.Load())
	}
}

// verify is gated exactly like a real action: allowed on loopback (no password), refused
// on a non-loopback no-password bind, and absent entirely when controls are disabled.
func TestControlVerifyGated(t *testing.T) {
	lb, _, stopLB := ctlServer(t, Controls{AllowControl: true}, true)
	defer stopLB()
	if code := post(t, lb, "/control/verify", nil, nil); code != http.StatusOK {
		t.Errorf("loopback verify: %d, want 200", code)
	}

	nlb, _, stopNLB := ctlServer(t, Controls{AllowControl: true}, false)
	defer stopNLB()
	if code := post(t, nlb, "/control/verify", nil, nil); code != http.StatusForbidden {
		t.Errorf("non-loopback no-password verify: %d, want 403", code)
	}

	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	if code := post(t, "http://"+s.Addr(), "/control/verify", nil, nil); code != http.StatusNotFound {
		t.Errorf("disabled-controls verify: %d, want 404 (route absent)", code)
	}
}

// A wrong verify and a wrong real action must be indistinguishable (no cleaner oracle).
func TestControlVerifyOracleHygiene(t *testing.T) {
	base, _, stop := ctlServer(t, Controls{AllowControl: true, Password: "s3cret"}, false)
	defer stop()
	vc, vb := postBody(t, base, "/control/verify", map[string]string{"X-Diag-Password": "wrong"})
	ac, ab := postBody(t, base, "/control/flush-cache", map[string]string{"X-Diag-Password": "wrong"})
	if vc != ac || vb != ab {
		t.Errorf("verify-fail (%d %q) must equal action-fail (%d %q)", vc, vb, ac, ab)
	}
}

// Failed-password attempts trigger a shared exponential backoff across verify AND real
// actions, so a side-effect-free probe can't be a friction-free brute-force oracle.
func TestControlAuthBackoff(t *testing.T) {
	var flushed atomic.Int32
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	s.WithControls(Controls{AllowControl: true, Password: "s3cret", FlushCache: func() { flushed.Add(1) }})
	var nowNs atomic.Int64
	nowNs.Store(time.Unix(1_000_000, 0).UnixNano())
	s.now = func() time.Time { return time.Unix(0, nowNs.Load()) } // race-safe controllable clock
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	base := "http://" + s.Addr()
	wrong := map[string]string{"X-Diag-Password": "nope"}
	right := map[string]string{"X-Diag-Password": "s3cret"}

	// The first 5 failures are within the grace window: each is a plain 401, no block.
	for i := 0; i < 5; i++ {
		if code := post(t, base, "/control/verify", nil, wrong); code != http.StatusUnauthorized {
			t.Fatalf("grace attempt %d: %d, want 401", i+1, code)
		}
	}
	// The 6th failure arms the backoff; the next attempt is 429 — even with the CORRECT
	// password, and even against a different endpoint (the throttle is shared).
	if code := post(t, base, "/control/verify", nil, wrong); code != http.StatusUnauthorized {
		t.Fatalf("6th wrong: %d, want 401", code)
	}
	if code := post(t, base, "/control/flush-cache", nil, right); code != http.StatusTooManyRequests {
		t.Errorf("correct password during backoff: %d, want 429 (shared throttle)", code)
	}
	if flushed.Load() != 0 {
		t.Errorf("nothing should have flushed during backoff")
	}
	// After the window elapses, the correct password works and resets the counter.
	nowNs.Store(time.Unix(1_000_002, 0).UnixNano()) // +2s > the 1s backoff
	if code := post(t, base, "/control/flush-cache", nil, right); code != http.StatusOK {
		t.Fatalf("after backoff, correct password: %d, want 200", code)
	}
	if flushed.Load() != 1 {
		t.Errorf("flush fired %d, want 1", flushed.Load())
	}
	// Reset means a fresh single failure is a plain 401 again, not immediately blocked.
	if code := post(t, base, "/control/verify", nil, wrong); code != http.StatusUnauthorized {
		t.Errorf("post-reset single failure: %d, want 401", code)
	}
}

// The lock UI renders only in password mode; loopback mode shows the controls with no
// password/lock affordances at all.
func TestControlLockUI(t *testing.T) {
	base, _, stop := ctlServer(t, Controls{AllowControl: true, Password: "s3cret"}, true)
	defer stop()
	_, html := get(t, base+"/")
	// pwentry (the field+Unlock group) and lockbtn are toggled mutually exclusively by JS,
	// so the unlocked state never shows both an Unlock and a Lock button.
	for _, want := range []string{`id="chip-controls"`, `id="pwerr"`, `id="pwentry"`, `id="lockbtn"`, `/control/verify`} {
		if !strings.Contains(html, want) {
			t.Errorf("password-mode HTML missing %q", want)
		}
	}

	base2, _, stop2 := ctlServer(t, Controls{AllowControl: true}, true)
	defer stop2()
	_, html2 := get(t, base2+"/")
	if !strings.Contains(html2, `id="controls"`) {
		t.Error("loopback: the controls section should still render")
	}
	if strings.Contains(html2, `id="chip-controls"`) || strings.Contains(html2, `id="pwform"`) {
		t.Error("loopback (no password) must NOT render the lock chip or password form")
	}
}
