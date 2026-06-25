package diag

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

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
