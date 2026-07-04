package diag

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/gutschke/splitdns/internal/model"
)

func diagWithSnap(t *testing.T, addr string) *Server {
	t.Helper()
	snap := testSnap()
	return New(addr, func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
}

// A Unix-socket bind serves the views and is treated as loopback (no-password control OK).
func TestUnixSocketBind(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "diag.sock")
	var flushed bool
	s := diagWithSnap(t, sock)
	s.WithControls(Controls{AllowControl: true, FlushCache: func() { flushed = true }})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start unix: %v", err)
	}
	defer s.Shutdown(context.Background())
	if s.Addr() != sock {
		t.Errorf("Addr() = %q, want the socket path", s.Addr())
	}

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	resp, err := client.Get("http://unix/healthz")
	if err != nil {
		t.Fatalf("GET over unix: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("healthz over unix = %d, want 200", resp.StatusCode)
	}
	// Control works WITHOUT a password (unix counts as loopback).
	req, _ := http.NewRequest("POST", "http://unix/control/flush-cache", nil)
	req.Header.Set("X-Diag-Control", "1") // CSRF token the in-page fetch always sends
	cr, err := client.Do(req)
	if err != nil {
		t.Fatalf("control over unix: %v", err)
	}
	cr.Body.Close()
	if cr.StatusCode != 200 || !flushed {
		t.Errorf("unix control flush: status=%d flushed=%v, want 200/true", cr.StatusCode, flushed)
	}
}

// A failed Unix-socket bind (e.g. a missing parent directory, as can happen with a
// shared reverse-proxy dir) returns an error cleanly — no panic — and the Server stays
// safe to keep around. The daemon treats this as benign and DNS keeps serving.
func TestUnixBindFailureIsClean(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "missing-dir", "diag.sock") // parent does not exist
	s := diagWithSnap(t, bad)
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("expected an error binding a socket into a nonexistent directory")
	}
	_ = s.Addr()                     // must not panic
	s.Shutdown(context.Background()) // must be a safe no-op (no listener was created)
}

// WithSocketMode sets the Unix-socket permission (for cross-container reverse-proxy use).
func TestUnixSocketMode(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "diag.sock")
	s := diagWithSnap(t, sock)
	s.WithSocketMode(0o666)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Shutdown(context.Background())
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if fi.Mode().Perm() != 0o666 {
		t.Errorf("socket mode = %o, want 0666", fi.Mode().Perm())
	}
}

// The source-IP allow-list gates every route.
func TestAccessAllowList(t *testing.T) {
	deny := diagWithSnap(t, "127.0.0.1:0")
	deny.WithAccess(func(netip.Addr) bool { return false })
	if err := deny.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer deny.Shutdown(context.Background())
	if code, _ := get(t, "http://"+deny.Addr()+"/"); code != http.StatusForbidden {
		t.Errorf("denied client: status = %d, want 403", code)
	}

	allow := diagWithSnap(t, "127.0.0.1:0")
	allow.WithAccess(func(ip netip.Addr) bool { return ip.IsLoopback() })
	if err := allow.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer allow.Shutdown(context.Background())
	if code, _ := get(t, "http://"+allow.Addr()+"/"); code != 200 {
		t.Errorf("allowed loopback client: status = %d, want 200", code)
	}
}
