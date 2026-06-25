package diag

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gutschke/splitdns/internal/model"
)

func selfTestServer(t *testing.T, fn func(context.Context) []TestResult) (string, func()) {
	t.Helper()
	snap := testSnap()
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return &model.MDNSView{} }, "t", nil)
	s.WithSelfTest(fn)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return "http://" + s.Addr(), func() { s.Shutdown(context.Background()) }
}

// /selftest runs the provider and renders JSON; the main page links to it.
func TestSelfTestJSON(t *testing.T) {
	base, stop := selfTestServer(t, func(context.Context) []TestResult {
		return []TestResult{{Name: "upstream-resolve", OK: true, Detail: "rcode=NOERROR"}, {Name: "cloudflare-token", OK: false, Detail: "boom"}}
	})
	defer stop()

	code, body := get(t, base+"/selftest")
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	var results []TestResult
	if err := json.Unmarshal([]byte(body), &results); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(results) != 2 || results[0].Name != "upstream-resolve" || !results[0].OK || results[1].OK {
		t.Errorf("unexpected results: %+v", results)
	}

	// The main page advertises the link.
	_, html := get(t, base+"/")
	if !strings.Contains(html, `href="/selftest"`) {
		t.Error("main page missing the self-tests link")
	}
}

// The self-test endpoint is rate-limited (active probes).
func TestSelfTestRateLimited(t *testing.T) {
	base, stop := selfTestServer(t, func(context.Context) []TestResult { return nil })
	defer stop()
	if code, _ := get(t, base+"/selftest"); code != 200 {
		t.Fatalf("first call status = %d, want 200", code)
	}
	if code, _ := get(t, base+"/selftest"); code != http.StatusTooManyRequests {
		t.Errorf("immediate second call status = %d, want 429", code)
	}
}

// HTML rendering shows PASS/FAIL.
func TestSelfTestHTML(t *testing.T) {
	base, stop := selfTestServer(t, func(context.Context) []TestResult {
		return []TestResult{{Name: "x", OK: true}, {Name: "y", OK: false}}
	})
	defer stop()
	req, _ := http.NewRequest("GET", base+"/selftest", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	html := string(buf[:n])
	if !strings.Contains(html, "PASS") || !strings.Contains(html, "FAIL") {
		t.Errorf("HTML missing PASS/FAIL: %s", html)
	}
}
