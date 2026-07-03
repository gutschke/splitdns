package diag

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gutschke/splitdns/internal/model"
)

func TestRedactConfig(t *testing.T) {
	in := []byte(`read_token_file = "/etc/splitdns/secrets/cf.token"
control_password = "hunter2"
tsig_secret = "bXlzZWNyZXQ="
tsig_keys = [ { name = "n", secret = "AbCdEf0123456789==" } ]
`)
	out := redactConfig(in)
	for _, leak := range []string{"hunter2", "bXlzZWNyZXQ=", "AbCdEf0123456789=="} {
		if strings.Contains(out, leak) {
			t.Errorf("secret %q leaked:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "/etc/splitdns/secrets/cf.token") {
		t.Errorf("*_file path must be preserved:\n%s", out)
	}
	if strings.Count(out, "***REDACTED***") != 3 {
		t.Errorf("want 3 redactions, got:\n%s", out)
	}
}

func TestClassifyHost(t *testing.T) {
	for _, id := range []string{"0912320f-cbf9-4f76-bc56-82eb9444b0a2", "56442ef43e60884b27a10de08f8fa439"} {
		if classifyHost(id) != "id" {
			t.Errorf("%q should classify as id", id)
		}
	}
	for _, host := range []string{"printer", "webserver", "router", "living-room-tv"} {
		if classifyHost(host) != "" {
			t.Errorf("%q should NOT be an id", host)
		}
	}
}

func TestConfigEndpointRedacts(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(f, []byte("control_password = \"topsecret\"\nlocal = [\"example.com\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New("127.0.0.1:0", func() *model.Snapshot { return &model.Snapshot{} },
		func() *model.MDNSView { return &model.MDNSView{} }, "t", nil).WithConfigFile(f)
	rec := httptest.NewRecorder()
	s.handleConfig(rec, httptest.NewRequest("GET", "/config", nil))
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "topsecret") {
		t.Errorf("secret leaked via /config:\n%s", body)
	}
	if !strings.Contains(body, "example.com") {
		t.Errorf("non-secret config should be shown:\n%s", body)
	}
}
