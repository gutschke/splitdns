package diag

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gutschke/splitdns/internal/model"
)

func TestRootRendersConfigPanelAndBadge(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan"}
	view := &model.MDNSView{Forward: map[string][]model.RR{"56442ef43e60884b27a10de08f8fa439": {{Type: 1, Content: "192.0.2.9"}}}}
	s := New("127.0.0.1:0", func() *model.Snapshot { return snap }, func() *model.MDNSView { return view }, "t", nil).WithConfigFile("/dev/null")
	rec := httptest.NewRecorder()
	s.handleRoot(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "cfgpanel") {
		t.Error("config panel missing from render")
	}
	if !strings.Contains(body, `<span class="badge">id</span>`) {
		t.Error("id badge missing for a machine-id host")
	}
}
