// Package mockedge is the shared test fabric for splitdns's external edges (design
// S25): an in-process Cloudflare REST API, authoritative/forwarding DNS servers, an
// mDNS announcer, and a reverse-proxy vhost feed. It replaces the per-package ad-hoc mocks
// so every test exercises the SAME faithful edge behavior (pagination, fault
// injection, a mutation log), and is the mock layer the netns e2e harness wires in.
//
// It imports nothing from the production packages it serves — it only speaks their
// wire formats — so any test package may import it without a cycle.
package mockedge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CFRecord is a seeded/stored Cloudflare DNS record.
type CFRecord struct {
	ID       string
	ZoneID   string
	Type     string
	Name     string
	Content  string
	Proxied  bool
	TTL      int
	Priority float64
}

// Mutation records one write the client made, for assertions.
type Mutation struct {
	Op       string // "create" | "update" | "delete"
	ZoneID   string
	RecordID string
	Type     string
	Name     string
	Content  string
}

// Fault injects API failures. Status>0 returns that HTTP status with an error
// envelope; Delay sleeps before responding; Down hijacks and resets the connection.
// Times>0 limits the fault to that many requests (then it self-clears); Times==0
// applies to every request until cleared.
type Fault struct {
	Status int
	Delay  time.Duration
	Down   bool
	Times  int
}

// CloudflareMock is an in-process stand-in for the Cloudflare v4 API: zones, paged
// dns_records list (honoring page/per_page), and create/update/delete, with token
// auth, a mutation log, and injectable faults.
type CloudflareMock struct {
	mu        sync.Mutex
	token     string
	zones     []zone
	recs      map[string]*CFRecord // id -> record
	nextID    int
	mutations []Mutation
	fault     Fault
	calls     int
}

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// NewCloudflare returns a mock requiring the given bearer token.
func NewCloudflare(token string) *CloudflareMock {
	return &CloudflareMock{token: token, recs: map[string]*CFRecord{}}
}

// Start wraps the mock in an httptest.Server (caller closes it).
func (m *CloudflareMock) Start() *httptest.Server { return httptest.NewServer(m) }

// AddZone registers a zone id/name pair.
func (m *CloudflareMock) AddZone(id, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zones = append(m.zones, zone{ID: id, Name: name})
}

// Seed inserts a record (assigning an ID if absent) and returns its ID.
func (m *CloudflareMock) Seed(zoneID string, r CFRecord) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seedLocked(zoneID, r)
}

func (m *CloudflareMock) seedLocked(zoneID string, r CFRecord) string {
	if r.ID == "" {
		m.nextID++
		r.ID = "rec" + strconv.Itoa(m.nextID)
	}
	r.ZoneID = zoneID
	cp := r
	m.recs[r.ID] = &cp
	return r.ID
}

// SeedApex synthesizes the apex SOA + NS records for a zone (the metadata a real CF
// zone carries), so zone-building paths see a complete apex.
func (m *CloudflareMock) SeedApex(zoneID, apex string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seedLocked(zoneID, CFRecord{Type: "NS", Name: apex, Content: "ns1." + apex, TTL: 3600})
	m.seedLocked(zoneID, CFRecord{Type: "NS", Name: apex, Content: "ns2." + apex, TTL: 3600})
	m.seedLocked(zoneID, CFRecord{Type: "SOA", Name: apex,
		Content: "ns1." + apex + " hostmaster." + apex + " 2024010100 7200 3600 1209600 300", TTL: 3600})
}

// SetFault installs (or clears, with the zero value) a fault.
func (m *CloudflareMock) SetFault(f Fault) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fault = f
}

// Mutations returns a copy of the write log.
func (m *CloudflareMock) Mutations() []Mutation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Mutation(nil), m.mutations...)
}

// Calls returns how many requests were served (incl. faulted ones).
func (m *CloudflareMock) Calls() int { m.mu.Lock(); defer m.mu.Unlock(); return m.calls }

// Content returns a record's current content (or "").
func (m *CloudflareMock) Content(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.recs[id]; ok {
		return r.Content
	}
	return ""
}

// ContentsForZone lists every record content in a zone (order unspecified).
func (m *CloudflareMock) ContentsForZone(zoneID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, r := range m.recs {
		if r.ZoneID == zoneID {
			out = append(out, r.Content)
		}
	}
	return out
}

func (m *CloudflareMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.calls++
	if m.applyFaultLocked(w) {
		m.mu.Unlock()
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+m.token {
		m.mu.Unlock()
		writeErr(w, http.StatusForbidden, 9109, "bad token")
		return
	}
	m.mu.Unlock()

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "zones" && r.Method == http.MethodGet:
		m.handleZones(w, r)
	case len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == http.MethodGet:
		m.handleListRecords(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == http.MethodPost:
		m.handleCreate(w, r, parts[1])
	case len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == http.MethodPatch:
		m.handleUpdate(w, r, parts[1], parts[3])
	case len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == http.MethodDelete:
		m.handleDelete(w, parts[1], parts[3])
	default:
		writeErr(w, http.StatusNotFound, 7003, "no route")
	}
}

// applyFaultLocked enacts the configured fault (caller holds mu). Returns true if it
// handled the response. Down hijacks and resets the connection.
func (m *CloudflareMock) applyFaultLocked(w http.ResponseWriter) bool {
	f := m.fault
	if f.Status == 0 && f.Delay == 0 && !f.Down {
		return false
	}
	if f.Times > 0 {
		m.fault.Times--
		if m.fault.Times == 0 {
			m.fault = Fault{}
		}
	}
	if f.Delay > 0 {
		time.Sleep(f.Delay)
	}
	if f.Down {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close() // reset: client sees EOF/connection error
			}
		}
		return true
	}
	if f.Status != 0 {
		writeErr(w, f.Status, 10000, "injected fault")
		return true
	}
	return false
}

func (m *CloudflareMock) handleZones(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	all := make([]any, 0, len(m.zones))
	for _, z := range m.zones {
		all = append(all, z)
	}
	m.mu.Unlock()
	writePage(w, all, r)
}

func (m *CloudflareMock) handleListRecords(w http.ResponseWriter, r *http.Request, zoneID string) {
	name := strings.ToLower(r.URL.Query().Get("name"))
	m.mu.Lock()
	var matched []*CFRecord
	for _, rec := range m.recs {
		if rec.ZoneID != zoneID {
			continue
		}
		if name != "" && strings.ToLower(rec.Name) != name {
			continue
		}
		matched = append(matched, rec)
	}
	m.mu.Unlock()
	// Deterministic order so pagination across separate requests never overlaps or
	// drops a record (the map's iteration order is random).
	sort.Slice(matched, func(i, j int) bool { return matched[i].ID < matched[j].ID })
	all := make([]any, len(matched))
	for i, rec := range matched {
		all[i] = recJSON(rec)
	}
	writePage(w, all, r)
}

func (m *CloudflareMock) handleCreate(w http.ResponseWriter, r *http.Request, zoneID string) {
	var body CFRecord
	decodeRec(r, &body)
	m.mu.Lock()
	id := m.seedLocked(zoneID, body)
	rec := *m.recs[id]
	m.mutations = append(m.mutations, Mutation{Op: "create", ZoneID: zoneID, RecordID: id, Type: rec.Type, Name: rec.Name, Content: rec.Content})
	m.mu.Unlock()
	writeOK(w, recJSON(&rec))
}

func (m *CloudflareMock) handleUpdate(w http.ResponseWriter, r *http.Request, zoneID, id string) {
	var body CFRecord
	decodeRec(r, &body)
	m.mu.Lock()
	rec, ok := m.recs[id]
	if !ok {
		m.mu.Unlock()
		writeErr(w, http.StatusNotFound, 81044, "record not found")
		return
	}
	rec.Type, rec.Content, rec.Name = body.Type, body.Content, body.Name
	snapshot := *rec
	m.mutations = append(m.mutations, Mutation{Op: "update", ZoneID: zoneID, RecordID: id, Type: rec.Type, Name: rec.Name, Content: rec.Content})
	m.mu.Unlock()
	writeOK(w, recJSON(&snapshot))
}

func (m *CloudflareMock) handleDelete(w http.ResponseWriter, zoneID, id string) {
	m.mu.Lock()
	delete(m.recs, id)
	m.mutations = append(m.mutations, Mutation{Op: "delete", ZoneID: zoneID, RecordID: id})
	m.mu.Unlock()
	writeOK(w, map[string]string{"id": id})
}

// --- JSON helpers (emit the exact envelope shape the real client parses) ---

func recJSON(r *CFRecord) map[string]any {
	return map[string]any{
		"id": r.ID, "type": r.Type, "name": r.Name, "content": r.Content,
		"proxied": r.Proxied, "ttl": r.TTL, "priority": r.Priority,
	}
}

func decodeRec(r *http.Request, dst *CFRecord) {
	var body struct {
		Type     string  `json:"type"`
		Name     string  `json:"name"`
		Content  string  `json:"content"`
		Proxied  bool    `json:"proxied"`
		TTL      int     `json:"ttl"`
		Priority float64 `json:"priority"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	dst.Type, dst.Name, dst.Content = body.Type, body.Name, body.Content
	dst.Proxied, dst.TTL, dst.Priority = body.Proxied, body.TTL, body.Priority
}

// writePage paginates all by the request's page/per_page and emits the envelope with
// result_info (so the client's drain loop is genuinely exercised).
func writePage(w http.ResponseWriter, all []any, r *http.Request) {
	perPage := atoiDefault(r.URL.Query().Get("per_page"), len(all))
	if perPage <= 0 {
		perPage = len(all)
		if perPage == 0 {
			perPage = 1
		}
	}
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	if page < 1 {
		page = 1
	}
	total := len(all)
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	raw, _ := json.Marshal(all[start:end])
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true, "errors": []any{},
		"result":      json.RawMessage(raw),
		"result_info": map[string]int{"page": page, "total_pages": totalPages},
	})
}

func writeOK(w http.ResponseWriter, result any) {
	raw, _ := json.Marshal(result)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true, "errors": []any{},
		"result":      json.RawMessage(raw),
		"result_info": map[string]int{"page": 1, "total_pages": 1},
	})
}

func writeErr(w http.ResponseWriter, status, code int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"errors":  []map[string]any{{"code": code, "message": msg}},
	})
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
