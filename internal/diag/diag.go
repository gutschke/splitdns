// Package diag is the read-only diagnostics HTTP endpoint (requirement R10, design
// §4.8). It renders the live snapshot — zones, records, reverse/stub zones, vhosts,
// the mDNS view, and health/staleness — as HTML or JSON. It is hardened: localhost
// only by default, GET only, NO reflected query params, NO secrets, and CF ZoneID/
// RecordID are REDACTED (account-correlatable, and the hot path never reads them).
package diag

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/anscache"
	"github.com/gutschke/splitdns/internal/ddns"
	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/hostinfo"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
	"github.com/gutschke/splitdns/internal/qlog"
	"github.com/gutschke/splitdns/internal/supervisor"
)

// Server serves the diagnostics views. It reads the live planes through accessors so
// the control plane can swap snapshots atomically underneath it.
type Server struct {
	addr           string
	snapshot       func() *model.Snapshot
	view           func() *model.MDNSView
	cacheStats     func() (anscache.Stats, bool)    // nil or (_, false) => cache disabled
	cacheEntries   func(n int) []anscache.EntryStat // nil => hottest-entries table omitted
	qlog           *qlog.Log                        // query telemetry; nil => section omitted
	backends       func() []forwarder.BackendStatus
	workers        func() map[string]supervisor.WorkerStats
	encStatus      func() *EncStatus // encrypted front-end (DoT/DoH)+DDR status; nil => omitted
	transportQuery func(ctx context.Context, transport, name, qtype string) TransportResult
	selftest       func(context.Context) []TestResult
	ddnsSim        func(ctx context.Context, host string, addrs []netip.Addr, ignoreEligible bool) ddns.SimResult
	clientName     func(netip.Addr) string // resolve a client IP to a name (cache/mDNS only)
	clientDevice   func(netip.Addr) string // guess a client's device/vendor from its MAC (nil => omitted)
	allow          func(netip.Addr) bool   // nil => allow all sources
	socketMode     os.FileMode             // Unix-socket permission (0 => 0660)
	controls       Controls
	loopback       bool // set at Start: is the bound address loopback-only?
	controlsActive bool // set at Start: controls enabled AND (password set OR loopback)
	log            func(string)
	version        string
	configFile     string                                  // path shown (redacted) in the config panel; "" => panel omitted
	hostInfo       func(name string) (hostinfo.Info, bool) // lazy per-host enrichment; nil => omitted

	now func() time.Time // injectable clock for rate-limit/backoff tests (default time.Now)

	hs      *http.Server
	ctlMu   sync.Mutex
	ctlLast map[string]time.Time // per-action last-run, for rate limiting
	// Shared failed-password backoff (guarded by ctlMu). Covers BOTH /control/<action>
	// and /control/verify, so a side-effect-free verify can't be a friction-free
	// brute-force oracle. Global (not per-IP): a LAN attacker rotates source addresses,
	// so a single counter is the real backstop.
	authFails      int
	authBlockUntil time.Time
}

// New builds a diagnostics Server. snapshot/view must be non-nil; log may be nil.
func New(addr string, snapshot func() *model.Snapshot, view func() *model.MDNSView, version string, log func(string)) *Server {
	if log == nil {
		log = func(string) {}
	}
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	return &Server{addr: addr, snapshot: snapshot, view: view, version: version, log: log, ctlLast: map[string]time.Time{}, now: time.Now}
}

// WithConfigFile enables the collapsible config panel, served lazily (on tab-expand, not in
// the polled JSON) from GET /config with cryptographic material redacted. Empty path omits
// the panel.
func (s *Server) WithConfigFile(path string) *Server { s.configFile = path; return s }

// WithHostInfo wires lazy per-host enrichment (vendor/MAC/scope), served from GET
// /host?name=<label> only for hosts present in the mDNS view. The provider returns
// (info, true) for a known host and (_, false) otherwise.
func (s *Server) WithHostInfo(fn func(name string) (hostinfo.Info, bool)) *Server {
	s.hostInfo = fn
	return s
}

// handleHostInfo serves enrichment for a single mDNS host. Lazy (only on demand), bounded to
// known hosts (unknown names are 404, so it can't be driven for arbitrary work), and cached
// by the provider. All data is local; nothing is sent off the box.
func (s *Server) handleHostInfo(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("name")))
	if name == "" || len(name) > 253 {
		http.Error(w, "usage: /host?name=<mdns-label>", http.StatusBadRequest)
		return
	}
	info, ok := s.hostInfo(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(info)
}

const secretKeyAlt = `secret|tsig_secret|control_password|password|passwd|token|api_key|apikey`

// secretKeyLine matches a LINE-START assignment to a secret key (quoted keys allowed),
// capturing the "key = " prefix (group 1) so the WHOLE value — single-line, multi-line
// ("""/”'), or array — can be replaced. The `*_file` path keys don't match: after the
// keyword the regex requires `=`, but `secret_file` has `_file` there.
var secretKeyLine = regexp.MustCompile(`(?i)^(\s*"?(?:` + secretKeyAlt + `)"?\s*=\s*)(.*)$`)

// secretInline redacts a single-line secret assignment appearing ANYWHERE on a line (e.g.
// a `secret = "…"` inside an inline table), replacing just its value (group 3).
var secretInline = regexp.MustCompile(`(?i)\b(` + secretKeyAlt + `)(\s*=\s*)("[^"]*"|'[^']*'|[^\s,}\]]+)`)

// redactConfig masks inline cryptographic material in a raw TOML config so the config panel
// never discloses a key/token/password even if the operator inlined one instead of using a
// *_file reference. It handles single-line values, TOML multi-line strings ("""…""" /
// ”'…”'), and arrays (whose body may span lines), plus secrets embedded in inline tables.
func redactConfig(b []byte) string {
	var out []string
	closer := "" // when set, we are inside a redacted multi-line/array value: drop lines until it closes
	for _, line := range strings.Split(string(b), "\n") {
		if closer != "" {
			if strings.Contains(line, closer) {
				closer = ""
			}
			continue // drop the redacted body (and the line that closes it)
		}
		if m := secretKeyLine.FindStringSubmatch(line); m != nil {
			out = append(out, m[1]+`"***REDACTED***"`)
			switch val := strings.TrimSpace(m[2]); {
			case strings.HasPrefix(val, `"""`) && !strings.Contains(val[3:], `"""`):
				closer = `"""`
			case strings.HasPrefix(val, `'''`) && !strings.Contains(val[3:], `'''`):
				closer = `'''`
			case strings.HasPrefix(val, "[") && !strings.Contains(val, "]"):
				closer = "]"
			}
			continue
		}
		out = append(out, secretInline.ReplaceAllString(line, `$1$2"***REDACTED***"`))
	}
	return strings.Join(out, "\n")
}

// handleConfig serves the redacted config file. Read on demand (small file, only hit on
// tab-expand), never cached in the polled payload.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if s.configFile == "" {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(s.configFile)
	if err != nil {
		http.Error(w, "config unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprintf(w, "# %s (cryptographic material redacted)\n%s", s.configFile, redactConfig(b))
}

// WithCacheStats wires a provider for the forward-path answer-cache counters. fn
// returns (stats, true) when the cache is enabled and (zero, false) when it is off.
func (s *Server) WithCacheStats(fn func() (anscache.Stats, bool)) *Server {
	s.cacheStats = fn
	return s
}

// WithCacheEntries wires a provider listing the hottest live cache entries (read-only;
// it neither records stats nor touches LRU order). nil omits the per-entry table.
func (s *Server) WithCacheEntries(fn func(n int) []anscache.EntryStat) *Server {
	s.cacheEntries = fn
	return s
}

// WithQueryLog wires the query telemetry (recent queries + top clients + totals).
func (s *Server) WithQueryLog(l *qlog.Log) *Server { s.qlog = l; return s }

// WithBackends wires a provider for upstream/backend health (circuit-breaker status).
func (s *Server) WithBackends(fn func() []forwarder.BackendStatus) *Server { s.backends = fn; return s }

// WithEncrypted wires a provider for the encrypted front-end (DoT/DoH) + DDR status.
func (s *Server) WithEncrypted(fn func() *EncStatus) *Server { s.encStatus = fn; return s }

// EncStatus is the encrypted-front-end (DoT/DoH) and DDR advertising status the console
// renders, so an operator can see the certificate and debug why clients don't upgrade.
type EncStatus struct {
	Enabled      bool       `json:"enabled"`
	ADN          string     `json:"adn,omitempty"`
	CertValid    bool       `json:"cert_valid"`
	Expiry       string     `json:"expiry,omitempty"` // pre-rendered, e.g. "in 41d (2026-…)" / "EXPIRED"
	SANs         []string   `json:"sans,omitempty"`   // certificate SAN DNS names
	DoT          []string   `json:"dot,omitempty"`    // bound DoT listener addresses
	DoH          []string   `json:"doh,omitempty"`    // bound DoH listener addresses
	DoHPath      string     `json:"doh_path,omitempty"`
	AdvertiseDDR bool       `json:"advertise_ddr"`
	DDRReady     bool       `json:"ddr_ready"`      // the SVCB designation is currently served
	SVCB         []string   `json:"svcb,omitempty"` // the SVCB RRs actually served at _dns.resolver.arpa
	Checks       []EncCheck `json:"checks,omitempty"`
}

// EncCheck is one precondition for DDR upgrade (the "why won't clients upgrade" list).
type EncCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// TransportResult is the outcome of a diagnostic query issued at the resolver over a
// specific transport (Do53/DoT/DoH) — including TLS handshake details, which is exactly
// what tells you why a client fails to upgrade.
type TransportResult struct {
	Transport string   `json:"transport"`
	Target    string   `json:"target,omitempty"`
	Query     string   `json:"query"`
	OK        bool     `json:"ok"`
	Rcode     string   `json:"rcode,omitempty"`
	Answer    []string `json:"answer,omitempty"`
	TLS       string   `json:"tls,omitempty"` // negotiated version + ALPN + peer cert
	LatencyMS float64  `json:"latency_ms"`
	Err       string   `json:"error,omitempty"`
}

// WithTransportQuery wires the transport tester (GET /tquery): it runs a query at the
// resolver over the chosen transport and reports the result. nil omits the tool.
func (s *Server) WithTransportQuery(fn func(ctx context.Context, transport, name, qtype string) TransportResult) *Server {
	s.transportQuery = fn
	return s
}

// WithWorkers wires a provider for supervisor worker stats (restarts/stalls/panics).
func (s *Server) WithWorkers(fn func() map[string]supervisor.WorkerStats) *Server {
	s.workers = fn
	return s
}

// Controls configures the DANGEROUS, mutating control actions. They are exposed only
// when AllowControl is true, are POST-only, and are authorized either by a matching
// Password or — when Password is empty — only on a loopback bind. Each action is a
// callback; a nil callback means that action is unavailable.
type Controls struct {
	AllowControl  bool
	Password      string
	FlushCache    func()                               // drop every answer-cache entry
	RefreshMirror func()                               // force a Cloudflare mirror refresh (restarts the mirror worker)
	Restart       func()                               // trigger a graceful daemon restart (systemd brings it back)
	SetBackend    func(addr string, enabled bool) bool // disable/enable an upstream on the fly (false => unknown addr)
	ResetBackends func()                               // clear all manual backend disables
}

func (c Controls) enabled() bool { return c.AllowControl }

// WithControls wires the mutating control plane. Safe to omit (controls disabled).
func (s *Server) WithControls(c Controls) *Server { s.controls = c; return s }

// WithClientNames wires a resolver from a client IP to a display name (from the mDNS
// view / answer cache only — no network lookups). Used to annotate the query telemetry.
func (s *Server) WithClientNames(fn func(netip.Addr) string) *Server { s.clientName = fn; return s }

// WithClientDevice wires a cheap, passive device/vendor guess (from the client's MAC via
// the local neighbor table / EUI-64) shown next to each client in the Queries panel. It runs
// in the poll, so the provider must be cached and must NOT probe the network.
func (s *Server) WithClientDevice(fn func(netip.Addr) string) *Server { s.clientDevice = fn; return s }

// WithAccess restricts which source IPs may reach the endpoint. nil (the default) allows
// all. Unix-socket clients are always allowed.
func (s *Server) WithAccess(allow func(netip.Addr) bool) *Server { s.allow = allow; return s }

// WithSocketMode sets the permission applied to a Unix-socket bind (0 => 0660).
func (s *Server) WithSocketMode(m os.FileMode) *Server { s.socketMode = m; return s }

// TestResult is one self-test outcome (Tier-1 active probe — reads/probes, mutates nothing).
type TestResult struct {
	Name     string        `json:"name"`
	OK       bool          `json:"ok"`
	Detail   string        `json:"detail"`
	Duration time.Duration `json:"-"`
	DurMS    float64       `json:"ms"`
}

// WithSelfTest wires the on-demand self-test runner (GET /selftest). fn runs active
// probes (upstream reachability, CF token validity, end-to-end local resolve, …) and
// returns their results; it must not mutate state. nil omits the endpoint.
func (s *Server) WithSelfTest(fn func(context.Context) []TestResult) *Server {
	s.selftest = fn
	return s
}

// WithDDNSSimulate wires the DDNS dry-run simulator (GET /ddns-simulate?host=&addr=…). It
// reports the Cloudflare API calls write-back WOULD make for an announcement, without
// making them and even when DDNS is disabled. nil omits the endpoint.
func (s *Server) WithDDNSSimulate(fn func(ctx context.Context, host string, addrs []netip.Addr, ignoreEligible bool) ddns.SimResult) *Server {
	s.ddnsSim = fn
	return s
}

// Start binds and serves until ctx is cancelled. It returns once bound (so tests can
// query immediately). Binding a non-loopback address is allowed (configurable) but
// warned about, since the endpoint exposes inventory and is meant to stay local.
func (s *Server) Start(ctx context.Context) error {
	var ln net.Listener
	if path, ok := unixAddr(s.addr); ok {
		// Unix socket: local-only and filesystem-permission-controlled (0660). Counts as
		// loopback for the control gate — the filesystem perms ARE the authentication.
		s.loopback = true
		if !strings.HasPrefix(path, "@") { // not the abstract namespace
			_ = os.Remove(path) // clear a stale socket from a previous run
		}
		l, err := net.Listen("unix", path)
		if err != nil {
			return fmt.Errorf("diag: listen unix %s: %w", path, err)
		}
		if !strings.HasPrefix(path, "@") {
			mode := s.socketMode
			if mode == 0 {
				mode = 0o660
			}
			if cerr := os.Chmod(path, mode); cerr != nil {
				l.Close()
				return fmt.Errorf("diag: chmod %s: %w", path, cerr)
			}
		}
		ln = l
		s.addr = path
	} else {
		// TCP. Classify the bind as loopback-only, failing CLOSED: anything we cannot
		// positively prove is loopback — a wildcard bind, or a hostname we will not
		// resolve — is treated as non-loopback (a hostname must not default to loopback).
		s.loopback = false
		if host, _, err := net.SplitHostPort(s.addr); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				s.loopback = ip.IsLoopback()
			}
		}
		if !s.loopback {
			s.log(fmt.Sprintf("diag: binding non-loopback %s — keep this behind auth; it exposes the zone inventory", s.addr))
		}
		l, err := net.Listen(netmatch.ListenNetwork("tcp", s.addr), s.addr)
		if err != nil {
			return fmt.Errorf("diag: listen %s: %w", s.addr, err)
		}
		ln = l
		s.addr = l.Addr().String() // record the real bound addr (ephemeral port in tests)
	}
	// Controls are usable only when enabled AND (a password is set OR the bind is
	// loopback/unix). Otherwise the /control/ route is NOT registered at all — "refused"
	// is enforced by the absence of the route, not by a runtime branch a later refactor
	// could bypass.
	s.controlsActive = s.controls.enabled() && (s.controls.Password != "" || s.loopback)
	if s.controls.enabled() && !s.controlsActive {
		s.log("diag: allow_control is set on a non-loopback bind with NO control_password — control actions are DISABLED; set control_password or bind to loopback")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/diag.json", s.handleJSON)
	mux.HandleFunc("/healthz", s.handleHealth)
	if s.selftest != nil {
		mux.HandleFunc("/selftest", s.handleSelfTest)
	}
	if s.ddnsSim != nil {
		mux.HandleFunc("/ddns-simulate", s.handleDDNSSimulate)
	}
	if s.transportQuery != nil {
		mux.HandleFunc("/tquery", s.handleTransportQuery)
	}
	if s.configFile != "" {
		mux.HandleFunc("/config", s.handleConfig)
	}
	if s.hostInfo != nil {
		mux.HandleFunc("/host", s.handleHostInfo)
	}
	if s.controlsActive {
		mux.HandleFunc("/control/", s.handleControl)
	}
	s.hs = &http.Server{Handler: s.accessGuard(s.methodGuard(mux)), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.hs.Serve(ln) }() // returns ErrServerClosed on Shutdown; nothing to do
	return nil
}

// unixAddr reports whether addr names a Unix socket and returns its path. Accepted forms:
// "unix:/path", an absolute path ("/run/…"), or a Linux abstract name ("@name").
func unixAddr(addr string) (string, bool) {
	switch {
	case strings.HasPrefix(addr, "unix:"):
		return strings.TrimPrefix(addr, "unix:"), true
	case strings.HasPrefix(addr, "/"), strings.HasPrefix(addr, "@"):
		return addr, true
	default:
		return "", false
	}
}

// accessGuard restricts which source IPs may reach the endpoint when an allow-list is
// configured. Unix-socket clients (no IP) are always allowed (local). Applies to every
// route, read and control alike.
func (s *Server) accessGuard(h http.Handler) http.Handler {
	if s.allow == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil { // unix socket: RemoteAddr has no host:port — local, allow
			h.ServeHTTP(w, r)
			return
		}
		ip, perr := netip.ParseAddr(host)
		if perr != nil || !s.allow(ip.Unmap()) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Addr returns the bound address (after Start).
func (s *Server) Addr() string {
	if s.hs == nil {
		return s.addr
	}
	return s.addr
}

// Shutdown stops the server.
func (s *Server) Shutdown(ctx context.Context) {
	if s.hs != nil {
		_ = s.hs.Shutdown(ctx)
	}
}

// methodGuard enforces GET/HEAD for the read-only views; the /control/ routes are
// POST-only and police their own method and authorization in handleControl.
func (s *Server) methodGuard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/control/") {
			h.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only endpoint", http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// controlMinInterval rate-limits the disruptive/expensive actions so even an authorized
// client can't restart-loop the daemon or hammer the Cloudflare API. flush-cache is
// idempotent and cheap, so it is unlimited (and the test relies on that).
var controlMinInterval = map[string]time.Duration{
	"refresh-mirror": 10 * time.Second,
	"restart":        10 * time.Second,
	"selftest":       2 * time.Second, // active probes; don't let a client hammer them
	"ddns-simulate":  1 * time.Second,
	"tquery":         1 * time.Second, // issues a real query (incl. a TLS handshake)
}

// handleSelfTest runs the on-demand self-tests (GET) under a bounded context and renders
// HTML or JSON. It probes fixed targets only (no user-supplied destinations), and is
// rate-limited to avoid probe flooding.
func (s *Server) handleSelfTest(w http.ResponseWriter, r *http.Request) {
	if !s.controlRateOK("selftest") {
		http.Error(w, "self-tests rate-limited; retry shortly", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	results := s.selftest(ctx)
	for i := range results {
		results[i].DurMS = float64(results[i].Duration.Microseconds()) / 1000
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := selfTestTmpl.Execute(w, results); err != nil {
			s.log(fmt.Sprintf("diag: selftest render: %v", err))
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}

// handleDDNSSimulate runs a dry DDNS simulation for host=&addr=… (repeatable addr). It
// only reads state and computes a plan — it never writes to Cloudflare — so it is a GET.
func (s *Server) handleDDNSSimulate(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.FormValue("host"))
	if host == "" {
		http.Error(w, "usage: /ddns-simulate?host=<short-host>&addr=<ip>[&addr=<ip>…]", http.StatusBadRequest)
		return
	}
	if !s.controlRateOK("ddns-simulate") { // rate-limit only real simulations, not 400s
		http.Error(w, "rate-limited; retry shortly", http.StatusTooManyRequests)
		return
	}
	var addrs []netip.Addr
	var bad []string
	for _, a := range r.Form["addr"] {
		if ip, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
			addrs = append(addrs, ip)
		} else if a != "" {
			bad = append(bad, a)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res := s.ddnsSim(ctx, host, addrs, r.FormValue("explore") == "1")
	if len(bad) > 0 {
		res.Note = strings.TrimSpace(res.Note + " (ignored unparseable addrs: " + strings.Join(bad, ", ") + ")")
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := ddnsSimTmpl.Execute(w, res); err != nil {
			s.log(fmt.Sprintf("diag: ddns-simulate render: %v", err))
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}

// handleTransportQuery runs a diagnostic query at the resolver over a chosen transport
// (GET; it only queries, never mutates). Renders HTML or JSON.
func (s *Server) handleTransportQuery(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "usage: /tquery?name=<fqdn>&type=A&transport=do53|tcp|dot|doh", http.StatusBadRequest)
		return
	}
	qtype := strings.ToUpper(strings.TrimSpace(r.FormValue("type")))
	if qtype == "" {
		qtype = "A"
	}
	transport := strings.ToLower(strings.TrimSpace(r.FormValue("transport")))
	if transport == "" {
		transport = "do53"
	}
	if !s.controlRateOK("tquery") {
		http.Error(w, "rate-limited; retry shortly", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	res := s.transportQuery(ctx, transport, name, qtype)
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tqueryTmpl.Execute(w, res); err != nil {
			s.log(fmt.Sprintf("diag: tquery render: %v", err))
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}

var tqueryTmpl = template.Must(template.New("tquery").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Transport query</title>
<style>body{font:14px/1.4 system-ui,sans-serif;margin:1.5rem;color:#222}
.ok{color:#161} .flag{color:#c00} .muted{color:#777}
pre{background:#f6f8fa;padding:.6rem;border-radius:4px;overflow:auto}</style>
</head><body>
<h1>Transport query <span class="muted">{{.Transport}}</span></h1><p><a href="/" onclick="if(history.length>1){history.back();return false}">&larr; back</a></p>
<p><b>{{.Query}}</b> via <b>{{.Transport}}</b>{{if .Target}} → {{.Target}}{{end}} —
{{if .OK}}<span class="ok">OK</span>{{else}}<span class="flag">FAILED</span>{{end}}
<span class="muted">({{printf "%.1f" .LatencyMS}} ms)</span></p>
{{if .Err}}<p class="flag">error: {{.Err}}</p>{{end}}
{{if .TLS}}<p class="muted">TLS: {{.TLS}}</p>{{end}}
{{if .Rcode}}<p>rcode: <b>{{.Rcode}}</b></p>{{end}}
{{if .Answer}}<pre>{{range .Answer}}{{.}}
{{end}}</pre>{{end}}
</body></html>`))

var ddnsSimTmpl = template.Must(template.New("ddnssim").Funcs(template.FuncMap{
	"add": func(a, b int) int { return a + b },
}).Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>DDNS simulate</title>
<style>body{font:14px/1.4 system-ui,sans-serif;margin:1.5rem;color:#222}
table{border-collapse:collapse}td,th{padding:.2rem .6rem;text-align:left;border-bottom:1px solid #eee}
.muted{color:#777} .banner{padding:.5rem .7rem;border-radius:4px;margin:.4rem 0}
.explore{background:#fff3cd;border:1px solid #ffe69c} .conf{background:#eef6ee;border:1px solid #cfe6cf}</style>
</head><body>
<h1>DDNS simulate <span class="muted">{{.Host}}</span></h1><p><a href="/" onclick="if(history.length>1){history.back();return false}">&larr; back</a></p>
{{if .Override}}<div class="banner explore"><b>EXPLORE mode</b> — the eligibility allowlist was <b>IGNORED</b>.
This is a <b>what-if</b> for planning policy, <b>not what runs today</b>.</div>
{{else}}<div class="banner conf"><b>As configured</b> — this reflects your current policy exactly.</div>{{end}}
<p>Outcome: <b>{{.Outcome}}</b> &mdash; write-back is {{if .Enabled}}ENABLED{{else}}disabled{{end}}{{if .DryRun}} (dry-run){{end}}.
<b>No Cloudflare calls were made.</b>{{if .Note}}<br><span class="muted">{{.Note}}</span>{{end}}</p>
{{if .Calls}}<table><tr><th>#</th><th>op</th><th>name</th><th>type</th><th>content</th><th>was</th></tr>
{{range $i, $c := .Calls}}<tr><td class="muted">{{add $i 1}}</td><td>{{$c.Op}}</td><td>{{$c.Name}}</td><td>{{$c.Type}}</td><td>{{$c.Content}}</td><td class="muted">{{$c.Old}}</td></tr>
{{end}}</table>
<p class="muted">Runs <b>top-to-bottom</b> in this order: <b>updates &rarr; creates &rarr; deletes</b>. Applying the new addresses before removing the old ones keeps the name resolving throughout (no NXDOMAIN gap). <b>Deletes</b> drop addresses your announcement didn't include — write-back converges the host's records to <b>exactly</b> the addresses announced, so announce all the ones you want to keep.</p>
{{else}}<p class="muted">No API calls would be made.</p>{{end}}
</body></html>`))

var selfTestTmpl = template.Must(template.New("selftest").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>splitdnsd self-tests</title>
<style>body{font:14px/1.4 system-ui,sans-serif;margin:1.5rem;color:#222}
table{border-collapse:collapse}td,th{padding:.2rem .6rem;text-align:left;border-bottom:1px solid #eee}
.ok{color:#080;font-weight:600}.flag{color:#b00;font-weight:600}</style></head><body>
<h1>Self-tests</h1><p><a href="/" onclick="if(history.length>1){history.back();return false}">&larr; back</a></p>
<table><tr><th>check</th><th>result</th><th>detail</th><th>ms</th></tr>
{{range .}}<tr><td>{{.Name}}</td>
<td>{{if .OK}}<span class="ok">PASS</span>{{else}}<span class="flag">FAIL</span>{{end}}</td>
<td>{{.Detail}}</td><td>{{printf "%.1f" .DurMS}}</td></tr>
{{end}}</table></body></html>`))

// handleControl dispatches a mutating control action after authorizing it. POST only.
func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "control actions are POST-only", http.StatusMethodNotAllowed)
		return
	}
	// CSRF defense (Fetch Metadata): a cross-site (or same-site/subdomain) browser form
	// carries Sec-Fetch-Site != same-origin; reject it. Non-browser clients (curl) omit
	// the header, and the in-page same-origin form sends "same-origin", so both pass.
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		http.Error(w, "cross-site control request refused", http.StatusForbidden)
		return
	}
	if code, msg := s.controlAuthorized(r); code != http.StatusOK {
		http.Error(w, msg, code)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/control/")
	if !s.controlRateOK(action) {
		http.Error(w, "control action rate-limited; retry shortly", http.StatusTooManyRequests)
		return
	}
	switch action {
	case "verify":
		// Side-effect-free auth probe so the UI can confirm "unlocked" immediately. It
		// reached here only after passing controlAuthorized (incl. the failed-auth
		// backoff), so just acknowledge — no state change, generic body.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	case "flush-cache":
		if s.controls.FlushCache == nil {
			http.Error(w, "flush-cache unavailable (no cache)", http.StatusNotFound)
			return
		}
		s.controls.FlushCache()
		s.controlOK(w, r, "answer cache flushed")
	case "refresh-mirror":
		if s.controls.RefreshMirror == nil {
			http.Error(w, "refresh-mirror unavailable", http.StatusNotFound)
			return
		}
		s.controls.RefreshMirror()
		s.controlOK(w, r, "mirror refresh triggered")
	case "restart":
		if s.controls.Restart == nil {
			http.Error(w, "restart unavailable", http.StatusNotFound)
			return
		}
		s.controlOK(w, r, "restarting daemon")
		// Trigger AFTER the response is written so the caller sees confirmation; the
		// graceful-shutdown path then tears us down and systemd brings us back.
		s.controls.Restart()
	case "backend":
		if s.controls.SetBackend == nil {
			http.Error(w, "backend control unavailable", http.StatusNotFound)
			return
		}
		switch op := r.FormValue("op"); op {
		case "reset":
			if s.controls.ResetBackends != nil {
				s.controls.ResetBackends()
			}
			s.controlOK(w, r, "backend overrides reset to defaults")
		case "enable", "disable":
			addr := r.FormValue("addr")
			if !s.controls.SetBackend(addr, op == "enable") {
				http.Error(w, "unknown backend addr", http.StatusNotFound)
				return
			}
			s.controlOK(w, r, fmt.Sprintf("backend %s %sd", addr, op))
		default:
			http.Error(w, "op must be enable, disable, or reset", http.StatusBadRequest)
		}
	default:
		http.Error(w, "unknown control action", http.StatusNotFound)
	}
}

// controlAuthorized returns http.StatusOK when the request may run a control action, or
// an error status + message otherwise. Order: master switch, then password (if set), then
// loopback-only fallback when no password is configured.
func (s *Server) controlAuthorized(r *http.Request) (int, string) {
	if !s.controls.enabled() {
		return http.StatusForbidden, "control actions are disabled (set [diag] allow_control)"
	}
	if s.controls.Password != "" {
		// Failed-attempt backoff first (cheap, reveals nothing about correctness): an
		// online guesser is slowed whether it targets a real action or /control/verify.
		if s.authBackoffActive() > 0 {
			return http.StatusTooManyRequests, "too many failed attempts; retry shortly"
		}
		got := r.Header.Get("X-Diag-Password")
		if got == "" {
			got = r.PostFormValue("password")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.controls.Password)) != 1 {
			s.authFailed()
			return http.StatusUnauthorized, "missing or incorrect control password"
		}
		s.authSucceeded()
		return http.StatusOK, ""
	}
	// No password configured: honor only on a loopback bind.
	if !s.loopback {
		return http.StatusForbidden, "control_password required for a non-loopback bind"
	}
	return http.StatusOK, ""
}

// authBackoffActive returns the remaining failed-auth block (>0 => currently throttled).
func (s *Server) authBackoffActive() time.Duration {
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	if rem := s.authBlockUntil.Sub(s.now()); rem > 0 {
		return rem
	}
	return 0
}

// authFailed records a wrong password and arms the backoff window.
func (s *Server) authFailed() {
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	s.authFails++
	if d := authBackoff(s.authFails); d > 0 {
		s.authBlockUntil = s.now().Add(d)
	}
}

// authSucceeded clears the failed-auth counter on a correct password.
func (s *Server) authSucceeded() {
	s.ctlMu.Lock()
	s.authFails = 0
	s.authBlockUntil = time.Time{}
	s.ctlMu.Unlock()
}

// authBackoff is the delay imposed after n consecutive failed password attempts: a short
// grace, then exponential growth capped at 30s. Exponential rather than a hard lockout so
// an unauthenticated LAN attacker can slow — but not fully deny — the operator.
func authBackoff(n int) time.Duration {
	const grace = 5
	if n <= grace {
		return 0
	}
	shift := n - grace - 1
	if shift > 5 {
		shift = 5
	}
	if d := time.Second << uint(shift); d < 30*time.Second {
		return d
	}
	return 30 * time.Second
}

// controlRateOK enforces a per-action minimum interval (returns false => 429).
func (s *Server) controlRateOK(action string) bool {
	iv := controlMinInterval[action]
	if iv == 0 {
		return true
	}
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	now := time.Now()
	if last, ok := s.ctlLast[action]; ok && now.Sub(last) < iv {
		return false
	}
	s.ctlLast[action] = now
	return true
}

// controlOK logs the action and replies (redirecting a browser form back to the page).
func (s *Server) controlOK(w http.ResponseWriter, r *http.Request, msg string) {
	s.log("diag control: " + msg)
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, msg)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	snap := s.snap()
	status := "ok"
	if !snap.CFHealthy {
		status = "degraded"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%s\nzones=%d built=%s\n", status, len(snap.Zones), snap.BuiltAt.Format(time.RFC3339))
}

func (s *Server) handleJSON(w http.ResponseWriter, r *http.Request) {
	page := s.build()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(page)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page := s.build()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTmpl.Execute(w, page); err != nil {
		s.log(fmt.Sprintf("diag: render: %v", err))
	}
}

func (s *Server) snap() *model.Snapshot {
	if snap := s.snapshot(); snap != nil {
		return snap
	}
	return &model.Snapshot{}
}

// --- redacted view model (NO ZoneID/RecordID, NO token) ---

type page struct {
	Version     string        `json:"version"`
	BuiltAt     time.Time     `json:"built_at"`
	CFHealthy   bool          `json:"cf_healthy"`
	Zones       []zoneView    `json:"zones"`
	Reverse     []string      `json:"reverse_zones"`
	Stub        []stubView    `json:"stub_zones"`
	VHosts      []string      `json:"vhosts"`
	VHostV4     string        `json:"vhost_v4,omitempty"`
	VHostV6     string        `json:"vhost_v6,omitempty"`
	MDNSFwd     []hostView    `json:"mdns_forward"`
	MDNSRev     []hostView    `json:"mdns_reverse"`
	HasConfig   bool          `json:"-"` // config panel available (rendered lazily via /config)
	HasHostInfo bool          `json:"-"` // per-host enrichment available (lazy via /host)
	Cache       *cacheView    `json:"answer_cache,omitempty"`
	Queries     *queryStats   `json:"queries,omitempty"`
	Backends    []backendView `json:"backends,omitempty"`
	Workers     []workerView  `json:"workers,omitempty"`
	Enc         *EncStatus    `json:"encrypted,omitempty"`
	Controls    *controlsView `json:"-"` // HTML-only (the JSON view stays purely read-only)
	SelfTest    bool          `json:"-"` // HTML-only: render the self-tests link
	DDNSSim     bool          `json:"-"` // HTML-only: render the DDNS-simulate form
	TQuery      bool          `json:"-"` // HTML-only: render the transport-query tool form
}

// controlsView drives the HTML control panel; it lists which actions are wired and
// whether a password field is needed.
type controlsView struct {
	NeedPassword  bool
	FlushCache    bool
	RefreshMirror bool
	Restart       bool
	Backend       bool // on-the-fly backend enable/disable available
}

// cacheView is the forward-path answer-cache summary (RFC 2308/8767/9520 caching).
type cacheView struct {
	anscache.Stats
	HitRatio string           `json:"hit_ratio"`             // "NN.N%" over hits+misses, for at-a-glance reading
	Hot      []cacheEntryView `json:"hot_entries,omitempty"` // hottest live entries (what is actually cached)
}

// cacheEntryView is one live cache entry: what is cached, its class, and how hot it is.
type cacheEntryView struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Kind string `json:"kind"` // positive / negative / fail
	Hits uint64 `json:"hits"`
	Live bool   `json:"live"` // within TTL (vs. serve-stale-eligible)
	TTL  string `json:"ttl"`  // pre-rendered remaining/total
	Age  string `json:"age"`  // pre-rendered time since insertion
}

// queryStats is the query-telemetry rollup plus the recent ring and busiest clients.
type queryStats struct {
	Total       uint64            `json:"total"`
	Clients     int               `json:"clients"`
	ByDecision  map[string]uint64 `json:"by_decision"`
	ByTransport map[string]uint64 `json:"by_transport"`
	Recent      []queryView       `json:"recent"`
	Top         []clientView      `json:"top_clients"`
}

type queryView struct {
	Seq        uint64  `json:"seq"`
	Time       string  `json:"time"`
	Client     string  `json:"client"`
	ClientName string  `json:"client_name,omitempty"`
	Device     string  `json:"device,omitempty"` // vendor/device guess from the client's MAC
	Transport  string  `json:"transport"`
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Decision   string  `json:"decision"`
	Rcode      string  `json:"rcode"`
	LatencyMS  float64 `json:"latency_ms"`
}

type clientView struct {
	Client     string          `json:"client"`
	Name       string          `json:"name,omitempty"`
	Device     string          `json:"device,omitempty"` // vendor/device guess from the client's MAC (OUI)
	Count      uint64          `json:"count"`
	LastSeen   string          `json:"last_seen"`
	TopNames   []nameCountView `json:"top_names,omitempty"`  // this client's most-asked names
	Transports []nameCountView `json:"transports,omitempty"` // per-transport counts (upgrade debugging)
}

type nameCountView struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type backendView struct {
	Addr      string  `json:"addr"`
	Net       string  `json:"net"`
	Role      string  `json:"role"`
	State     string  `json:"state"`
	Healthy   bool    `json:"healthy"`
	Disabled  bool    `json:"disabled"`
	Consec    int     `json:"consecutive_failures"`
	FailRatio float64 `json:"fail_ratio"`
	FailPct   string  `json:"-"` // pre-rendered "NN%" for the HTML view
	OpenFor   string  `json:"open_for,omitempty"`
	Cooldown  string  `json:"cooldown_remaining,omitempty"`

	Queries  uint64 `json:"queries"`           // lifetime exchanges against this upstream
	Failures uint64 `json:"failures"`          // of which errored
	AvgRTT   string `json:"avg_rtt,omitempty"` // mean latency over successes, pre-rendered
	LastRTT  string `json:"-"`                 // most-recent success latency (HTML title)
}

type workerView struct {
	Name        string `json:"name"`
	Restarts    int64  `json:"restarts"`
	Stalls      int64  `json:"stalls"`
	Panics      int64  `json:"panics"`
	ProgressAge string `json:"progress_age"`
}

type zoneView struct {
	Apex           string   `json:"apex"`
	Serial         uint32   `json:"serial"`
	Stale          bool     `json:"stale"`
	SyntheticStale bool     `json:"synthetic_stale"`
	Records        []rrView `json:"records"`
}

type rrView struct {
	Owner     string `json:"owner"`
	Type      string `json:"type"`
	TTL       uint32 `json:"ttl"`
	RDATA     string `json:"rdata"`
	Proxied   bool   `json:"proxied,omitempty"`
	Synthetic bool   `json:"synthetic,omitempty"`
}

type stubView struct {
	Apex    string   `json:"apex"`
	Targets []string `json:"targets"`
}

type hostView struct {
	Name    string   `json:"name"`
	Records []string `json:"records"`
	Kind    string   `json:"kind,omitempty"` // "" for a normal host; "id" for a machine/instance id
}

// classifyHost labels an mDNS host name so the UI can flag machine/instance ids (container,
// VM, or device without a friendly hostname) that would otherwise confuse the reader.
func classifyHost(name string) string {
	if looksLikeMachineID(name) {
		return "id"
	}
	return ""
}

// looksLikeMachineID reports whether a label is a machine/instance id (only hex digits and
// dashes, with enough hex to be an id) rather than a human hostname.
func looksLikeMachineID(s string) bool {
	hex := 0
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			hex++
		case c == '-':
		default:
			return false
		}
	}
	return hex >= 16
}

func (s *Server) build() page {
	snap := s.snap()
	view := s.view()
	if view == nil {
		view = &model.MDNSView{}
	}
	p := page{
		Version:   s.version,
		BuiltAt:   snap.BuiltAt,
		CFHealthy: snap.CFHealthy,
	}
	if snap.VHostV4.IsValid() {
		p.VHostV4 = snap.VHostV4.String()
	}
	if snap.VHostV6.IsValid() {
		p.VHostV6 = snap.VHostV6.String()
	}

	for apex, z := range snap.Zones {
		zv := zoneView{Apex: apex, Serial: z.LastFetchedSerial, Stale: z.Stale, SyntheticStale: z.SyntheticStale}
		zv.Records = append(zv.Records, ownerRecords(z)...)
		sortRR(zv.Records)
		p.Zones = append(p.Zones, zv)
	}
	sort.Slice(p.Zones, func(i, j int) bool { return p.Zones[i].Apex < p.Zones[j].Apex })

	for apex := range snap.ReverseZ {
		p.Reverse = append(p.Reverse, apex)
	}
	sort.Slice(p.Reverse, func(i, j int) bool { return lessReverseDNS(p.Reverse[i], p.Reverse[j]) })

	for apex, sz := range snap.StubZones {
		sv := stubView{Apex: apex}
		for _, t := range sz.Target {
			sv.Targets = append(sv.Targets, t.String())
		}
		p.Stub = append(p.Stub, sv)
	}
	sort.Slice(p.Stub, func(i, j int) bool { return p.Stub[i].Apex < p.Stub[j].Apex })

	for v := range snap.VHosts {
		p.VHosts = append(p.VHosts, v)
	}
	sort.Strings(p.VHosts)

	p.MDNSFwd = hostViews(view.Forward)
	p.MDNSRev = reverseHostViews(view.Reverse, snap.LocalDomain)
	p.HasConfig = s.configFile != ""
	p.HasHostInfo = s.hostInfo != nil
	// mDNS reverse keys are in-addr/ip6.arpa names; order them by address, not alphabet.
	sort.Slice(p.MDNSRev, func(i, j int) bool { return lessReverseDNS(p.MDNSRev[i].Name, p.MDNSRev[j].Name) })

	if s.cacheStats != nil {
		if st, on := s.cacheStats(); on {
			p.Cache = &cacheView{Stats: st, HitRatio: hitRatio(st.Hits, st.Misses)}
			if s.cacheEntries != nil {
				p.Cache.Hot = buildCacheEntries(s.cacheEntries(cacheEntryLimit))
			}
		}
	}
	if s.qlog != nil {
		p.Queries = buildQueryStats(s.qlog, s.clientName, s.clientDevice)
	}
	if s.backends != nil {
		p.Backends = buildBackends(s.backends())
	}
	if s.workers != nil {
		p.Workers = buildWorkers(s.workers())
	}
	if s.encStatus != nil {
		p.Enc = s.encStatus()
	}
	if s.controlsActive {
		p.Controls = &controlsView{
			NeedPassword:  s.controls.Password != "",
			FlushCache:    s.controls.FlushCache != nil,
			RefreshMirror: s.controls.RefreshMirror != nil,
			Restart:       s.controls.Restart != nil,
			Backend:       s.controls.SetBackend != nil,
		}
	}
	p.SelfTest = s.selftest != nil
	p.DDNSSim = s.ddnsSim != nil
	p.TQuery = s.transportQuery != nil
	return p
}

// hitRatio renders hits/(hits+misses) as a percentage string, "—" when no lookups yet.
func hitRatio(hits, misses uint64) string {
	total := hits + misses
	if total == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(hits)/float64(total))
}

// recentQueryLimit caps how many recent queries the page renders (the ring may hold more).
const recentQueryLimit = 100

func buildQueryStats(l *qlog.Log, nameFor, deviceFor func(netip.Addr) string) *queryStats {
	name := func(a netip.Addr) string {
		if nameFor == nil || !a.IsValid() {
			return ""
		}
		return nameFor(a)
	}
	device := func(a netip.Addr) string {
		if deviceFor == nil || !a.IsValid() {
			return ""
		}
		return deviceFor(a)
	}
	tot := l.Totals()
	qs := &queryStats{Total: tot.Total, Clients: tot.Clients, ByDecision: map[string]uint64{}, ByTransport: map[string]uint64{}}
	for d, n := range tot.ByDecision {
		qs.ByDecision[string(d)] = n
	}
	for x, n := range tot.ByTransport {
		qs.ByTransport[x] = n
	}
	for _, e := range l.Recent(recentQueryLimit) {
		qs.Recent = append(qs.Recent, queryView{
			Seq:        e.Seq,
			Time:       e.Time.Format("15:04:05"),
			Client:     addrStr(e.Client),
			ClientName: name(e.Client),
			Device:     device(e.Client),
			Transport:  e.Transport,
			Name:       e.Name,
			Type:       e.Qtype,
			Decision:   string(e.Decision),
			Rcode:      e.Rcode,
			LatencyMS:  float64(e.Latency.Microseconds()) / 1000,
		})
	}
	for _, c := range l.TopClients(20) {
		cv := clientView{
			Client:   addrStr(c.Client),
			Name:     name(c.Client),
			Device:   device(c.Client),
			Count:    c.Count,
			LastSeen: c.LastSeen.Format("15:04:05"),
		}
		for _, nc := range c.TopNames {
			cv.TopNames = append(cv.TopNames, nameCountView{Name: nc.Name, Count: nc.Count})
		}
		for _, nc := range c.Transports {
			cv.Transports = append(cv.Transports, nameCountView{Name: nc.Name, Count: nc.Count})
		}
		qs.Top = append(qs.Top, cv)
	}
	return qs
}

// cacheEntryLimit caps how many hot cache entries the page lists (the cache may hold
// thousands; the table only surfaces the busiest).
const cacheEntryLimit = 50

func buildCacheEntries(es []anscache.EntryStat) []cacheEntryView {
	out := make([]cacheEntryView, 0, len(es))
	for _, e := range es {
		ttl := e.TTL.Round(time.Second).String()
		if e.Live {
			// Remaining vs. configured TTL, so an operator sees how fresh it is.
			if rem := (e.TTL - e.Age).Round(time.Second); rem > 0 {
				ttl = rem.String() + " / " + ttl
			}
		} else {
			ttl = "expired (stale-ok)"
		}
		out = append(out, cacheEntryView{
			Name: e.Name, Type: e.Type, Kind: e.Kind, Hits: e.Hits, Live: e.Live,
			TTL: ttl, Age: e.Age.Round(time.Second).String(),
		})
	}
	return out
}

func buildBackends(bs []forwarder.BackendStatus) []backendView {
	out := make([]backendView, 0, len(bs))
	for _, b := range bs {
		bv := backendView{
			Addr: b.Addr, Net: b.Net, Role: b.Role, State: b.State, Healthy: b.Healthy,
			Disabled: b.Disabled, Consec: b.Consec, FailRatio: b.FailRatio,
			FailPct: fmt.Sprintf("%.0f%%", b.FailRatio*100),
			Queries: b.Queries, Failures: b.Failures,
		}
		if b.OpenFor > 0 {
			bv.OpenFor = b.OpenFor.Round(time.Second).String()
		}
		if b.Cooldown > 0 {
			bv.Cooldown = b.Cooldown.Round(time.Second).String()
		}
		if b.AvgRTT > 0 {
			bv.AvgRTT = fmt.Sprintf("%.1f ms", float64(b.AvgRTT.Microseconds())/1000)
		}
		if b.LastRTT > 0 {
			bv.LastRTT = fmt.Sprintf("%.1f ms", float64(b.LastRTT.Microseconds())/1000)
		}
		out = append(out, bv)
	}
	return out
}

func buildWorkers(m map[string]supervisor.WorkerStats) []workerView {
	out := make([]workerView, 0, len(m))
	for name, ws := range m {
		out = append(out, workerView{
			Name: name, Restarts: ws.Restarts, Stalls: ws.Stalls, Panics: ws.Panics,
			ProgressAge: ws.ProgressAge.Round(time.Second).String(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func addrStr(a netip.Addr) string {
	if !a.IsValid() {
		return "?"
	}
	return a.String()
}

// ownerRecords flattens a zone's real records, wildcard records, and synthetic
// tunnel addresses into redacted rows (never the CF object IDs).
func ownerRecords(z *model.Zone) []rrView {
	var out []rrView
	emit := func(owner string, rr model.RR, synthetic bool) {
		out = append(out, rrView{
			Owner:     ownerLabel(owner),
			Type:      dns.TypeToString[rr.Type],
			TTL:       rr.TTL,
			RDATA:     rr.RDATA(),
			Proxied:   rr.Proxied,
			Synthetic: synthetic || rr.Synthetic,
		})
	}
	for owner, byType := range z.Records {
		for _, rrs := range byType {
			for _, rr := range rrs {
				emit(owner, rr, false)
			}
		}
	}
	for _, rrs := range z.Wildcards {
		for _, rr := range rrs {
			emit("*", rr, false)
		}
	}
	for owner, byType := range z.TunnelAddr {
		for _, rrs := range byType {
			for _, rr := range rrs {
				emit(owner, rr, true)
			}
		}
	}
	return out
}

// reverseHostViews renders the mDNS reverse view, rewriting PTR targets from the
// mDNS-native host.local to the served canonical host.<local-domain> (e.g. host.lan) so the
// panel matches what the resolver actually answers over unicast. Empty/"local" local domain
// leaves *.local unchanged.
func reverseHostViews(m map[string][]model.RR, localDomain string) []hostView {
	hv := hostViews(m)
	if localDomain == "" || localDomain == "local" {
		return hv
	}
	suffix := "." + localDomain + "."
	for i := range hv {
		for j, rec := range hv[i].Records {
			if base := strings.TrimSuffix(rec, ".local."); base != rec {
				hv[i].Records[j] = base + suffix
			}
		}
	}
	return hv
}

func hostViews(m map[string][]model.RR) []hostView {
	var out []hostView
	for name, rrs := range m {
		hv := hostView{Name: name, Kind: classifyHost(name)}
		for _, rr := range rrs {
			hv.Records = append(hv.Records, dns.TypeToString[rr.Type]+" "+rr.RDATA())
		}
		sort.Strings(hv.Records)
		out = append(out, hv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func ownerLabel(owner string) string {
	if owner == "" {
		return "@"
	}
	return owner
}

// lessReverseDNS orders reverse-DNS names (in-addr.arpa / ip6.arpa) intuitively: by their
// labels in REVERSE order — most-significant address component first — comparing numeric
// labels numerically. So zones group in address order (e.g. 192.0.2/24 before 192.168/16,
// and 9.x before 10.x) rather than the misleading left-to-right alphabetical order, where
// "2.0.192.in-addr.arpa." would sort after "168.192.in-addr.arpa.".
func lessReverseDNS(a, b string) bool {
	ra, rb := reverseLabels(a), reverseLabels(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] == rb[i] {
			continue
		}
		na, ea := strconv.Atoi(ra[i])
		nb, eb := strconv.Atoi(rb[i])
		if ea == nil && eb == nil {
			return na < nb // both numeric (decimal octets): compare numerically
		}
		return ra[i] < rb[i] // labels (or hex nibbles): lexical, which is correct for hex digits
	}
	return len(ra) < len(rb)
}

// reverseLabels splits a name on "." (dropping the trailing dot) and reverses the labels,
// so "2.0.192.in-addr.arpa." becomes [arpa, in-addr, 192, 0, 2].
func reverseLabels(name string) []string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels
}

func sortRR(rr []rrView) {
	sort.Slice(rr, func(i, j int) bool {
		if rr[i].Owner != rr[j].Owner {
			return rr[i].Owner < rr[j].Owner
		}
		if rr[i].Type != rr[j].Type {
			return rr[i].Type < rr[j].Type
		}
		return rr[i].RDATA < rr[j].RDATA
	})
}

var pageTmpl = template.Must(template.New("diag").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>splitdnsd diagnostics</title>
<style>
:root{--topbar-h:0px}
body{font:14px/1.4 system-ui,sans-serif;margin:1.5rem;color:#222}
h1{font-size:1.3rem;margin:0 0 .3rem}
h2{font-size:1.05rem;margin:1.4rem 0 0;border-bottom:1px solid #ddd;position:sticky;top:var(--topbar-h);background:#fff;z-index:2;padding:.15rem 0}
h3{font-size:.95rem;margin:.8rem 0 .2rem}
section{scroll-margin-top:calc(var(--topbar-h) + .5rem)}
table{border-collapse:collapse;margin:.3rem 0} td,th{padding:.15rem .6rem;text-align:left;vertical-align:top}
td{font-variant-numeric:tabular-nums} /* stop counters jittering column width on update */
[data-live] td,[data-live] th{box-sizing:border-box;white-space:nowrap} /* stable, never-shrink columns */
tr:nth-child(even){background:#f6f6f6} .flag{color:#b00;font-weight:600}
.ok{color:#080} .muted{color:#777} table.sortable th{cursor:pointer}
/* sticky header for long tables (e.g. recent queries); box-shadow stands in for the
   collapsed bottom border, which a sticky cell otherwise drops. */
table.sortable thead th{position:sticky;top:calc(var(--topbar-h) + 1.9rem);background:#fff;z-index:1;box-shadow:inset 0 -1px 0 #ccc}
/* sticky top chrome: at-a-glance health strip + in-page section nav */
.topbar{position:sticky;top:0;z-index:5;background:#fff;border-bottom:1px solid #ddd;margin:.2rem -1.5rem .3rem;padding:.35rem 1.5rem}
.health{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center}
.chip{display:inline-flex;gap:.35rem;align-items:center;text-decoration:none;color:#222;border:1px solid #ccc;border-radius:1rem;padding:.05rem .65rem;font-size:.85rem;white-space:nowrap}
.chip b{font-variant-numeric:tabular-nums} .chip .lbl{color:#777}
.chip.ok{border-color:#9c9} .chip.flag{border-color:#e88;background:#fdeaea}
.chip.clickable{cursor:pointer}
.badge{font-size:.7rem;padding:0 .35rem;border-radius:.35rem;background:#e6e6e6;color:#555;vertical-align:middle}
#cfgtext{max-height:22rem;overflow:auto;background:#f6f6f6;padding:.6rem;border-radius:4px;white-space:pre;font:12px/1.35 ui-monospace,monospace;color:#333}
/* control-action feedback + lock affordances (see the control JS) */
.ctl-msg{font-size:.85rem;margin-left:.4rem;font-variant-numeric:tabular-nums}
.ctl-msg.ok{color:#161} .ctl-msg.flag{color:#c00} .ctl-msg.muted{color:#777}
button.ctl[aria-busy="true"]{opacity:.6;cursor:progress}
body[data-locked="true"] button.ctl{opacity:.55}
#pwerr{color:#c00;font-size:.85rem;margin-left:.4rem}
#diagpw.flash{outline:2px solid #e88;outline-offset:1px}
@media (prefers-reduced-motion:no-preference){#diagpw{transition:outline-color .5s}}
nav.toc{margin-top:.3rem;font-size:.85rem;line-height:1.9}
nav.toc a{color:#36c;text-decoration:none} nav.toc a:hover{text-decoration:underline}
nav.toc a:not(:first-child)::before{content:"·";color:#ccc;margin:0 .45rem}
details>summary{cursor:pointer;color:#36c} details>summary::marker{color:#999}
details.zone{margin:.3rem 0} details.zone>summary{font-weight:600;color:#222}
@media print{
  .topbar{display:none} h2,table.sortable thead th{position:static;box-shadow:none}
  details{display:block} details>summary{display:none} details>*{display:block!important}
}
</style></head><body>
<header id="status">
<h1>splitdnsd diagnostics <span class="muted">{{.Version}}</span></h1>
<p>Built {{.BuiltAt}} — Cloudflare mirror:
{{if .CFHealthy}}<span class="ok">healthy</span>{{else}}<span class="flag">degraded (serving stale)</span>{{end}}</p>
{{if .SelfTest}}<p><a href="/selftest">Run self-tests &rarr;</a></p>{{end}}
{{if .DDNSSim}}<form method="get" action="/ddns-simulate" style="margin:.3rem 0">
<b>DDNS simulate</b> <span class="muted">(never writes)</span> &mdash; host <input name="host" size="12">
addr <input name="addr" size="16" placeholder="1.2.3.4 (public)">
<button name="explore" value="" title="exactly what write-back does with your current config">As configured &rarr;</button>
<button name="explore" value="1" title="ignore the eligibility allowlist — explore what enabling this host would do">Explore: ignore allowlist &rarr;</button></form>{{end}}
</header>

<div class="topbar">
<div class="health" id="health">
<a class="chip {{if .CFHealthy}}ok{{else}}flag{{end}}" id="chip-mirror" href="#status"><span class="lbl">mirror</span> {{if .CFHealthy}}OK{{else}}stale{{end}}</a>
{{if .Backends}}<a class="chip" id="chip-upstreams" href="#upstreams"><span class="lbl">upstreams</span> <b>{{len .Backends}}</b></a>{{end}}
{{with .Cache}}<a class="chip" id="chip-cache" href="#cache"><span class="lbl">cache</span> <b>{{.HitRatio}}</b></a>{{end}}
{{with .Workers}}<a class="chip" id="chip-workers" href="#workers"><span class="lbl">workers</span> <b>{{len .}}</b></a>{{end}}
{{with .Queries}}<a class="chip" id="chip-queries" href="#queries"><span class="lbl">queries</span> <b>{{.Total}}</b></a>{{end}}
{{if .Enc}}{{if .Enc.Enabled}}<a class="chip {{if and .Enc.CertValid .Enc.DDRReady}}ok{{else}}flag{{end}}" id="chip-encrypted" href="#encrypted"><span class="lbl">encrypted</span> {{if .Enc.DDRReady}}DDR{{else if .Enc.CertValid}}no-DDR{{else}}cert!{{end}}</a>{{end}}{{end}}
{{if .Controls}}{{if .Controls.NeedPassword}}<a class="chip flag clickable" id="chip-controls" href="#controls" aria-label="Controls locked — activate to unlock"><span class="lbl">controls</span> locked</a>{{end}}{{end}}
</div>
<nav class="toc">
{{if .Controls}}<a href="#controls">Controls</a>{{end}}
{{if .Backends}}<a href="#upstreams">Upstreams</a>{{end}}
{{if .Cache}}<a href="#cache">Cache</a>{{end}}
{{if .Enc}}<a href="#encrypted">Encrypted</a>{{end}}
{{if .Workers}}<a href="#workers">Workers</a>{{end}}
{{if .Queries}}<a href="#queries">Queries</a>{{end}}
<a href="#reference">Reference</a>
</nav>
</div>

{{with .Controls}}
<section id="controls">
<h2>Controls <span class="flag">danger</span></h2>
<div id="ctl" data-need-pw="{{.NeedPassword}}">
{{if .NeedPassword}}<form id="pwform" autocomplete="on" style="margin:.2rem 0">
<input type="text" name="username" value="diag" autocomplete="username" tabindex="-1" aria-hidden="true" style="position:absolute;left:-9999px">
<span id="pwentry"><input type="password" id="diagpw" name="password" autocomplete="current-password" placeholder="control password" size="18" aria-describedby="pwerr">
<button type="submit">Unlock</button>
<span id="pwerr" role="alert"></span>
<span class="muted" id="lockhint">— enter the control password to enable the actions below and the upstream enable/disable buttons. Kept for this browser session (cleared when you close the tab).</span></span>
<span class="muted" id="unlockednote" hidden>controls unlocked for this session — </span><button type="button" id="lockbtn" hidden>Lock</button></form>{{end}}
{{if .FlushCache}}<button class="ctl" data-action="flush-cache">Flush answer cache</button>{{end}}
{{if .RefreshMirror}}<button class="ctl" data-action="refresh-mirror">Force mirror refresh</button>{{end}}
{{if .Restart}}<button class="ctl" data-action="restart" data-confirm="Restart the daemon?">Restart daemon</button>{{end}}
</div>
</section>
{{end}}

{{if .Backends}}
<section id="upstreams">
<h2>Upstreams <span class="muted">circuit breaker</span></h2>
<p class="muted">Selection is <b>sequential failover</b>: queries go to the first healthy
upstream in this order; if it fails or its breaker is open, the next is tried, and so on.
It is NOT round-robin or query-all-take-first. (If every upstream is tripped the breaker
fails open and tries them anyway.){{if and $.Controls $.Controls.Backend}} Use the
buttons to disable/enable an upstream on the fly (until re-enabled or restart) to force
traffic onto another.{{end}}</p>
<div data-live="backends"><table><thead><tr><th>backend</th><th>net</th><th>role</th><th>state</th><th>consec fails</th><th>fail ratio</th><th>tripped for</th><th>cooldown</th><th>queries</th><th>fails</th><th>avg rtt</th>{{if and $.Controls $.Controls.Backend}}<th></th>{{end}}</tr></thead><tbody>
{{range .Backends}}<tr data-key="{{.Addr}}">
<td data-f="addr">{{.Addr}}</td><td data-f="net">{{.Net}}</td><td data-f="role">{{.Role}}</td>
<td data-f="state" class="{{if .Healthy}}ok{{else}}flag{{end}}">{{.State}}</td>
<td data-f="consecutive_failures">{{.Consec}}</td><td data-f="fail_ratio">{{.FailPct}}</td>
<td data-f="open_for" class="muted">{{.OpenFor}}</td><td data-f="cooldown_remaining" class="muted">{{.Cooldown}}</td>
<td data-f="queries">{{.Queries}}</td><td data-f="failures"{{if .Failures}} class="flag"{{end}}>{{.Failures}}</td><td data-f="avg_rtt" class="muted"{{if .LastRTT}} title="last {{.LastRTT}}"{{end}}>{{.AvgRTT}}</td>
{{if and $.Controls $.Controls.Backend}}<td data-f="btn">{{if .Disabled}}<button class="ctl" data-action="backend" data-op="enable" data-addr="{{.Addr}}">enable</button>{{else}}<button class="ctl" data-action="backend" data-op="disable" data-addr="{{.Addr}}">disable</button>{{end}}</td>{{end}}</tr>
{{end}}</tbody></table></div>
{{if and $.Controls $.Controls.Backend}}<button class="ctl" data-action="backend" data-op="reset">Reset backend overrides</button>{{end}}
</section>
{{end}}

{{with .Cache}}
<section id="cache">
<h2>Answer cache <span class="muted">forward path</span></h2>
<div data-live="answer_cache"><table>
<tr><th>hit ratio</th><td data-f="hit_ratio">{{.HitRatio}}</td><th>entries</th><td data-f="entries">{{.Entries}} / {{.Capacity}}</td></tr>
<tr><th>hits</th><td data-f="hits">{{.Hits}}</td><th>misses</th><td data-f="misses">{{.Misses}}</td></tr>
<tr><th>stale serves</th><td data-f="stale_serves">{{.StaleServes}}</td><th>servfail hits</th><td data-f="fail_hits">{{.FailHits}}</td></tr>
<tr><th>inserts</th><td data-f="inserts">{{.Inserts}}</td><th>evictions</th><td data-f="evictions">{{.Evictions}}</td></tr>
</table>
{{if .Hot}}<details><summary>Hottest entries <span class="muted">(what's cached, by hit count — click a header to sort)</span></summary>
<table class="sortable" data-rows="hot_entries" data-defsort="3:num:desc"><thead><tr><th>name</th><th>type</th><th>kind</th><th>hits</th><th>ttl left / total</th><th>age</th></tr></thead><tbody>
{{range .Hot}}<tr data-key="{{.Name}}|{{.Type}}"><td data-f="name">{{.Name}}</td><td data-f="type">{{.Type}}</td><td data-f="kind"{{if ne .Kind "positive"}} class="flag"{{end}}>{{.Kind}}</td><td data-f="hits">{{.Hits}}</td><td data-f="ttl" class="muted">{{.TTL}}</td><td data-f="age" class="muted">{{.Age}}</td></tr>{{end}}</tbody></table>
</details>{{end}}
</div>
</section>
{{end}}

{{with .Enc}}
<section id="encrypted">
<h2>Encrypted &amp; DDR <span class="muted">DoT / DoH / discovery</span></h2>
<div data-live="encrypted">
{{if .Enabled}}
<table>
<tr><th>ADN</th><td data-f="adn">{{.ADN}}</td><th>certificate</th><td data-f="cert" class="{{if .CertValid}}ok{{else}}flag{{end}}">{{if .CertValid}}valid{{else}}INVALID{{end}}{{if .Expiry}} — {{.Expiry}}{{end}}</td></tr>
<tr><th>cert SANs</th><td data-f="sans" colspan="3" class="muted">{{range .SANs}}{{.}} {{end}}</td></tr>
<tr><th>DoT</th><td data-f="dot">{{if .DoT}}{{range .DoT}}{{.}} {{end}}{{else}}&mdash;{{end}}</td><th>DoH</th><td data-f="doh">{{if .DoH}}{{range .DoH}}{{.}} {{end}}{{if .DoHPath}}<span class="muted">{{.DoHPath}}</span>{{end}}{{else}}&mdash;{{end}}</td></tr>
<tr><th>DDR advertised</th><td data-f="ddr" class="{{if .DDRReady}}ok{{else}}flag{{end}}" colspan="3">{{if .DDRReady}}yes — serving the SVCB designation{{else}}no{{end}}</td></tr>
</table>
{{if .SVCB}}<details><summary>SVCB served at _dns.resolver.arpa</summary><pre data-f="svcb">{{range .SVCB}}{{.}}
{{end}}</pre></details>{{end}}
<h3>Upgrade readiness <span class="muted">(why clients do / don't upgrade)</span></h3>
<table data-f="checks"><tbody>
{{range .Checks}}<tr><td class="{{if .OK}}ok{{else}}flag{{end}}">{{if .OK}}OK{{else}}&#10007;{{end}}</td><td>{{.Name}}</td><td class="muted">{{.Detail}}</td></tr>{{end}}
</tbody></table>
{{else}}<p class="muted">Encrypted front-end is configured but not currently enabled.</p>{{end}}
</div>
</section>
{{end}}

{{if .TQuery}}
<section id="tquery">
<h2>Transport query <span class="muted">test Do53 / DoT / DoH at this resolver</span></h2>
<form method="get" action="/tquery" style="margin:.3rem 0">
name <input name="name" size="22" placeholder="example.com or _dns.resolver.arpa">
type <select name="type"><option selected>ANY</option><option>A</option><option>AAAA</option><option>SVCB</option><option>HTTPS</option><option>PTR</option><option>TXT</option><option>MX</option></select>
transport <select name="transport"><option value="do53">Do53 (UDP)</option><option value="tcp">Do53 (TCP)</option><option value="dot">DoT</option><option value="doh">DoH</option></select>
<button>Query &rarr;</button> <span class="muted">— shows the answer plus the TLS handshake (why a client can't upgrade)</span></form>
</section>
{{end}}

{{with .Workers}}
<section id="workers">
<h2>Workers <span class="muted">supervisor</span></h2>
<div data-live="workers"><table><thead><tr><th>worker</th><th>restarts</th><th>stalls</th><th>panics</th><th>last progress</th></tr></thead><tbody>
{{range .}}<tr data-key="{{.Name}}"><td data-f="name">{{.Name}}</td>
<td data-f="restarts"{{if .Restarts}} class="flag"{{end}}>{{.Restarts}}</td>
<td data-f="stalls"{{if .Stalls}} class="flag"{{end}}>{{.Stalls}}</td>
<td data-f="panics"{{if .Panics}} class="flag"{{end}}>{{.Panics}}</td>
<td data-f="progress_age" class="muted">{{.ProgressAge}} ago</td></tr>
{{end}}</tbody></table></div>
</section>
{{end}}

{{with .Queries}}
<section id="queries">
<h2>Queries</h2>
<div data-live="queries">
<p><b data-f="total">{{.Total}}</b> total, <b data-f="clients">{{.Clients}}</b> clients</p>
<p class="muted"><span data-f="by_decision">{{range $d, $n := .ByDecision}}{{$d}}={{$n}} {{end}}</span></p>
<p class="muted">transport: <span data-f="by_transport">{{range $t, $n := .ByTransport}}{{$t}}={{$n}} {{end}}</span></p>
<h3>Busiest clients <span class="muted">(recent activity — counts decay ~10&nbsp;min half-life; the transports column is lifetime, to see whether a client ever upgraded; click a header to sort)</span></h3>
<table class="sortable" data-rows="top_clients" data-defsort="3:num:desc"><thead><tr><th>client</th><th>name</th><th>device</th><th>queries</th><th>last seen</th><th>top names</th><th>transports</th></tr></thead><tbody>
{{range .Top}}<tr data-key="{{.Client}}"><td data-f="client">{{.Client}}</td><td data-f="name" class="muted">{{.Name}}</td><td data-f="device" class="muted">{{.Device}}</td><td data-f="count">{{.Count}}</td><td data-f="last_seen" class="muted">{{.LastSeen}}</td><td data-f="top_names" class="muted">{{range .TopNames}}{{.Name}} ({{.Count}}) {{end}}</td><td data-f="transports">{{range .Transports}}{{.Name}}:{{.Count}} {{end}}</td></tr>{{end}}</tbody></table>
<h3>Recent queries <span class="muted">(click a header to sort)</span></h3>
<table class="sortable" data-rows="recent" data-defsort="key:num:desc"><thead><tr><th>time</th><th>client</th><th>proto</th><th>name</th><th>type</th><th>decision</th><th>rcode</th><th>ms</th></tr></thead><tbody>
{{range .Recent}}<tr data-key="{{.Seq}}"><td data-f="time" class="muted">{{.Time}}</td><td data-f="client">{{.Client}}{{if .ClientName}} <span data-f="cname" class="muted">{{.ClientName}}</span>{{end}}{{if .Device}} <span data-f="cdev" class="muted">({{.Device}})</span>{{end}}</td><td data-f="transport">{{.Transport}}</td><td data-f="name">{{.Name}}</td><td data-f="type">{{.Type}}</td>
<td data-f="decision">{{.Decision}}</td><td data-f="rcode">{{.Rcode}}</td><td data-f="ms">{{printf "%.1f" .LatencyMS}}</td></tr>{{end}}</tbody></table>
</div>
</section>
{{end}}

<section id="reference">
<h2>Reference <span class="muted">zones &amp; static maps — click to expand</span></h2>
{{range .Zones}}
<details class="zone"><summary>{{.Apex}} <span class="muted">serial {{.Serial}}</span>{{if .Stale}} <span class="flag">STALE</span>{{end}}{{if .SyntheticStale}} <span class="flag">SYNTHETIC-STALE</span>{{end}}</summary>
<table><tr><th>owner</th><th>type</th><th>ttl</th><th>rdata</th><th></th></tr>
{{range .Records}}<tr><td>{{.Owner}}</td><td>{{.Type}}</td><td>{{.TTL}}</td><td>{{.RDATA}}</td>
<td class="muted">{{if .Synthetic}}synthetic {{end}}{{if .Proxied}}proxied{{end}}</td></tr>
{{end}}</table>
</details>
{{end}}
<details><summary>Reverse zones</summary><table>{{range .Reverse}}<tr><td>{{.}}</td></tr>{{end}}</table></details>
<details><summary>Stub zones</summary><table>{{range .Stub}}<tr><td>{{.Apex}}</td><td>{{range .Targets}}{{.}} {{end}}</td></tr>{{end}}</table></details>
<details><summary>VHosts</summary><p>reverse proxy {{.VHostV4}} {{.VHostV6}}</p>
<table>{{range .VHosts}}<tr><td>{{.}}</td></tr>{{end}}</table></details>
<details><summary>mDNS forward</summary>
<p class="muted">badge <span class="badge">id</span> marks a machine/instance id (container, VM, or a device with no friendly hostname).</p>
<div data-live="mdns_forward"><table><tbody>
{{range .MDNSFwd}}<tr data-key="{{.Name}}"><td data-f="name">{{.Name}}{{if .Kind}} <span class="badge">{{.Kind}}</span>{{end}}</td><td data-f="records">{{range $i, $r := .Records}}{{if $i}}; {{end}}{{$r}}{{end}}</td><td data-f="info" class="muted">{{if $.HasHostInfo}}<a class="hi" data-h="{{.Name}}" href="#" title="identify this host (vendor/scope)">identify</a>{{end}}</td></tr>{{end}}
</tbody></table></div></details>
<details><summary>mDNS reverse</summary><div data-live="mdns_reverse"><table><tbody>
{{range .MDNSRev}}<tr data-key="{{.Name}}"><td data-f="name">{{.Name}}</td><td data-f="records">{{range $i, $r := .Records}}{{if $i}}; {{end}}{{$r}}{{end}}</td></tr>{{end}}
</tbody></table></div></details>
{{if .HasConfig}}<details id="cfgpanel"><summary>Config <span class="muted">effective file — cryptographic material redacted</span></summary><pre id="cfgtext" class="muted">Loading…</pre></details>{{end}}
</section>
<script>
(function(){
  'use strict';
  // ---- small DOM helpers ----
  function fcell(el, n){ return el.querySelector('[data-f="' + n + '"]'); }
  function patchText(node, val){ if(node){ var s = String(val); if(node.textContent !== s) node.textContent = s; } }
  function td(text, cls){ var c = document.createElement('td'); if(cls) c.className = cls; if(text != null) c.textContent = text; return c; }

  // ---- selection / focus guard: never patch a region the user is working in ----
  var dragging = false;
  function hasSelIn(el){
    var sel = window.getSelection();
    if(sel && sel.rangeCount && !sel.isCollapsed){ try { if(sel.getRangeAt(0).intersectsNode(el)) return true; } catch(e){} }
    var a = document.activeElement;
    if(a && el.contains(a) && (a.tagName === 'INPUT' || a.tagName === 'TEXTAREA' || a.isContentEditable)) return true;
    return false;
  }
  function locked(el){ return dragging || hasSelIn(el); }

  // ---- click-to-sort: store the comparator as state, reapply after every patch ----
  function cellVal(tr, col){ return col === 'key' ? tr.dataset.key : (tr.cells[col] ? tr.cells[col].textContent.trim() : ''); }
  function applySort(table){
    var s = table._sort; if(!s) return;
    var body = table.tBodies[0]; var rows = Array.prototype.slice.call(body.rows);
    rows.sort(function(a, b){
      var x = cellVal(a, s.col), y = cellVal(b, s.col), c;
      if(s.type === 'num'){ c = (parseFloat(x) || 0) - (parseFloat(y) || 0); }
      else { var nx = parseFloat(x), ny = parseFloat(y); c = (!isNaN(nx) && !isNaN(ny)) ? nx - ny : x.localeCompare(y); }
      return s.dir === 'desc' ? -c : c;
    });
    rows.forEach(function(r){ body.appendChild(r); });
  }
  document.querySelectorAll('table.sortable').forEach(function(t){
    if(t.dataset.defsort){ var p = t.dataset.defsort.split(':'); t._sort = { col: p[0] === 'key' ? 'key' : parseInt(p[0], 10), type: p[1] || 'str', dir: p[2] || 'asc' }; applySort(t); }
    var ths = t.tHead ? t.tHead.rows[0].cells : [];
    Array.prototype.forEach.call(ths, function(th, idx){
      th.addEventListener('click', function(){
        var dir = (t._sort && t._sort.col === idx && t._sort.dir === 'asc') ? 'desc' : 'asc';
        var body = t.tBodies[0], sample = (body.rows[0] && body.rows[0].cells[idx]) ? body.rows[0].cells[idx].textContent.trim() : '';
        var type = (sample !== '' && !isNaN(parseFloat(sample))) ? 'num' : 'str';
        t._sort = { col: idx, type: type, dir: dir }; applySort(t);
      });
    });
  });

  // ---- keyed row reconcile (add/update/remove, ends in data order) ----
  function reconcile(tbody, rows, keyOf, make, fill){
    var existing = {};
    Array.prototype.forEach.call(tbody.children, function(tr){ existing[tr.dataset.key] = tr; });
    var seen = {};
    rows.forEach(function(d){
      var k = String(keyOf(d)); seen[k] = true;
      var tr = existing[k];
      if(!tr){ tr = make(d); tr.dataset.key = k; }
      else if(fill){ fill(tr, d); }
      tbody.appendChild(tr);
    });
    Object.keys(existing).forEach(function(k){ if(!seen[k]) existing[k].remove(); });
  }

  function fillBackend(tr, x){
    patchText(fcell(tr, 'addr'), x.addr); patchText(fcell(tr, 'net'), x.net); patchText(fcell(tr, 'role'), x.role);
    var st = fcell(tr, 'state'); patchText(st, x.state); var cls = x.healthy ? 'ok' : 'flag'; if(st.className !== cls) st.className = cls;
    patchText(fcell(tr, 'consecutive_failures'), x.consecutive_failures);
    patchText(fcell(tr, 'fail_ratio'), Math.round((x.fail_ratio || 0) * 100) + '%');
    patchText(fcell(tr, 'open_for'), x.open_for || ''); patchText(fcell(tr, 'cooldown_remaining'), x.cooldown_remaining || '');
    patchText(fcell(tr, 'queries'), x.queries || 0);
    var fa = fcell(tr, 'failures'); patchText(fa, x.failures || 0); var fcls = x.failures ? 'flag' : ''; if(fa.className !== fcls) fa.className = fcls;
    patchText(fcell(tr, 'avg_rtt'), x.avg_rtt || '');
    var cell = fcell(tr, 'btn');
    if(cell){
      var op = x.disabled ? 'enable' : 'disable', b = cell.querySelector('button');
      if(!b || b.dataset.op !== op){
        cell.textContent = ''; b = document.createElement('button'); b.className = 'ctl';
        b.dataset.action = 'backend'; b.dataset.op = op; b.dataset.addr = x.addr; b.textContent = op;
        cell.appendChild(b); // clicks handled by the delegated listener (reconcile-safe)
      }
    }
  }
  function makeBackend(x){ var tr = document.createElement('tr');
    tr.innerHTML = '<td data-f="addr"></td><td data-f="net"></td><td data-f="role"></td><td data-f="state"></td><td data-f="consecutive_failures"></td><td data-f="fail_ratio"></td><td data-f="open_for" class="muted"></td><td data-f="cooldown_remaining" class="muted"></td><td data-f="queries"></td><td data-f="failures"></td><td data-f="avg_rtt" class="muted"></td>';
    if(document.querySelector('[data-live="backends"] [data-f="btn"]')) tr.appendChild(td('', null)).setAttribute('data-f', 'btn');
    fillBackend(tr, x); return tr; }

  function makeRecent(x){
    var tr = document.createElement('tr');
    tr.appendChild(td(x.time, 'muted'));
    tr.appendChild(td(x.client, null)); // client cell; the resolved name span is added by fillRecent
    tr.appendChild(td(x.transport)); // proto (udp/tcp/dot/doh)
    tr.appendChild(td(x.name)); tr.appendChild(td(x.type)); tr.appendChild(td(x.decision)); tr.appendChild(td(x.rcode));
    tr.appendChild(td((x.latency_ms || 0).toFixed(1)));
    fillRecent(tr, x);
    return tr;
  }
  // A recorded query is immutable EXCEPT its opportunistic client name, which can resolve
  // later as mDNS (or DHCP, eventually) learns the host — so keep that span up to date.
  function fillRecent(tr, x){
    var cell = tr.cells[1], span = cell.querySelector('[data-f="cname"]');
    if(x.client_name){
      if(!span){ cell.appendChild(document.createTextNode(' ')); span = document.createElement('span'); span.className = 'muted'; span.dataset.f = 'cname'; cell.appendChild(span); }
      patchText(span, x.client_name);
    } else if(span){ span.remove(); }
    var dev = cell.querySelector('[data-f="cdev"]');
    if(x.device){
      if(!dev){ cell.appendChild(document.createTextNode(' ')); dev = document.createElement('span'); dev.className = 'muted'; dev.dataset.f = 'cdev'; cell.appendChild(dev); }
      patchText(dev, '(' + x.device + ')');
    } else if(dev){ dev.remove(); }
  }

  // mDNS forward/reverse: keyed by host/arpa name; only the records cell changes.
  function mdnsRecords(tr, x){ patchText(fcell(tr, 'records'), (x.records || []).join('; ')); }
  function makeMDNS(x){ var tr = document.createElement('tr'); tr.innerHTML = '<td data-f="name"></td><td data-f="records"></td><td data-f="info" class="muted"></td>'; var nc = fcell(tr, 'name'); nc.textContent = x.name; if(x.kind){ nc.appendChild(document.createTextNode(' ')); var b = document.createElement('span'); b.className = 'badge'; b.textContent = x.kind; nc.appendChild(b); } if(hasHostInfo){ var a = document.createElement('a'); a.className = 'hi'; a.href = '#'; a.dataset.h = x.name; a.textContent = 'identify'; fcell(tr, 'info').appendChild(a); } mdnsRecords(tr, x); return tr; }
  function mdnsPatch(root, d){ reconcile(root.querySelector('tbody'), d || [], function(x){ return x.name; }, makeMDNS, mdnsRecords); }

  // ---- per-section patchers (key === data-live === /diag.json field) ----
  var patchers = {
    answer_cache: function(root, d){
      ['hits','misses','stale_serves','fail_hits','inserts','evictions','hit_ratio'].forEach(function(n){ patchText(fcell(root, n), d[n]); });
      patchText(fcell(root, 'entries'), d.entries + ' / ' + d.capacity);
      var hot = root.querySelector('table[data-rows="hot_entries"]'); // present only when entries are wired
      if(hot){
        reconcile(hot.tBodies[0], d.hot_entries || [], function(x){ return x.name + '|' + x.type; },
          function(x){ var tr = document.createElement('tr'); tr.innerHTML = '<td data-f="name"></td><td data-f="type"></td><td data-f="kind"></td><td data-f="hits"></td><td data-f="ttl" class="muted"></td><td data-f="age" class="muted"></td>'; fcell(tr,'name').textContent = x.name; fcell(tr,'type').textContent = x.type; return tr; },
          function(tr, x){ var k = fcell(tr,'kind'); patchText(k, x.kind); var kc = (x.kind === 'positive') ? '' : 'flag'; if(k.className !== kc) k.className = kc; patchText(fcell(tr,'hits'), x.hits); patchText(fcell(tr,'ttl'), x.ttl || ''); patchText(fcell(tr,'age'), x.age || ''); });
        applySort(hot);
      }
    },
    workers: function(root, d){
      reconcile(root.querySelector('tbody'), d, function(x){ return x.name; },
        function(){ var tr = document.createElement('tr'); tr.innerHTML = '<td data-f="name"></td><td data-f="restarts"></td><td data-f="stalls"></td><td data-f="panics"></td><td data-f="progress_age" class="muted"></td>'; return tr; },
        function(tr, x){ patchText(fcell(tr,'name'), x.name); patchText(fcell(tr,'restarts'), x.restarts); patchText(fcell(tr,'stalls'), x.stalls); patchText(fcell(tr,'panics'), x.panics); patchText(fcell(tr,'progress_age'), x.progress_age + ' ago'); });
    },
    backends: function(root, d){
      var table = root.querySelector('table');
      reconcile(table.tBodies[0], d, function(x){ return x.addr; }, makeBackend, fillBackend);
      applySort(table);
    },
    queries: function(root, d){
      patchText(fcell(root, 'total'), d.total); patchText(fcell(root, 'clients'), d.clients);
      var bd = ''; Object.keys(d.by_decision || {}).sort().forEach(function(k){ bd += k + '=' + d.by_decision[k] + ' '; });
      patchText(fcell(root, 'by_decision'), bd);
      var bx = ''; Object.keys(d.by_transport || {}).sort().forEach(function(k){ bx += k + '=' + d.by_transport[k] + ' '; });
      patchText(fcell(root, 'by_transport'), bx);
      var xports = function(a){ return (a || []).map(function(n){ return n.name + ':' + n.count; }).join(' '); };
      var top = root.querySelector('table[data-rows="top_clients"]');
      reconcile(top.tBodies[0], d.top_clients || [], function(x){ return x.client; },
        function(x){ var tr = document.createElement('tr'); tr.innerHTML = '<td data-f="client"></td><td data-f="name" class="muted"></td><td data-f="device" class="muted"></td><td data-f="count"></td><td data-f="last_seen" class="muted"></td><td data-f="top_names" class="muted"></td><td data-f="transports"></td>'; fcell(tr,'client').textContent = x.client; return tr; },
        function(tr, x){ patchText(fcell(tr,'name'), x.name || ''); patchText(fcell(tr,'device'), x.device || ''); patchText(fcell(tr,'count'), x.count); patchText(fcell(tr,'last_seen'), x.last_seen || ''); patchText(fcell(tr,'top_names'), (x.top_names || []).map(function(n){ return n.name + ' (' + n.count + ')'; }).join(' ')); patchText(fcell(tr,'transports'), xports(x.transports)); });
      applySort(top);
      var rec = root.querySelector('table[data-rows="recent"]');
      reconcile(rec.tBodies[0], d.recent || [], function(x){ return x.seq; }, makeRecent, fillRecent); // only the client name can change
      applySort(rec);
    },
    encrypted: function(root, d){
      if(!d || !d.enabled) return;
      patchText(fcell(root, 'adn'), d.adn || '');
      var cert = fcell(root, 'cert'); if(cert){ cert.textContent = (d.cert_valid ? 'valid' : 'INVALID') + (d.expiry ? (' — ' + d.expiry) : ''); cert.className = d.cert_valid ? 'ok' : 'flag'; }
      patchText(fcell(root, 'sans'), (d.sans || []).join(' '));
      patchText(fcell(root, 'dot'), (d.dot && d.dot.length) ? d.dot.join(' ') : '—');
      patchText(fcell(root, 'doh'), (d.doh && d.doh.length) ? (d.doh.join(' ') + (d.doh_path ? (' ' + d.doh_path) : '')) : '—');
      var ddr = fcell(root, 'ddr'); if(ddr){ ddr.textContent = d.ddr_ready ? 'yes — serving the SVCB designation' : 'no'; ddr.className = d.ddr_ready ? 'ok' : 'flag'; }
      var svcb = fcell(root, 'svcb'); if(svcb) svcb.textContent = (d.svcb || []).join('\n');
      var checks = fcell(root, 'checks');
      if(checks && checks.tBodies[0]){ var tb = checks.tBodies[0]; tb.textContent = '';
        (d.checks || []).forEach(function(c){ var tr = document.createElement('tr'); tr.appendChild(td(c.ok ? 'OK' : '✗', c.ok ? 'ok' : 'flag')); tr.appendChild(td(c.name)); tr.appendChild(td(c.detail || '', 'muted')); tb.appendChild(tr); });
      }
    },
    mdns_forward: mdnsPatch,
    mdns_reverse: mdnsPatch
  };

  // ---- column-width ratchet: columns only ever WIDEN on live update; reset on reload ----
  // Measure natural widths in auto-layout, then pin them in fixed-layout on the reference
  // row (thead row if present, else first body row). State (max-seen widths) lives on the
  // <table> node, so it dies with the DOM and resets on a full reload.
  function measureRow(tr, nat){ if(!tr) return; for(var c=0;c<tr.cells.length && c<nat.length;c++){ var w=tr.cells[c].getBoundingClientRect().width; if(w>nat[c]) nat[c]=w; } }
  function ratchet(table){
    if(!table || !table.tBodies[0] || table.offsetParent===null) return; // skip hidden (closed <details>)
    var body=table.tBodies[0], ref=(table.tHead && table.tHead.rows[0]) || body.rows[0];
    if(!ref || !ref.cells.length) return;
    var n=ref.cells.length, max=table._cw||(table._cw=[]); while(max.length<n) max.push(0);
    table.style.tableLayout='auto';                                  // measure unhindered by our pins
    for(var c=0;c<n;c++){ if(ref.cells[c]) ref.cells[c].style.width=''; }
    var nat=new Array(n).fill(0); measureRow(ref,nat);
    var rows=body.rows, len=rows.length, cap=200, step=len<=cap?1:Math.ceil(len/cap);
    for(var i=0;i<len;i+=step) measureRow(rows[i],nat);
    for(var k=0;k<n;k++){ if(nat[k]>max[k]) max[k]=nat[k]; }          // ratchet up only
    table.style.tableLayout='fixed';                                 // pin in same synchronous task (no flicker)
    for(var m=0;m<n;m++){ if(ref.cells[m]) ref.cells[m].style.width=max[m]+'px'; }
  }
  function ratchetIn(root){ root.querySelectorAll('table').forEach(ratchet); }

  // ---- at-a-glance health strip: derived client-side from the full /diag.json ----
  function chip(id, ok, html){ var c=document.getElementById('chip-'+id); if(!c) return; c.className='chip '+(ok?'ok':'flag'); c.innerHTML=html; }
  function updateHealth(d){
    if(!document.getElementById('health')) return;
    if('cf_healthy' in d) chip('mirror', d.cf_healthy, '<span class="lbl">mirror</span> '+(d.cf_healthy?'OK':'stale'));
    if(d.backends){ var up=0; d.backends.forEach(function(b){ if(b.healthy) up++; }); chip('upstreams', up===d.backends.length, '<span class="lbl">upstreams</span> <b>'+up+'/'+d.backends.length+'</b>'); }
    if(d.answer_cache) chip('cache', true, '<span class="lbl">cache</span> <b>'+d.answer_cache.hit_ratio+'</b>');
    if(d.workers){ var bad=0; d.workers.forEach(function(w){ bad+=(w.restarts||0)+(w.stalls||0)+(w.panics||0); }); chip('workers', bad===0, '<span class="lbl">workers</span> '+(bad?bad+' events':'OK')); }
    if(d.queries) chip('queries', true, '<span class="lbl">queries</span> <b>'+d.queries.total+'</b>');
    if(d.encrypted && d.encrypted.enabled){ var e = d.encrypted; chip('encrypted', e.cert_valid && e.ddr_ready, '<span class="lbl">encrypted</span> '+(e.ddr_ready ? 'DDR' : (e.cert_valid ? 'no-DDR' : 'cert!'))); }
  }

  function patchSection(root, data){
    if(locked(root)){ root._dirty = data; return; } // defer while the user is selecting/typing here
    root._dirty = null;
    var fn = patchers[root.dataset.live]; if(fn) fn(root, data);
    ratchetIn(root); // after reconcile + applySort: widen-only column widths
  }
  function patchAll(data){
    document.querySelectorAll('[data-live]').forEach(function(root){ var k = root.dataset.live; if(data[k] !== undefined) patchSection(root, data[k]); });
    updateHealth(data);
  }
  function flushDirty(){ document.querySelectorAll('[data-live]').forEach(function(root){ if(root._dirty && !locked(root)) patchSection(root, root._dirty); }); }

  // ---- visibility-aware polling with backoff ----
  var POLL_BASE = 4000, POLL_MAX = 30000, delay = POLL_BASE, timer = null;
  function schedule(){ clearTimeout(timer); if(!document.hidden) timer = setTimeout(poll, delay); }
  function poll(){
    fetch('/diag.json', { cache: 'no-store' }).then(function(r){ if(!r.ok) throw new Error(r.status); return r.json(); })
      .then(function(d){ patchAll(d); delay = POLL_BASE; })
      .catch(function(){ delay = Math.min(delay * 2, POLL_MAX); })
      .then(schedule);
  }
  document.addEventListener('visibilitychange', function(){ if(document.hidden) clearTimeout(timer); else { delay = POLL_BASE; poll(); } });
  var selT; document.addEventListener('selectionchange', function(){ clearTimeout(selT); selT = setTimeout(flushDirty, 150); });
  document.addEventListener('pointerdown', function(){ dragging = true; });
  document.addEventListener('pointerup', function(){ dragging = false; flushDirty(); });
  document.addEventListener('focusout', flushDirty);

  // ---- control actions: lock/unlock + inline per-action feedback (no modal alerts) ----
  var ctl = document.getElementById('ctl'), needPw = ctl && ctl.dataset.needPw === 'true';
  var pwInput = document.getElementById('diagpw'), pwForm = document.getElementById('pwform');
  var pwErr = document.getElementById('pwerr'), lockBtn = document.getElementById('lockbtn');
  var pwEntry = document.getElementById('pwentry'), unlockedNote = document.getElementById('unlockednote');
  var chipLock = document.getElementById('chip-controls');
  // stagedPw is the SINGLE source of truth for "unlocked". The <input> is read only at
  // submit time, so typing-without-Unlock can never half-work. Mirrored to sessionStorage
  // (per-tab; gone on tab close), never localStorage.
  var stagedPw = needPw ? (sessionStorage.getItem('diagpw') || '') : '';

  function setLock(unlocked){
    if(!needPw) return; // loopback mode: no password, no lock concept
    document.body.dataset.locked = unlocked ? 'false' : 'true'; // CSS greys controls when locked
    // Locked shows the password entry; unlocked shows only the Lock affordance — never both.
    if(pwEntry) pwEntry.hidden = unlocked;
    if(unlockedNote) unlockedNote.hidden = !unlocked;
    if(lockBtn) lockBtn.hidden = !unlocked;
    if(chipLock){
      chipLock.className = 'chip clickable ' + (unlocked ? 'ok' : 'flag');
      chipLock.lastChild.nodeValue = unlocked ? ' unlocked' : ' locked';
      chipLock.setAttribute('aria-label', unlocked ? 'Controls unlocked' : 'Controls locked — activate to unlock');
    }
  }
  function stage(pw){ stagedPw = pw || ''; if(stagedPw) sessionStorage.setItem('diagpw', stagedPw); else sessionStorage.removeItem('diagpw'); setLock(!!stagedPw); }
  function showPwErr(msg){ if(pwErr) pwErr.textContent = msg || ''; if(pwInput){ if(msg) pwInput.setAttribute('aria-invalid','true'); else pwInput.removeAttribute('aria-invalid'); } }
  function focusField(){ if(!pwInput) return; var sec = document.getElementById('controls'); if(sec) sec.scrollIntoView({ block: 'nearest' }); pwInput.focus(); pwInput.classList.add('flash'); setTimeout(function(){ pwInput.classList.remove('flash'); }, 700); }
  // verify against the side-effect-free probe so Unlock confirms immediately; cb(ok, status).
  function verify(pw, cb){ fetch('/control/verify', { method: 'POST', headers: { 'X-Diag-Password': pw } }).then(function(r){ cb(r.status === 200, r.status); }).catch(function(){ cb(false, 0); }); }

  if(pwForm){ pwForm.addEventListener('submit', function(e){
    e.preventDefault();
    var pw = pwInput ? pwInput.value : '';
    if(!pw){ stage(''); showPwErr(''); return; }
    showPwErr('checking…');
    verify(pw, function(ok, status){
      if(ok){ stage(pw); showPwErr(''); if(pwInput) pwInput.blur(); }
      else if(status === 429){ showPwErr('too many attempts — retry shortly'); }
      else if(status === 401){ stage(''); showPwErr('incorrect password'); if(pwInput) pwInput.focus(); }
      else { showPwErr('could not reach server'); }
    });
  }); }
  if(lockBtn){ lockBtn.addEventListener('click', function(){ stage(''); if(pwInput) pwInput.value = ''; showPwErr(''); }); }
  if(chipLock){ chipLock.addEventListener('click', function(e){ if(document.body.dataset.locked === 'true'){ e.preventDefault(); focusField(); } }); }

  // Each control button gets its own adjacent status slot (live region). For a backend
  // button the slot lives in the btn cell and is naturally cleared when the row reconciles.
  function slotFor(btn){
    var s = btn.nextElementSibling;
    if(!s || !s.classList.contains('ctl-msg')){ s = document.createElement('span'); s.className = 'ctl-msg'; s.setAttribute('role', 'status'); s.setAttribute('aria-live', 'polite'); btn.parentNode.insertBefore(s, btn.nextSibling); }
    return s;
  }
  function setSlot(btn, msg, cls){ var s = slotFor(btn); s.textContent = msg || ''; s.className = 'ctl-msg' + (cls ? ' ' + cls : ''); return s; }

  function doControl(btn){
    if(needPw && !stagedPw){ setSlot(btn, 'unlock first ↑', 'muted'); focusField(); return; } // locked: route to the field
    if(btn.dataset.confirm && !confirm(btn.dataset.confirm)) return; // a confirmation, not a result alert
    var q = ''; if(btn.dataset.op){ q = 'op=' + encodeURIComponent(btn.dataset.op); if(btn.dataset.addr) q += '&addr=' + encodeURIComponent(btn.dataset.addr); }
    var headers = {}; if(needPw) headers['X-Diag-Password'] = stagedPw;
    btn.disabled = true; btn.setAttribute('aria-busy', 'true'); setSlot(btn, 'working…', 'muted'); // persists until resolved: "slow" is unambiguous
    var done = function(){ btn.disabled = false; btn.removeAttribute('aria-busy'); };
    fetch('/control/' + btn.dataset.action + (q ? '?' + q : ''), { method: 'POST', headers: headers }).then(function(r){
      if(r.ok){ done(); var s = setSlot(btn, 'done', 'ok'); setTimeout(function(){ if(s.textContent === 'done') s.textContent = ''; }, 4000); poll(); return; }
      if(r.status === 401){ done(); stage(''); setSlot(btn, 'locked — re-enter password', 'flag'); showPwErr('incorrect password'); focusField(); return; }
      if(r.status === 429){ done(); setSlot(btn, 'rate-limited — retry shortly', 'flag'); return; }
      if(r.status === 403){ done(); setSlot(btn, 'refused (cross-site or disabled)', 'flag'); return; }
      r.text().then(function(t){ done(); setSlot(btn, (t && t.trim()) ? t.trim() : ('error ' + r.status), 'flag'); if(r.status === 404) poll(); }); // 404/5xx: show the server's reason
    }).catch(function(){ done(); setSlot(btn, 'request failed', 'flag'); }); // network, not auth — stay unlocked
  }
  // Delegate clicks so reconciled backend buttons need no re-binding.
  document.addEventListener('click', function(e){ var b = e.target.closest && e.target.closest('button.ctl'); if(b) doControl(b); });

  setLock(!!stagedPw); // reflect any session password in the chip/body state on load
  if(needPw && stagedPw){ verify(stagedPw, function(ok, status){ if(!ok && status === 401){ stage(''); showPwErr('session expired — re-enter password'); } }); } // silent re-check

  // ---- sticky-offset measurement + ratchet seeding ----
  function setTopbarH(){ var tb = document.querySelector('.topbar'); if(tb) document.documentElement.style.setProperty('--topbar-h', tb.offsetHeight + 'px'); }
  setTopbarH(); window.addEventListener('resize', setTopbarH);
  // Re-ratchet tables when a <details> opens (they have no layout while closed).
  document.addEventListener('toggle', function(e){ if(e.target.tagName === 'DETAILS' && e.target.open) ratchetIn(e.target); }, true);
  document.querySelectorAll('[data-live] table').forEach(ratchet); // seed widths from server-rendered content
  setTopbarH();

  // Host enrichment: fetch vendor/scope for one mDNS host on demand (lazy, cached server-side).
  var hasHostInfo = {{if .HasHostInfo}}true{{else}}false{{end}};
  function fmtHostInfo(d){
    var parts = [];
    if(d.vendors && d.vendors.length) parts.push(d.vendors.join(', '));
    if(d.services && d.services.length) parts.push(d.services.join(' '));
    if(d.families) parts.push(d.families);
    if(d.scopes && d.scopes.length) parts.push(d.scopes.join('/'));
    return parts.length ? parts.join(' — ') : 'unidentified';
  }
  document.addEventListener('click', function(ev){
    var a = ev.target && ev.target.closest ? ev.target.closest('a.hi') : null;
    if(!a) return;
    ev.preventDefault();
    var cell = a.parentNode; cell.textContent = '…';
    fetch('/host?name=' + encodeURIComponent(a.dataset.h), { cache: 'no-store' })
      .then(function(r){ return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function(d){ cell.textContent = fmtHostInfo(d); })
      .catch(function(e){ cell.textContent = (e === 404) ? 'no longer in view' : 'n/a'; });
  });

  // Config panel: fetch the redacted config lazily on first expand (never in the poll).
  var cfgP = document.getElementById('cfgpanel');
  if(cfgP){ cfgP.addEventListener('toggle', function(){
    if(!cfgP.open || cfgP.dataset.loaded) return;
    cfgP.dataset.loaded = '1';
    fetch('/config', { cache: 'no-store' })
      .then(function(r){ return r.ok ? r.text() : Promise.reject(r.status); })
      .then(function(t){ document.getElementById('cfgtext').textContent = t; })
      .catch(function(e){ cfgP.dataset.loaded = ''; document.getElementById('cfgtext').textContent = 'config unavailable (' + e + ')'; });
  }); }

  poll(); // kick off live updates
})();
</script>
</body></html>`))
