// Package forwarder forwards non-authoritative queries to upstream resolvers
// (design §2.4 step 8, §6, Q6). Transport is negotiated most-secure-first: DoT
// (DNS-over-TLS, :853) by default, with an audited one-shot fallback to cleartext
// UDP (then TCP on truncation) only when explicitly enabled. It performs no answer
// filtering itself — the handler applies the §4.2 rebind filter to the result — so
// this package stays a thin, well-bounded transport.
package forwarder

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dotNames maps well-known resolver IPs to the TLS server name their certificate
// presents, so DoT validates. Unlisted servers may carry an explicit name via the
// "ip@servername" config form (see Build).
var dotNames = map[string]string{
	"1.1.1.1": "cloudflare-dns.com", "1.0.0.1": "cloudflare-dns.com",
	"2606:4700:4700::1111": "cloudflare-dns.com", "2606:4700:4700::1001": "cloudflare-dns.com",
	"8.8.8.8": "dns.google", "8.8.4.4": "dns.google",
	"2001:4860:4860::8888": "dns.google", "2001:4860:4860::8844": "dns.google",
	"9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net",
}

// Upstream is one resolver endpoint with its transport.
type Upstream struct {
	Addr       string // host:port
	Net        string // "tcp-tls" (DoT), "udp", or "tcp"
	ServerName string // TLS SNI/verification name for tcp-tls
}

// Forwarder forwards queries over its configured upstreams.
type Forwarder struct {
	primary   []Upstream // DoT, tried in order
	fallback  []Upstream // cleartext UDP, used only when cleartext is true
	cleartext bool
	perTry    time.Duration // single-exchange cap (dns.Client.Timeout)
	overall   time.Duration // ceiling for the whole multi-upstream excursion
	audit     func(string)

	breakerEnabled bool
	policy         Policy
	now            func() time.Time

	mu       sync.Mutex
	clients  map[string]*dns.Client  // keyed by net+serverName
	breakers map[string]*breaker     // per-upstream, keyed by net+addr
	disabled map[string]bool         // manually disabled upstreams (by addr), for debugging
	bstats   map[string]*backendStat // per-upstream lifetime counters, keyed by net+addr
}

// backendStat accumulates lifetime per-upstream telemetry for the diagnostics page.
// Unlike the breaker's rolling window (which resets on recovery), these never reset, so
// they answer "how much traffic has this upstream carried, and how fast/reliably".
type backendStat struct {
	queries   uint64
	failures  uint64
	okLatency time.Duration // summed over successful exchanges only (avg = / successes)
	lastOK    time.Duration // latency of the most recent successful exchange
}

// Option customizes a Forwarder at construction (used mainly for the breaker and by
// tests that inject a clock/policy).
type Option func(*Forwarder)

// WithBreaker enables or disables the per-upstream circuit breaker (default on).
func WithBreaker(enabled bool) Option { return func(f *Forwarder) { f.breakerEnabled = enabled } }

// WithPolicy overrides the breaker policy.
func WithPolicy(p Policy) Option { return func(f *Forwarder) { f.policy = p } }

// WithClock injects the clock the breaker reads (deterministic tests).
func WithClock(now func() time.Time) Option { return func(f *Forwarder) { f.now = now } }

// newForwarder builds the common Forwarder shell and applies opts.
func newForwarder(cleartext bool, audit func(string), opts []Option) *Forwarder {
	if audit == nil {
		audit = func(string) {}
	}
	f := &Forwarder{
		cleartext: cleartext, perTry: 1500 * time.Millisecond, overall: 4 * time.Second,
		audit: audit, clients: map[string]*dns.Client{}, breakers: map[string]*breaker{},
		disabled:       map[string]bool{},
		bstats:         map[string]*backendStat{},
		breakerEnabled: true, policy: DefaultPolicy(), now: time.Now,
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

// Build constructs a Forwarder from config server strings. Each "host[:port]" (or
// "host@servername") becomes a DoT primary (default port 853) and a cleartext UDP
// fallback (port 53). audit may be nil.
func Build(servers []string, cleartext bool, audit func(string), opts ...Option) (*Forwarder, error) {
	f := newForwarder(cleartext, audit, opts)
	for _, s := range servers {
		host, sni := s, ""
		if at := indexByte(s, '@'); at >= 0 {
			host, sni = s[:at], s[at+1:]
		}
		ip, port, err := net.SplitHostPort(host)
		if err != nil {
			ip, port = host, ""
		}
		if sni == "" {
			sni = dotNames[ip]
		}
		dotPort := port
		if dotPort == "" || dotPort == "53" {
			dotPort = "853"
		}
		f.primary = append(f.primary, Upstream{Addr: net.JoinHostPort(ip, dotPort), Net: "tcp-tls", ServerName: sni})
		f.fallback = append(f.fallback, Upstream{Addr: net.JoinHostPort(ip, "53"), Net: "udp"})
	}
	if len(f.primary) == 0 {
		return nil, fmt.Errorf("forwarder: no upstream servers configured")
	}
	return f, nil
}

// NewWithUpstreams constructs a Forwarder from explicit upstream lists (used by
// tests and any caller that wants full control over transports/ports).
func NewWithUpstreams(primary, fallback []Upstream, cleartext bool, audit func(string), opts ...Option) *Forwarder {
	f := newForwarder(cleartext, audit, opts)
	f.primary, f.fallback = primary, fallback
	return f
}

// Forward sends req and returns the upstream response. It tries each DoT upstream in
// order; if all DoT attempts fail and cleartext fallback is enabled, it tries each
// upstream over plain UDP (retrying TCP on truncation), auditing the downgrade.
func (f *Forwarder) Forward(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// Overall ceiling; the caller's (shorter) per-request deadline still wins (D4).
	ctx, cancel := context.WithTimeout(ctx, f.overall)
	defer cancel()

	resp, err := f.tryAll(ctx, req, f.primary, true)
	if err == nil {
		return resp, nil
	}
	if !f.cleartext {
		return nil, fmt.Errorf("forwarder: all DoT upstreams failed (cleartext disabled): %w", err)
	}
	f.audit(fmt.Sprintf("forwarder: DoT failed (%v); falling back to cleartext for %s", err, qname(req)))
	resp, ferr := f.tryAll(ctx, req, f.fallback, false)
	if ferr == nil {
		return resp, nil
	}
	return nil, fmt.Errorf("forwarder: all upstreams failed: %w", ferr)
}

// ForwardTo sends req to an explicit set of resolver endpoints (the stub-zone path,
// §2.4 step 5) over plain UDP/TCP. Stub targets are LAN resolvers, not DoT.
func (f *Forwarder) ForwardTo(ctx context.Context, targets []string, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, f.overall)
	defer cancel()
	ups := make([]Upstream, len(targets))
	for i, addr := range targets {
		ups[i] = Upstream{Addr: addr, Net: "udp"}
	}
	resp, err := f.tryAll(ctx, req, ups, false)
	if err != nil {
		return nil, fmt.Errorf("forwarder: all stub targets failed: %w", err)
	}
	return resp, nil
}

// tryAll attempts each upstream under its circuit breaker. If EVERY eligible upstream
// is tripped (breaker open) it fails open — a forced pass that ignores breaker state —
// so the breaker can never make resolution worse than not having one; it only ever
// skips a dead upstream when a live one exists. requireSNI skips tcp-tls upstreams
// with no ServerName (cannot validate the cert).
func (f *Forwarder) tryAll(ctx context.Context, req *dns.Msg, ups []Upstream, requireSNI bool) (*dns.Msg, error) {
	var lastErr error
	allowedAny := false
	for _, u := range ups {
		if requireSNI && u.Net == "tcp-tls" && u.ServerName == "" {
			lastErr = fmt.Errorf("no TLS server name for %s", u.Addr)
			continue
		}
		if f.isDisabled(u.Addr) {
			lastErr = fmt.Errorf("forwarder: %s manually disabled", u.Addr)
			continue
		}
		br := f.breakerFor(u)
		if br != nil && !br.allow() {
			lastErr = fmt.Errorf("forwarder: breaker open for %s", u.Addr)
			continue
		}
		allowedAny = true
		start := f.now()
		resp, err := f.attempt(ctx, u, req)
		f.noteAttempt(u, err == nil, f.now().Sub(start))
		if br != nil {
			br.record(err == nil)
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if f.breakerEnabled && !allowedAny {
		for _, u := range ups { // fail-open: every eligible upstream was tripped
			if requireSNI && u.Net == "tcp-tls" && u.ServerName == "" {
				continue
			}
			if f.isDisabled(u.Addr) {
				continue // a manual disable is absolute, even under fail-open
			}
			start := f.now()
			resp, err := f.attempt(ctx, u, req)
			f.noteAttempt(u, err == nil, f.now().Sub(start))
			if br := f.breakerFor(u); br != nil {
				br.record(err == nil)
			}
			if err == nil {
				return resp, nil
			}
			lastErr = err
		}
	}
	return nil, lastErr
}

// attempt runs one exchange, upgrading a truncated UDP answer to TCP. A nil error
// means the upstream responded (transport-healthy), which is what the breaker counts.
func (f *Forwarder) attempt(ctx context.Context, u Upstream, req *dns.Msg) (*dns.Msg, error) {
	resp, err := f.exchange(ctx, u, req)
	if err != nil {
		return nil, err
	}
	if resp.Truncated && u.Net == "udp" {
		if tcp, terr := f.exchange(ctx, Upstream{Addr: u.Addr, Net: "tcp"}, req); terr == nil {
			return tcp, nil
		}
	}
	return resp, nil
}

// BackendStatus is a read-only health snapshot of one upstream for diagnostics.
type BackendStatus struct {
	Addr      string        `json:"addr"`
	Net       string        `json:"net"`   // "tcp-tls" (DoT), "udp", or "tcp"
	Role      string        `json:"role"`  // "primary" or "fallback"
	State     string        `json:"state"` // "closed"/"open"/"half-open"/"disabled", or "n/a"
	Healthy   bool          `json:"healthy"`
	Disabled  bool          `json:"disabled"` // manually disabled for debugging
	Consec    int           `json:"consecutive_failures"`
	FailRatio float64       `json:"fail_ratio"`
	OpenFor   time.Duration `json:"open_for"`
	Cooldown  time.Duration `json:"cooldown_remaining"`

	// Lifetime telemetry (never reset; survives breaker recovery).
	Queries  uint64        `json:"queries"`  // exchanges attempted against this upstream
	Failures uint64        `json:"failures"` // of which errored (timeout/refused/etc.)
	AvgRTT   time.Duration `json:"-"`        // mean latency over successful exchanges
	LastRTT  time.Duration `json:"-"`        // latency of the most recent success
}

// noteAttempt records the outcome and latency of one exchange against u (lifetime
// counters, independent of the breaker's rolling window). Concurrency-safe.
func (f *Forwarder) noteAttempt(u Upstream, ok bool, d time.Duration) {
	key := u.Net + "|" + u.Addr
	f.mu.Lock()
	bs := f.bstats[key]
	if bs == nil {
		bs = &backendStat{}
		f.bstats[key] = bs
	}
	bs.queries++
	if ok {
		bs.okLatency += d
		bs.lastOK = d
	} else {
		bs.failures++
	}
	f.mu.Unlock()
}

// statSnapshot returns the lifetime counters for u (zeroes if none recorded yet).
func (f *Forwarder) statSnapshot(u Upstream) (queries, failures uint64, avgRTT, lastRTT time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bs := f.bstats[u.Net+"|"+u.Addr]
	if bs == nil {
		return 0, 0, 0, 0
	}
	if ok := bs.queries - bs.failures; ok > 0 {
		avgRTT = bs.okLatency / time.Duration(ok)
	}
	return bs.queries, bs.failures, avgRTT, bs.lastOK
}

// Backends returns the health of every configured upstream (DoT primaries, plus the
// cleartext fallbacks when cleartext is enabled). Read-only and concurrency-safe.
func (f *Forwarder) Backends() []BackendStatus {
	now := f.now()
	var out []BackendStatus
	add := func(u Upstream, role string) {
		bs := BackendStatus{Addr: u.Addr, Net: u.Net, Role: role, State: "n/a", Healthy: true}
		bs.Queries, bs.Failures, bs.AvgRTT, bs.LastRTT = f.statSnapshot(u)
		if f.isDisabled(u.Addr) {
			bs.State, bs.Disabled, bs.Healthy = "disabled", true, false
			out = append(out, bs)
			return
		}
		if f.breakerEnabled {
			bs.State = "closed" // healthy until the breaker (if any) says otherwise
			if b := f.peekBreaker(u); b != nil {
				bs.State, bs.Consec, bs.FailRatio, bs.OpenFor, bs.Cooldown = b.status(now)
				bs.Healthy = bs.State != "open"
			}
		}
		out = append(out, bs)
	}
	for _, u := range f.primary {
		add(u, "primary")
	}
	if f.cleartext {
		for _, u := range f.fallback {
			add(u, "fallback")
		}
	}
	return out
}

// SetBackendEnabled manually enables/disables an upstream by its addr (host:port) for
// on-the-fly debugging. A disabled upstream is skipped like a tripped breaker, EXCEPT it
// is also excluded from the fail-open pass — a manual disable is absolute. Returns false
// if addr matches no configured upstream.
func (f *Forwarder) SetBackendEnabled(addr string, enabled bool) bool {
	if !f.knownAddr(addr) {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if enabled {
		delete(f.disabled, addr)
	} else {
		f.disabled[addr] = true
	}
	return true
}

// ResetBackends clears every manual disable (back to defaults).
func (f *Forwarder) ResetBackends() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disabled = map[string]bool{}
}

func (f *Forwarder) knownAddr(addr string) bool {
	for _, u := range f.primary {
		if u.Addr == addr {
			return true
		}
	}
	for _, u := range f.fallback {
		if u.Addr == addr {
			return true
		}
	}
	return false
}

func (f *Forwarder) isDisabled(addr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disabled[addr]
}

// peekBreaker returns the existing per-upstream breaker WITHOUT creating one — so the
// read-only diagnostics path neither mutates f.breakers nor allocates (it just takes a
// brief read of f.mu). Returns nil if no breaker has been created for u yet.
func (f *Forwarder) peekBreaker(u Upstream) *breaker {
	if !f.breakerEnabled {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.breakers[u.Net+"|"+u.Addr]
}

// breakerFor returns the per-upstream breaker (nil when breakers are disabled).
func (f *Forwarder) breakerFor(u Upstream) *breaker {
	if !f.breakerEnabled {
		return nil
	}
	key := u.Net + "|" + u.Addr
	f.mu.Lock()
	defer f.mu.Unlock()
	if b := f.breakers[key]; b != nil {
		return b
	}
	b := newBreaker(f.policy, f.now)
	f.breakers[key] = b
	return b
}

func (f *Forwarder) exchange(ctx context.Context, u Upstream, req *dns.Msg) (*dns.Msg, error) {
	c := f.clientFor(u)
	resp, _, err := c.ExchangeContext(ctx, req, u.Addr)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", u.Net, u.Addr, err)
	}
	return resp, nil
}

func (f *Forwarder) clientFor(u Upstream) *dns.Client {
	key := u.Net + "|" + u.ServerName
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[key]; ok {
		return c
	}
	c := &dns.Client{Net: u.Net, Timeout: f.perTry}
	if u.Net == "tcp-tls" {
		c.TLSConfig = &tls.Config{ServerName: u.ServerName, MinVersion: tls.VersionTLS12}
	}
	f.clients[key] = c
	return c
}

func qname(m *dns.Msg) string {
	if m != nil && len(m.Question) > 0 {
		return m.Question[0].Name
	}
	return "?"
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// ParseAddrPorts validates host:port stub targets at config time.
func ParseAddrPorts(targets []string) error {
	for _, t := range targets {
		if _, _, err := net.SplitHostPort(t); err != nil {
			return fmt.Errorf("forwarder: bad target %q: %w", t, err)
		}
		_, p, _ := net.SplitHostPort(t)
		if _, err := strconv.Atoi(p); err != nil {
			return fmt.Errorf("forwarder: bad port in %q", t)
		}
	}
	return nil
}
