// Package server is the :53 front end: UDP+TCP listeners and the dns.Handler that
// ties the hot path together. For each query it enforces client access control and
// an inbound concurrency limiter (design §3.5), then asks the pure resolver
// (§2.4) for a decision and either replies directly or forwards (default upstreams
// or a stub zone), applying the §4.2 rebind filter to forwarded answers. It reads
// the immutable Snapshot/MDNSView through caller-supplied accessors so the control
// plane can swap them atomically without the handler taking a lock.
package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/anscache"
	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
	"github.com/gutschke/splitdns/internal/qlog"
	"github.com/gutschke/splitdns/internal/resolver"
)

// Config wires the handler's dependencies.
type Config struct {
	Access      netmatch.Access
	Snapshot    func() *model.Snapshot
	View        func() *model.MDNSView
	Forwarder   *forwarder.Forwarder
	Cache       *anscache.Cache // forward-path answer cache; nil disables caching
	QueryLog    *qlog.Log       // query telemetry for diagnostics; nil disables recording
	Log         func(string)
	MaxInflight int             // global concurrent ServeDNS cap (default 4096)
	ReadTimeout time.Duration   // TCP read timeout (default 2s)
	IdleTimeout time.Duration   // TCP idle timeout (default 5s)
	Context     context.Context // daemon lifetime; per-request forwards derive from it (default Background)
	QueryBudget time.Duration   // per-request forward deadline (default 2s, design §3 SLO; D4)
}

// Server holds listeners and the shared handler state.
type Server struct {
	cfg     Config
	sem     chan struct{}
	log     func(string)
	baseCtx context.Context
	budget  time.Duration
	mu      sync.Mutex
	servers []*dns.Server
	bound   []net.Addr
}

// New builds a Server. Snapshot/View must be non-nil; both may return nil at first
// (an empty resolver still answers *.local/forward).
func New(cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = 4096
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 2 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Second
	}
	if cfg.QueryBudget <= 0 {
		cfg.QueryBudget = 2 * time.Second
	}
	baseCtx := cfg.Context
	if baseCtx == nil {
		// Serving-tree root used only when no daemon context is injected (tests/standalone
		// callers); every real forward still derives a WithTimeout deadline from it.
		baseCtx = context.Background() //nolint:forbidigo // sanctioned request-tree root
	}
	return &Server{cfg: cfg, sem: make(chan struct{}, cfg.MaxInflight), log: cfg.Log, baseCtx: baseCtx, budget: cfg.QueryBudget}
}

// result carries the decision/rcode for one request so ServeDNS can record telemetry
// once at the end regardless of which terminal path handled it.
type result struct {
	decision qlog.Decision
	rcode    int
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	ip := clientIP(w.RemoteAddr())
	transport := transportOf(w)
	res := result{decision: qlog.Servfail, rcode: dns.RcodeServerFailure}
	if s.cfg.QueryLog != nil {
		defer func() { s.recordQuery(start, ip, transport, req, res) }()
	}

	// Client access control (refuse beats allow).
	if ip.IsValid() && !s.cfg.Access.Allowed(ip) {
		res = result{qlog.Refused, dns.RcodeRefused}
		s.refuse(w, req, dns.RcodeRefused)
		return
	}

	// Inbound concurrency limiter: never grow unbounded under flood. On overflow,
	// drop UDP (no reply) and SERVFAIL TCP, rather than spawning more work.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		res.decision = qlog.Dropped
		if isTCP(w) {
			s.refuse(w, req, dns.RcodeServerFailure)
		}
		return
	}

	snap := s.cfg.Snapshot()
	view := s.cfg.View()
	if snap == nil {
		snap = &model.Snapshot{}
	}
	if view == nil {
		view = &model.MDNSView{}
	}

	out := resolver.Resolve(snap, view, req)
	switch {
	case out.Msg != nil:
		res = result{qlog.Local, out.Msg.Rcode}
		s.respond(w, req, out.Msg)
	case len(out.Stub) > 0:
		res.decision = qlog.Stub
		s.forward(w, req, func(ctx context.Context) (*dns.Msg, error) {
			return s.cfg.Forwarder.ForwardTo(ctx, out.Stub, req)
		}, false, snap, &res) // stub targets are trusted LAN resolvers: no rebind strip
	case out.Forward:
		s.forwardCached(w, req, snap, &res)
	default:
		s.refuse(w, req, dns.RcodeServerFailure)
	}
}

// recordQuery appends one telemetry entry (single-question queries only).
func (s *Server) recordQuery(start time.Time, ip netip.Addr, transport string, req *dns.Msg, res result) {
	if len(req.Question) != 1 {
		return
	}
	q := req.Question[0]
	s.cfg.QueryLog.Record(qlog.Entry{
		Time:      start,
		Client:    ip,
		Transport: transport,
		Name:      q.Name,
		Qtype:     dns.TypeToString[q.Qtype],
		Decision:  res.decision,
		Rcode:     dns.RcodeToString[res.rcode],
		Latency:   time.Since(start),
	})
}

// transportOf labels the transport a request arrived on. Encrypted front-ends decorate
// the ResponseWriter with a Transport() method ("dot"/"doh"); a plain Do53 writer has
// none, so we fall back to the TCP/UDP distinction.
func transportOf(w dns.ResponseWriter) string {
	if t, ok := w.(interface{ Transport() string }); ok {
		if s := t.Transport(); s != "" {
			return s
		}
	}
	if isTCP(w) {
		return "tcp"
	}
	return "udp"
}

func (s *Server) forward(w dns.ResponseWriter, req *dns.Msg, do func(context.Context) (*dns.Msg, error), rebind bool, snap *model.Snapshot, res *result) {
	if s.cfg.Forwarder == nil {
		s.refuse(w, req, dns.RcodeServerFailure)
		return
	}
	// Per-request budget (D4): bound every upstream excursion at QueryBudget and
	// cancel in-flight forwards when the daemon context is cancelled at shutdown.
	ctx, cancel := context.WithTimeout(s.baseCtx, s.budget)
	defer cancel()
	resp, err := do(ctx)
	if err != nil || resp == nil {
		s.log(fmt.Sprintf("forward %s: %v", qname(req), err))
		s.refuse(w, req, dns.RcodeServerFailure)
		return
	}
	res.rcode = resp.Rcode
	resp.Id = req.Id
	if rebind {
		applyRebindFilter(resp, snap.AllowSuffix)
	}
	s.respond(w, req, resp)
}

// forwardCached is the public-upstream forward path WITH the answer cache (anscache):
// it serves a fresh cache hit directly, returns SERVFAIL on a cached failure (RFC 9520),
// otherwise forwards upstream and caches the result. On an upstream failure it serves a
// stale entry if one exists (RFC 8767 serve-stale) and only SERVFAILs when it has no
// usable data. The rebind filter and EDNS re-stamping are applied on EGRESS for every
// serve (fresh-hit, stale, or live) so cache and live paths are identical and a policy
// change takes effect immediately. With a nil cache this degrades to a plain forward.
func (s *Server) forwardCached(w dns.ResponseWriter, req *dns.Msg, snap *model.Snapshot, res *result) {
	res.decision = qlog.Forward
	if s.cfg.Forwarder == nil {
		s.refuse(w, req, dns.RcodeServerFailure)
		return
	}
	key, cacheOK := anscache.Key{}, false
	if s.cfg.Cache != nil {
		key, cacheOK = anscache.KeyFor(req)
	}

	var stale *dns.Msg
	if cacheOK {
		switch msg, hit := s.cfg.Cache.Lookup(key); hit {
		case anscache.Fresh:
			res.decision, res.rcode = qlog.CacheHit, msg.Rcode
			s.serveForwarded(w, req, msg, snap)
			return
		case anscache.Fail:
			s.refuse(w, req, dns.RcodeServerFailure)
			return
		case anscache.Stale:
			stale = msg // try a live refresh first; fall back to this on failure
		}
	}

	ctx, cancel := context.WithTimeout(s.baseCtx, s.budget)
	defer cancel()
	resp, err := s.cfg.Forwarder.Forward(ctx, req)
	if err == nil && resp != nil && cacheableRcode(resp.Rcode) {
		res.rcode = resp.Rcode
		if cacheOK {
			s.cfg.Cache.Store(key, resp)
		}
		s.serveForwarded(w, req, resp, snap)
		return
	}

	// Upstream failed (transport error, nil, or a non-cacheable rcode like SERVFAIL).
	if err != nil {
		s.log(fmt.Sprintf("forward %s: %v", qname(req), err))
	}
	if stale != nil {
		res.decision, res.rcode = qlog.Stale, stale.Rcode
		if cacheOK {
			s.cfg.Cache.NoteStaleServed()
		}
		s.serveForwarded(w, req, stale, snap)
		return
	}
	if cacheOK {
		s.cfg.Cache.StoreFail(key)
	}
	s.refuse(w, req, dns.RcodeServerFailure)
}

// serveForwarded is the common egress for the public path: stamp the request Id, apply
// the §4.2 rebind filter against the CURRENT snapshot, and write. Used identically for
// a fresh cache hit, a stale serve, and a live upstream answer.
func (s *Server) serveForwarded(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg, snap *model.Snapshot) {
	resp.Id = req.Id
	applyRebindFilter(resp, snap.AllowSuffix)
	s.respond(w, req, resp)
}

// cacheableRcode reports whether an upstream rcode represents a real answer worth
// caching (positive or authoritative-negative) vs a failure handled via serve-stale.
func cacheableRcode(rcode int) bool {
	return rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError
}

// applyRebindFilter strips blocked private/non-routable A/AAAA from a forwarded
// answer (design §4.2) unless the answer name is under an AllowSuffix (a mirrored/
// stub/static suffix, where a private record is legitimate).
func applyRebindFilter(resp *dns.Msg, allow []string) {
	if len(resp.Question) > 0 && underAllow(strings.ToLower(resp.Question[0].Name), allow) {
		return
	}
	kept := resp.Answer[:0]
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if addr, ok := netipFrom(v.A); ok && netmatch.IsForwardBlocked(addr) {
				continue
			}
		case *dns.AAAA:
			if addr, ok := netipFrom(v.AAAA); ok && netmatch.IsForwardBlocked(addr) {
				continue
			}
		}
		kept = append(kept, rr)
	}
	resp.Answer = kept
}

func underAllow(name string, allow []string) bool {
	for _, sfx := range allow {
		sfx = strings.ToLower(sfx)
		// LABEL-ALIGNED suffix match only: "www.corp.test." is under "corp.test.",
		// but the look-alike "evilcorp.test." is NOT — a bare HasSuffix here would let
		// an attacker-named record bypass the rebind filter (panel finding D1).
		if name == sfx || strings.HasSuffix(name, "."+sfx) {
			return true
		}
	}
	return false
}

// serverUDPSize is the EDNS UDP payload size we advertise and truncate to —
// 1232 is the conservative DNS-flag-day value that avoids IP fragmentation.
const serverUDPSize = 1232

// respond finalizes EDNS signaling (D2) and writes m. If the client sent an OPT,
// we attach our own server OPT echoing its DO bit and advertising serverUDPSize;
// over UDP we then m.Truncate() to the negotiated size so oversized answers set
// TC and the client retries over TCP. Classic (no-OPT) clients get no OPT and a
// 512-byte UDP limit.
func (s *Server) respond(w dns.ResponseWriter, req *dns.Msg, m *dns.Msg) {
	tcp := isTCP(w)
	udpSize := 512
	if opt := req.IsEdns0(); opt != nil {
		// Re-stamp our own OPT (drop any echoed/upstream OPT first).
		stripOPT(m)
		do := opt.Do()
		m.SetEdns0(serverUDPSize, do)
		if cs := int(opt.UDPSize()); cs >= 512 {
			udpSize = cs
		}
		if udpSize > serverUDPSize {
			udpSize = serverUDPSize
		}
	} else {
		stripOPT(m) // never volunteer EDNS to a classic client
	}
	if !tcp {
		m.Truncate(udpSize) // sets TC + trims when oversized; no-op when it fits
	}
	if err := w.WriteMsg(m); err != nil {
		s.log(fmt.Sprintf("write: %v", err))
	}
}

// stripOPT removes any OPT pseudo-RR from m.Extra so respond can set its own.
func stripOPT(m *dns.Msg) {
	if len(m.Extra) == 0 {
		return
	}
	kept := m.Extra[:0]
	for _, rr := range m.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		kept = append(kept, rr)
	}
	m.Extra = kept
}

func (s *Server) refuse(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	s.respond(w, req, m)
}

// Start binds and serves on each address for the enabled protocols. It returns once
// the listeners are bound (so callers/tests can immediately query), serving in the
// background until Shutdown.
func (s *Server) Start(addrs []string, udp, tcp bool) error {
	for _, addr := range addrs {
		if udp {
			pc, err := net.ListenPacket(netmatch.ListenNetwork("udp", addr), addr)
			if err != nil {
				return fmt.Errorf("server: udp %s: %w", addr, err)
			}
			srv := &dns.Server{PacketConn: pc, Handler: s}
			s.track(srv, pc.LocalAddr())
			go func() { _ = srv.ActivateAndServe() }()
		}
		if tcp {
			l, err := net.Listen(netmatch.ListenNetwork("tcp", addr), addr)
			if err != nil {
				return fmt.Errorf("server: tcp %s: %w", addr, err)
			}
			srv := &dns.Server{Listener: l, Handler: s, ReadTimeout: s.cfg.ReadTimeout, IdleTimeout: func() time.Duration { return s.cfg.IdleTimeout }}
			s.track(srv, l.Addr())
			go func() { _ = srv.ActivateAndServe() }()
		}
	}
	return nil
}

func (s *Server) track(srv *dns.Server, addr net.Addr) {
	s.mu.Lock()
	s.servers = append(s.servers, srv)
	s.bound = append(s.bound, addr)
	s.mu.Unlock()
}

// BoundAddrs returns the actually-bound listener addresses (useful with port 0).
func (s *Server) BoundAddrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]net.Addr(nil), s.bound...)
}

// Shutdown stops all listeners.
func (s *Server) Shutdown() {
	s.mu.Lock()
	servers := append([]*dns.Server(nil), s.servers...)
	s.mu.Unlock()
	for _, srv := range servers {
		_ = srv.Shutdown()
	}
}

func clientIP(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return ip.Unmap()
		}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

func netipFrom(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func isTCP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}

func qname(m *dns.Msg) string {
	if len(m.Question) > 0 {
		return m.Question[0].Name
	}
	return "?"
}
