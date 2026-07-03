package encrypted

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/netmatch"
)

// Manager owns the encrypted listeners (DoT dns.Servers + DoH http.Servers). It reuses
// the daemon's *server.Server (passed as a dns.Handler) so every transport shares one
// query pipeline. It tracks its own listeners and shuts them down independently of the
// Do53 server.
type Manager struct {
	handler     dns.Handler
	reloader    *CertReloader
	log         func(string)
	readTimeout time.Duration
	idleTimeout time.Duration

	mu       sync.Mutex
	dnsSrvs  []*dns.Server
	httpSrvs []*http.Server
	bound    []net.Addr
	dotBound []net.Addr
	dohBound []net.Addr
}

// NewManager builds a Manager. handler is the shared query handler (*server.Server).
func NewManager(handler dns.Handler, reloader *CertReloader, log func(string)) *Manager {
	if log == nil {
		log = func(string) {}
	}
	return &Manager{
		handler: handler, reloader: reloader, log: log,
		readTimeout: 2 * time.Second, idleTimeout: 8 * time.Second,
	}
}

// StartDoT binds a DNS-over-TLS listener on each address (RFC 7858). ActivateAndServe
// serves the raw listener, so we wrap it with tls.NewListener ourselves. A bind failure
// on one address is returned; the caller logs and continues (Do53 is unaffected).
func (m *Manager) StartDoT(addrs []string) error {
	tlsCfg := m.reloader.tlsConfig("dot")
	for _, addr := range addrs {
		raw, err := net.Listen(netmatch.ListenNetwork("tcp", addr), addr)
		if err != nil {
			return fmt.Errorf("dot %s: %w", addr, err)
		}
		ln := tls.NewListener(raw, tlsCfg)
		srv := &dns.Server{
			Listener:    ln,
			Handler:     transportHandler{inner: m.handler, transport: "dot"},
			ReadTimeout: m.readTimeout,
			IdleTimeout: func() time.Duration { return m.idleTimeout },
		}
		m.mu.Lock()
		m.dnsSrvs = append(m.dnsSrvs, srv)
		m.bound = append(m.bound, raw.Addr())
		m.dotBound = append(m.dotBound, raw.Addr())
		m.mu.Unlock()
		go func(s *dns.Server) { _ = s.ActivateAndServe() }(srv)
		m.log(fmt.Sprintf("encrypted: DoT listening on %s", raw.Addr()))
	}
	return nil
}

// StartDoH binds a DNS-over-HTTPS listener on each address (RFC 8484). Each runs its own
// hardened http.Server (separate from the diagnostics server) serving exactly `path`.
func (m *Manager) StartDoH(addrs []string, path string) error {
	if path == "" {
		path = "/dns-query"
	}
	tlsCfg := m.reloader.tlsConfig("h2", "http/1.1")
	for _, addr := range addrs {
		raw, err := net.Listen(netmatch.ListenNetwork("tcp", addr), addr)
		if err != nil {
			return fmt.Errorf("doh %s: %w", addr, err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/", m.dohHandler(path)) // single route; every other path 404s
		hs := &http.Server{
			Handler:           mux,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		ln := tls.NewListener(raw, tlsCfg)
		m.mu.Lock()
		m.httpSrvs = append(m.httpSrvs, hs)
		m.bound = append(m.bound, raw.Addr())
		m.dohBound = append(m.dohBound, raw.Addr())
		m.mu.Unlock()
		go func(s *http.Server, l net.Listener) { _ = s.Serve(l) }(hs, ln)
		m.log(fmt.Sprintf("encrypted: DoH listening on %s%s", raw.Addr(), path))
	}
	return nil
}

// BoundAddrs returns the encrypted listeners' bound addresses (for DDR hints / -check).
func (m *Manager) BoundAddrs() []net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]net.Addr(nil), m.bound...)
}

// DoTAddrs / DoHAddrs return the per-transport bound addresses (for diagnostics).
func (m *Manager) DoTAddrs() []net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]net.Addr(nil), m.dotBound...)
}

func (m *Manager) DoHAddrs() []net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]net.Addr(nil), m.dohBound...)
}

// Shutdown stops all encrypted listeners, bounded by ctx for the HTTP servers.
func (m *Manager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	dnsSrvs := append([]*dns.Server(nil), m.dnsSrvs...)
	httpSrvs := append([]*http.Server(nil), m.httpSrvs...)
	m.mu.Unlock()
	for _, s := range httpSrvs {
		_ = s.Shutdown(ctx)
	}
	for _, s := range dnsSrvs {
		_ = s.Shutdown()
	}
}
