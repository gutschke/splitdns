package encrypted

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/miekg/dns"
)

// maxDNSMessage caps an inbound DoH message (a DNS message is at most 65535 bytes).
const maxDNSMessage = 65535

// dohWriter bridges an HTTP DoH request to the shared dns.Handler. Its RemoteAddr returns
// the real client as a *net.TCPAddr, which is load-bearing: it makes the handler's isTCP
// check true (so a large SVCB answer is never UDP-truncated) AND feeds the same access
// policy (Access.Allowed) and query log that Do53/DoT use. WriteMsg captures the reply.
type dohWriter struct {
	remote net.Addr // *net.TCPAddr — the TLS peer
	local  net.Addr
	msg    *dns.Msg
}

func (w *dohWriter) LocalAddr() net.Addr       { return w.local }
func (w *dohWriter) RemoteAddr() net.Addr      { return w.remote }
func (w *dohWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *dohWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	w.msg = m
	return len(b), nil
}
func (w *dohWriter) Close() error        { return nil }
func (w *dohWriter) TsigStatus() error   { return nil }
func (w *dohWriter) TsigTimersOnly(bool) {}
func (w *dohWriter) Hijack()             {}
func (w *dohWriter) Transport() string   { return "doh" } // the shared handler tags the query log

// transportHandler decorates the ResponseWriter with a Transport() label so the shared
// query handler records which encrypted transport a request arrived on. Used for DoT
// (DoH tags itself via dohWriter).
type transportHandler struct {
	inner     dns.Handler
	transport string
}

func (h transportHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	h.inner.ServeDNS(taggedWriter{ResponseWriter: w, transport: h.transport}, r)
}

type taggedWriter struct {
	dns.ResponseWriter
	transport string
}

func (t taggedWriter) Transport() string { return t.transport }

// dohHandler serves RFC 8484 DNS-over-HTTPS on exactly one path, translating HTTP to a
// *dns.Msg and back through the shared handler. It duplicates NO resolver logic.
func (m *Manager) dohHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		wire, code, msg := readDoHQuery(w, r)
		if code != 0 {
			http.Error(w, msg, code)
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(wire); err != nil {
			http.Error(w, "bad dns message", http.StatusBadRequest)
			return
		}
		bw := &dohWriter{remote: tcpAddr(r.RemoteAddr), local: nil}
		m.handler.ServeDNS(bw, req)
		if bw.msg == nil {
			http.Error(w, "no answer", http.StatusInternalServerError)
			return
		}
		out, err := bw.msg.Pack()
		if err != nil {
			http.Error(w, "pack failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		// Align HTTP freshness with the DNS answer's min TTL (RFC 8484 §5.1); GET only,
		// no caching of failures.
		if r.Method == http.MethodGet {
			if bw.msg.Rcode == dns.RcodeSuccess {
				w.Header().Set("Cache-Control", cacheControl(bw.msg))
			} else {
				w.Header().Set("Cache-Control", "no-store")
			}
		}
		_, _ = w.Write(out)
	}
}

// readDoHQuery extracts the wire-format query from a GET (?dns=base64url) or POST
// (application/dns-message) request, enforcing method/content-type/size limits. On
// rejection it returns (nil, status, message); on success (wire, 0, "").
func readDoHQuery(w http.ResponseWriter, r *http.Request) ([]byte, int, string) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			return nil, http.StatusBadRequest, "missing dns parameter"
		}
		wire, err := base64.RawURLEncoding.DecodeString(q)
		if err != nil {
			return nil, http.StatusBadRequest, "dns parameter is not base64url"
		}
		if len(wire) > maxDNSMessage {
			return nil, http.StatusRequestEntityTooLarge, "message too large"
		}
		return wire, 0, ""
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			return nil, http.StatusUnsupportedMediaType, "content-type must be application/dns-message"
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDNSMessage))
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return nil, http.StatusRequestEntityTooLarge, "message too large"
			}
			return nil, http.StatusBadRequest, "cannot read body"
		}
		return body, 0, ""
	default:
		w.Header().Set("Allow", "GET, POST")
		return nil, http.StatusMethodNotAllowed, "method not allowed"
	}
}

// cacheControl derives "max-age=<min TTL>" across the answer RRs (RFC 8484 §5.1).
func cacheControl(m *dns.Msg) string {
	min := uint32(0)
	first := true
	for _, rr := range m.Answer {
		if t := rr.Header().Ttl; first || t < min {
			min, first = t, false
		}
	}
	if first { // no answer records
		min = 0
	}
	return "max-age=" + strconv.FormatUint(uint64(min), 10)
}

func tcpAddr(remote string) net.Addr {
	if a, err := net.ResolveTCPAddr("tcp", remote); err == nil {
		return a
	}
	return &net.TCPAddr{} // best-effort; access control treats an invalid IP as not-allowed
}
