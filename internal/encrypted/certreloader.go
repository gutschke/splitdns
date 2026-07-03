// Package encrypted is the OPT-IN encrypted client front-end: DNS-over-TLS (RFC 7858)
// and DNS-over-HTTPS (RFC 8484) listeners that reuse the daemon's existing query handler
// (so they inherit access control, the concurrency limiter, the answer cache, and the
// DNS-rebinding filter unchanged), plus a hot-reloading certificate for the operator's
// Authentication Domain Name (ADN). It adds no new dependencies (miekg/dns + stdlib).
package encrypted

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// CertReloader holds the current ADN certificate behind an atomic pointer so a TLS
// handshake reads it lock-free, while a background trigger (SIGHUP / mtime, wired by the
// daemon) can atomically swap in a renewed cert. It NEVER swaps in a broken or expired
// cert: on a bad reload it logs and keeps serving the last-good one.
type CertReloader struct {
	certFile, keyFile string
	log               func(string)
	warnedExpiry      atomic.Bool // debounce near-expiry WARN spam
	cur               atomic.Pointer[tls.Certificate]
}

// NewCertReloader loads the initial cert. It returns an error if no valid cert can be
// loaded at all (so the daemon can fail closed to Do53-only without starting listeners).
func NewCertReloader(certFile, keyFile string, log func(string)) (*CertReloader, error) {
	if log == nil {
		log = func(string) {}
	}
	r := &CertReloader{certFile: certFile, keyFile: keyFile, log: log}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload loads+validates the cert files and, only on success, atomically swaps them in.
// On failure it returns the error and keeps the previous cert (if any) in service.
func (r *CertReloader) Reload() error {
	cert, err := loadValidCert(r.certFile, r.keyFile)
	if err != nil {
		if r.cur.Load() != nil {
			r.log(fmt.Sprintf("encrypted: cert reload failed, keeping previous certificate: %v", err))
		}
		return err
	}
	r.cur.Store(&cert)
	r.warnedExpiry.Store(false)
	r.checkExpiry(cert.Leaf.NotAfter)
	return nil
}

// GetCertificate is the tls.Config callback; it hands out the current cert per handshake,
// but REFUSES to serve an expired one — the handshake then fails and the client falls back
// to Do53 rather than trusting a stale cert.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := r.cur.Load()
	if c == nil {
		return nil, errors.New("encrypted: no certificate loaded")
	}
	if c.Leaf != nil && time.Now().After(c.Leaf.NotAfter) {
		return nil, errors.New("encrypted: certificate expired")
	}
	return c, nil
}

// Valid reports whether a currently-unexpired certificate is loaded. DDR advertising is
// gated on this so the SVCB is withdrawn when the cert lapses.
func (r *CertReloader) Valid() bool {
	c := r.cur.Load()
	return c != nil && c.Leaf != nil && time.Now().Before(c.Leaf.NotAfter)
}

// NotAfter reports the current cert's expiry (zero if none).
func (r *CertReloader) NotAfter() time.Time {
	if c := r.cur.Load(); c != nil && c.Leaf != nil {
		return c.Leaf.NotAfter
	}
	return time.Time{}
}

// CertInfo returns the current leaf's expiry and SAN DNS names for diagnostics (ok=false
// if no cert is loaded).
func (r *CertReloader) CertInfo() (notAfter time.Time, dnsNames []string, ok bool) {
	c := r.cur.Load()
	if c == nil || c.Leaf == nil {
		return time.Time{}, nil, false
	}
	return c.Leaf.NotAfter, c.Leaf.DNSNames, true
}

// Run watches the cert file's mtime and reloads on change until ctx is done, invoking
// onReloaded after each reload attempt (so the daemon can re-sync DDR readiness). A cheap
// stat poll avoids an fsnotify dependency.
func (r *CertReloader) Run(ctx context.Context, onReloaded func()) {
	last := mtime(r.certFile)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if m := mtime(r.certFile); !m.Equal(last) {
				last = m
				_ = r.Reload()
				if onReloaded != nil {
					onReloaded()
				}
			}
		}
	}
}

// ReloadNow reloads immediately (e.g. on SIGHUP) and invokes onReloaded.
func (r *CertReloader) ReloadNow(onReloaded func()) {
	_ = r.Reload()
	if onReloaded != nil {
		onReloaded()
	}
}

func mtime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

// tlsConfig returns a hardened TLS config sharing this reloader's live certificate, with
// ALPN restricted to exactly the advertised protocols for that listener.
func (r *CertReloader) tlsConfig(alpn ...string) *tls.Config {
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     tls.VersionTLS12, // TLS 1.3 negotiated when the client offers it
		NextProtos:     alpn,
	}
}

func (r *CertReloader) checkExpiry(notAfter time.Time) {
	switch d := time.Until(notAfter); {
	case d < 0:
		r.log(fmt.Sprintf("encrypted: WARNING certificate EXPIRED on %s", notAfter.Format(time.RFC3339)))
	case d < 14*24*time.Hour:
		r.log(fmt.Sprintf("encrypted: WARNING certificate expires in %s (%s) — check ACME renewal", d.Round(time.Hour), notAfter.Format(time.RFC3339)))
	}
}

// loadValidCert loads a cert+key pair and rejects it if the leaf can't be parsed or is
// already expired (never serve an expired cert).
func loadValidCert(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	if cert.Leaf == nil {
		leaf, perr := x509.ParseCertificate(cert.Certificate[0])
		if perr != nil {
			return tls.Certificate{}, fmt.Errorf("parse leaf: %w", perr)
		}
		cert.Leaf = leaf
	}
	if time.Now().After(cert.Leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("certificate expired on %s", cert.Leaf.NotAfter.Format(time.RFC3339))
	}
	return cert, nil
}
