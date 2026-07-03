package encrypted

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert writes a self-signed cert+key (with the given serial + expiry) to certFile/
// keyFile, creating them if absent. Reused to simulate a renewal by rewriting in place.
func writeCert(t *testing.T, certFile, keyFile string, serial int64, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "dns.example.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"dns.example.net"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func certPaths(t *testing.T) (string, string) {
	dir := t.TempDir()
	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
}

// Missing files and an already-expired cert both fail to load (so the daemon fails closed).
func TestCertReloaderRejectsBadCerts(t *testing.T) {
	cf, kf := certPaths(t)
	if _, err := NewCertReloader(cf, kf, nil); err == nil {
		t.Error("missing cert files should fail to load")
	}
	writeCert(t, cf, kf, 1, time.Now().Add(-time.Hour)) // expired
	if _, err := NewCertReloader(cf, kf, nil); err == nil {
		t.Error("expired cert should fail to load")
	}
}

// A renewal rewrites the files; Reload swaps in the new cert atomically.
func TestCertReloaderHotReload(t *testing.T) {
	cf, kf := certPaths(t)
	writeCert(t, cf, kf, 1, time.Now().Add(24*time.Hour))
	r, err := NewCertReloader(cf, kf, nil)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	c1, _ := r.GetCertificate(nil)
	if !r.Valid() {
		t.Fatal("cert should be valid")
	}

	writeCert(t, cf, kf, 2, time.Now().Add(48*time.Hour)) // "renewed"
	if err := r.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	c2, _ := r.GetCertificate(nil)
	if c1.Leaf.SerialNumber.Cmp(c2.Leaf.SerialNumber) == 0 {
		t.Error("GetCertificate still serves the old cert after reload")
	}
}

// A broken renewal is rejected and the last-good cert keeps serving.
func TestCertReloaderKeepsLastGood(t *testing.T) {
	cf, kf := certPaths(t)
	writeCert(t, cf, kf, 1, time.Now().Add(24*time.Hour))
	r, err := NewCertReloader(cf, kf, nil)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := r.GetCertificate(nil)

	os.WriteFile(cf, []byte("not a certificate"), 0o644) //nolint:errcheck
	if err := r.Reload(); err == nil {
		t.Error("reloading a broken cert should error")
	}
	still, _ := r.GetCertificate(nil)
	if still == nil || good.Leaf.SerialNumber.Cmp(still.Leaf.SerialNumber) != 0 {
		t.Error("a broken reload must keep serving the last-good cert")
	}
}

// GetCertificate refuses to serve a cert that has expired since it was loaded (never serve
// expired), and Valid() reports false.
func TestGetCertificateRefusesExpired(t *testing.T) {
	cf, kf := certPaths(t)
	writeCert(t, cf, kf, 1, time.Now().Add(24*time.Hour))
	cert, err := loadValidCert(cf, kf)
	if err != nil {
		t.Fatal(err)
	}
	cert.Leaf.NotAfter = time.Now().Add(-time.Minute) // simulate lapse after load
	r := &CertReloader{}
	r.cur.Store(&cert)
	if _, err := r.GetCertificate(nil); err == nil {
		t.Error("GetCertificate must refuse an expired cert")
	}
	if r.Valid() {
		t.Error("Valid() must be false for an expired cert")
	}
}
