package mdns

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// SigVerifier authenticates DDNS-trigger announcements by their TSIG signature
// (RFC 8945). It holds the shared secrets keyed by canonical key name; a packet is
// trusted only if it carries a TSIG record whose key is known and whose MAC (and
// signed-time/fudge window) verifies. Because the trust is cryptographic, a signed
// announcement is honored regardless of its source IP — unlike the trusted_sources
// path, it cannot be spoofed. A nil *SigVerifier verifies nothing (no keys
// configured), so callers can use it unconditionally.
type SigVerifier struct {
	secrets map[string]string // canonical key name (lowercase, trailing dot) -> base64 secret
	mu      sync.Mutex
	seen    map[string]time.Time // accepted TSIG MAC -> first-seen; anti-replay within the window
	now     func() time.Time     // injectable clock (tests)
}

// tsigSeenCap bounds the anti-replay set. It only ever holds legitimate, unspoofable MACs
// (an attacker without the secret cannot mint new ones), so it grows only with genuine
// announcement traffic and is pruned by the retention window; the cap is a safety ceiling.
const tsigSeenCap = 1024

// NewSigVerifier builds a verifier from a canonical-name -> base64-secret map (as
// produced by config.DDNSConfig.TSIGKeyset). An empty map yields nil so the common
// "no keys configured" case is a cheap nil check on the hot receive path.
func NewSigVerifier(secrets map[string]string) *SigVerifier {
	if len(secrets) == 0 {
		return nil
	}
	cp := make(map[string]string, len(secrets))
	for k, v := range secrets {
		cp[canonKeyName(k)] = v
	}
	return &SigVerifier{secrets: cp, seen: map[string]time.Time{}, now: time.Now}
}

// Verify reports whether b is a TSIG-signed announcement with a valid MAC for one of
// the configured keys. It is conservative: any parse failure, missing/!TSIG trailing
// record, unknown key, or MAC/time mismatch returns false (untrusted, not an error) so
// the packet falls through to the source-IP path or stays view-only.
func (v *SigVerifier) Verify(b []byte) bool {
	if v == nil {
		return false
	}
	var m dns.Msg
	if err := m.Unpack(b); err != nil {
		return false
	}
	if len(m.Extra) == 0 {
		return false
	}
	// A TSIG is always the LAST record in the additional section (RFC 8945 §5.1).
	t, ok := m.Extra[len(m.Extra)-1].(*dns.TSIG)
	if !ok {
		return false
	}
	secret, ok := v.secrets[canonKeyName(t.Hdr.Name)]
	if !ok {
		return false
	}
	// requestMAC="" (an unsolicited announcement, not a query response); timersOnly=false.
	// TsigVerify enforces the signed-time/fudge window, bounding how old a replay can be.
	if dns.TsigVerify(b, secret, "", false) != nil {
		return false
	}
	// Anti-replay: within the fudge window an on-path attacker can re-send a captured
	// valid packet to re-assert a (possibly stale) address set for an eligible host. Each
	// signature's MAC is unique and unspoofable (no secret => no new MAC), so reject any
	// MAC already accepted inside the retention window.
	return v.freshMAC(t.MAC, time.Duration(t.Fudge)*time.Second)
}

// freshMAC returns true the FIRST time a given TSIG MAC is seen and false for any repeat
// within the retention window (a replay). Retention is derived from the packet's own fudge
// (covering the +/- skew TsigVerify allows), clamped to a sane floor/ceiling.
func (v *SigVerifier) freshMAC(mac string, fudge time.Duration) bool {
	if mac == "" {
		return false
	}
	retain := 2 * fudge
	if retain < 30*time.Second {
		retain = 30 * time.Second
	}
	if retain > 10*time.Minute {
		retain = 10 * time.Minute
	}
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, ts := range v.seen { // prune expired (cheap: only genuine MACs ever land here)
		if now.Sub(ts) > retain {
			delete(v.seen, k)
		}
	}
	if _, dup := v.seen[mac]; dup {
		return false // replay of an already-accepted signature
	}
	if len(v.seen) < tsigSeenCap {
		v.seen[mac] = now
	}
	return true
}

// canonKeyName matches config.CanonicalTSIGName without importing config (which would
// pull the whole server schema into this package): lowercase, single trailing dot.
func canonKeyName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")) + "."
}
