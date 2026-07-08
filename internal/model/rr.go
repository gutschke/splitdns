// Package model holds the canonical, immutable data types that the hot data
// plane reads. Every value here is built by the cold control plane and published
// via atomic.Pointer; nothing in this package performs I/O.
//
// Design references: §2.3 data model, §2.5 sourcing, implementation steps S05/S06.
package model

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// RR is the canonical resource-record model. It round-trips through
// dns.RR.String() and carries type-specific fields explicitly so the
// versioned-JSON warm cache (S19) survives without depending on miekg internals.
//
// Hot path reads ONLY: Name, Type, TTL, Content, Priority, Weight, Port, Target.
// ZoneID/RecordID/Proxied/Synthetic are control-plane (DDNS, flattening) metadata
// and MUST NOT be consulted while answering a query (§2.3).
type RR struct {
	Name  string `json:"name"`  // canonical FQDN, trailing dot
	Type  uint16 `json:"type"`  // dns.TypeA, dns.TypeAAAA, ...
	TTL   uint32 `json:"ttl"`   // seconds
	Class uint16 `json:"class"` // dns.ClassINET

	// Content is the canonical presentation-form RDATA. For MX/SRV it is the
	// RECOMBINED wire form (preference/priority folded back in) — see RDATA().
	Content  string `json:"content"`
	Priority uint16 `json:"priority,omitempty"` // MX preference / SRV priority
	Weight   uint16 `json:"weight,omitempty"`   // SRV
	Port     uint16 `json:"port,omitempty"`     // SRV
	Target   string `json:"target,omitempty"`   // MX/SRV/CNAME target (FQDN, trailing dot)

	// Control-plane-only metadata. Never read on the hot path.
	ZoneID    string `json:"zone_id,omitempty"`
	RecordID  string `json:"record_id,omitempty"`
	Proxied   bool   `json:"proxied,omitempty"`
	Synthetic bool   `json:"synthetic,omitempty"` // HTTPS/SVCB/tunnel via sidecar (§2.5)

	// Trusted marks an mDNS-view address that arrived via the TRUSTED notification channel
	// (TSIG signature / unix peer-cred), as opposed to a self-announced multicast address.
	// This one flag IS read on the hot path — by the local-plane resolver — to serve
	// restricted (vhost/DDNS) names from the trusted tier only, and to prefer trusted
	// addresses. View-only: never populated for CF-zone records and never serialized.
	Trusted bool `json:"-"`
}

// RDATA returns the canonical wire-form RDATA presentation for the record. For
// MX and SRV it recombines the CF-separated Priority field with Content
// (blocking issue #11, §2.3): SRV => "priority weight port target",
// MX => "preference exchange".
func (r RR) RDATA() string {
	switch r.Type {
	case dns.TypeMX:
		return fmt.Sprintf("%d %s", r.Priority, ensureDot(r.Target))
	case dns.TypeSRV:
		return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, ensureDot(r.Target))
	default:
		return r.Content
	}
}

// ToMiekg renders the record as a concrete dns.RR by parsing the canonical
// presentation form "<name> <ttl> <class> <type> <rdata>". Returning an error
// (rather than panicking) keeps a single malformed record from crashing answer
// assembly; callers log-and-skip.
func (r RR) ToMiekg() (dns.RR, error) {
	line := fmt.Sprintf("%s %d %s %s %s",
		ensureDot(r.Name), r.TTL, dns.ClassToString[classOrINET(r.Class)],
		dns.TypeToString[r.Type], r.RDATA())
	rr, err := dns.NewRR(line)
	if err != nil {
		return nil, fmt.Errorf("model: cannot build RR from %q: %w", line, err)
	}
	if rr == nil {
		// dns.NewRR returns (nil, nil) for a line that parses to no record (empty
		// owner, comment-only, etc.). Treat that as an error so callers that only
		// nil-check on err never append a nil RR and panic at pack time (fuzz: a nil
		// answer RR crashes the server on serialize).
		return nil, fmt.Errorf("model: RR line %q produced no record", line)
	}
	return rr, nil
}

// CoercePriority defensively converts a Cloudflare priority (delivered as a
// float, e.g. 10.0) to uint16 (§2.3). A non-integer, negative, NaN, or
// out-of-range value is rejected with ok=false so the builder logs-and-skips the
// record instead of silently truncating or panicking.
func CoercePriority(f float64) (uint16, bool) {
	if f != f { // NaN
		return 0, false
	}
	if f < 0 || f > 65535 {
		return 0, false
	}
	if f != float64(uint16(f)) { // non-integer
		return 0, false
	}
	return uint16(f), true
}

// ParseSRVContent splits a Cloudflare SRV content field "weight port target"
// (priority lives in the separate Priority field) into its parts.
func ParseSRVContent(content string) (weight, port uint16, target string, err error) {
	fields := strings.Fields(content)
	if len(fields) != 3 {
		return 0, 0, "", fmt.Errorf("model: SRV content %q is not 'weight port target'", content)
	}
	w, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return 0, 0, "", fmt.Errorf("model: SRV weight %q: %w", fields[0], err)
	}
	p, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil {
		return 0, 0, "", fmt.Errorf("model: SRV port %q: %w", fields[1], err)
	}
	return uint16(w), uint16(p), ensureDot(fields[2]), nil
}

func ensureDot(s string) string {
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

func classOrINET(c uint16) uint16 {
	if c == 0 {
		return dns.ClassINET
	}
	return c
}
