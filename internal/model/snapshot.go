package model

import (
	"net/netip"
	"time"
)

// Snapshot is the immutable zone/static/vhost view the hot path reads via a
// single atomic.Pointer load (§2.1, §2.3). Build a new one and Store it; never
// mutate a published Snapshot.
type Snapshot struct {
	Zones     map[string]*Zone     // canonical apex FQDN (trailing dot) -> zone
	StubZones map[string]*StubZone // FQDN -> forward target (sub.example.com.)
	ReverseZ  map[string]*RevZone  // configured PTR zones (e.g. 2.0.192.in-addr.arpa.)
	VHosts    map[string]bool      // redirect set from :818 (relative labels)
	Excluded  map[string]bool      // apex FQDNs NOT subject to vhost redirect (config-driven)
	Static    map[string][]RR      // static specials + seeded hosts (forward + PTR)
	// DDNSEligible is the set of DDNS-writable FQDNs (lowercased, trailing dot). These
	// names are "managed" — their address comes from Cloudflare via the AUTHENTICATED
	// write-back path — so the split-horizon mDNS overlay must never let an unauthenticated
	// mDNS announcement shadow their A/AAAA (Q9 / §4.2 trust boundary).
	DDNSEligible map[string]bool
	// LocalDomain is the bare unicast local-domain label (e.g. "lan"); host.<LocalDomain>
	// resolves from the mDNS view like host.local, and is the canonical target for PTRs.
	// Empty => *.local only.
	LocalDomain string
	AllowSuffix []string // authoritative/stub/static suffixes (rebind scope, §4.2)
	BuiltAt     time.Time
	CFHealthy   bool // false => serving stale CF data (degraded)

	// VHostV4/VHostV6 are the reverse proxy redirect targets the R3 vhost/naked/www rule
	// answers with (design §2.4 step 6). Zero value => that family is NODATA.
	VHostV4 netip.Addr
	VHostV6 netip.Addr

	// DDR is the Discovery of Designated Resolvers advertisement (RFC 9462). A nil DDR
	// means "no designated encrypted resolver": the resolver answers resolver.arpa with
	// authoritative NODATA (unchanged pre-feature behavior). It is published by the daemon
	// ONLY after the encrypted (DoT/DoH) listeners bind and the ADN certificate validates,
	// and cleared on cert expiry — so a client is never pointed at a dead endpoint.
	DDR *DDRAdvert
}

// DDRAdvert is what the resolver synthesizes at _dns.resolver.arpa (SVCB) and uses to
// answer the ADN's own A/AAAA (split-horizon). DoT/DoH are non-nil only for a transport
// that is actually ready. Hints and the ADN address answer draw from the SAME slices, so
// the SVCB hints and the ADN A/AAAA can never disagree.
type DDRAdvert struct {
	ADN     string       // Authentication Domain Name (cert SAN), lowercased FQDN, trailing dot
	V4Hints []netip.Addr // resolver's own LAN IPv4 (SVCB ipv4hint + ADN A)
	V6Hints []netip.Addr // resolver's own LAN IPv6 (SVCB ipv6hint + ADN AAAA)
	DoT     *DDREndpoint // non-nil => advertise DoT
	DoH     *DDREndpoint // non-nil => advertise DoH
}

// DDREndpoint is one ready encrypted endpoint. Path is the DoH URI-template base
// (e.g. "/dns-query"); it is empty for DoT.
type DDREndpoint struct {
	Port uint16
	Path string
}

// Zone is a Cloudflare-mirrored authoritative zone.
type Zone struct {
	ID, Apex          string
	NS                []RR
	SOA               RR                         // ALWAYS present (§2.4d)
	Records           map[string]map[uint16][]RR // relative owner -> qtype -> RRset
	Wildcards         map[uint16][]RR            // '*' owner RRsets
	ENT               map[string]bool            // empty-non-terminal owners (RFC 4592)
	TunnelAddr        map[string]map[uint16][]RR // owner -> {A,AAAA} flattened addrs
	LastFetchedSerial uint32
	SyntheticStale    bool // HTTPS/SVCB/tunnel older than ceiling on warm-start
	Stale             bool // loaded from disk, refresh pending
}

// StubZone is a non-CF delegated subtree forwarded to a stub resolver.
type StubZone struct {
	Apex   string
	Target []netip.AddrPort // e.g. 192.0.2.53:53
}

// RevZone is a configured reverse zone with its OWN synthesized SOA, used for
// reverse NODATA in the AUTHORITY section — never borrows a CF zone's SOA (§2.4d).
type RevZone struct {
	Apex string // e.g. "2.0.192.in-addr.arpa."
	SOA  RR     // owner == reverse apex
}

// MDNSService is one DNS-SD service a host advertises, for diagnostics.
type MDNSService struct {
	Type string   `json:"type"`           // e.g. "_ipp._tcp"
	Port uint16   `json:"port,omitempty"` // SRV port (0 if unknown)
	Text []string `json:"text,omitempty"` // curated raw TXT key=values (on-hover detail)
}

// MDNSView is the SEPARATE, independently-published volatile plane for *.local
// hosts (§2.2). Decoupling it means mDNS churn never reallocates the CF zone map.
type MDNSView struct {
	// Forward maps a bare lowercase hostname -> A/AAAA RRs.
	Forward map[string][]RR
	// Reverse maps an in-addr/ip6 arpa name -> PTR RRs.
	Reverse map[string][]RR
	// Services maps a bare hostname -> the DNS-SD services it advertises (type + port), a
	// diagnostic fingerprint only. Never answered on the wire.
	Services map[string][]MDNSService
	// Info maps a bare hostname -> a friendly descriptor derived from DNS-SD TXT records
	// (device model / friendly name), diagnostics only.
	Info    map[string]string
	BuiltAt time.Time
}
