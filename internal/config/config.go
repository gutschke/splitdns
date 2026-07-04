// Package config loads splitdnsd's configuration from a TOML file layered over
// safe defaults. Every policy knob is configurable (the operator's standing
// guidance); see splitdns.conf(5) for the documented schema.
package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"

	"github.com/gutschke/splitdns/internal/netmatch"
	"github.com/gutschke/splitdns/internal/revzone"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	Listen     ListenConfig    `toml:"listen"`
	Access     AccessConfig    `toml:"access"`
	Upstream   UpstreamConfig  `toml:"upstream"`
	Zones      ZonesConfig     `toml:"zones"`
	MDNS       MDNSConfig      `toml:"mdns"`
	VHost      VHostConfig     `toml:"vhost"`
	Cloudflare CFConfig        `toml:"cloudflare"`
	DDNS       DDNSConfig      `toml:"ddns"`
	Notify     NotifyConfig    `toml:"notify"`
	Diag       DiagConfig      `toml:"diag"`
	Cache      CacheConfig     `toml:"cache"`
	Encrypted  EncryptedConfig `toml:"encrypted"`
}

// ListenConfig controls which local addresses :53 binds. Mode "private-auto"
// (default) binds only local-scope addresses, never global ones (Q7).
type ListenConfig struct {
	Mode      string   `toml:"mode"`      // "private-auto" | "explicit"
	Addresses []string `toml:"addresses"` // host:port list when mode="explicit"
	Port      int      `toml:"port"`
	UDP       bool     `toml:"udp"`
	TCP       bool     `toml:"tcp"`
}

// AccessConfig is the query-access allow/deny policy. Refuse beats Allow.
type AccessConfig struct {
	Allow  []string `toml:"allow"`
	Refuse []string `toml:"refuse"`
}

// UpstreamConfig configures forwarding of non-local queries (Q6).
type UpstreamConfig struct {
	Servers           []string `toml:"servers"`            // host:853 DoT targets
	CleartextFallback bool     `toml:"cleartext_fallback"` // audited; default off
	Breaker           bool     `toml:"breaker"`            // per-upstream circuit breaker; default on
}

// ZonesConfig is the authoritative inventory (Q1/Q2).
//
// Reverse-zone policy (Q2): the server is authoritative only for our locally
// managed address spaces and forwards every other PTR. The zone set is the union
// of two sources:
//   - Reverse: explicit, stable zone apexes (recommended for spaces whose size you
//     know — e.g. a /16 carved into subnets, or a fully-managed ULA /48).
//   - ReverseDetect: a scope ("off" default | "private" | "global" | "all") that
//     is auto-detected from local interfaces AND re-detected on network change
//     (see revzone.Watcher). Use "global" to track a DYNAMIC ISP-assigned GUA
//     prefix. Detected zones contained within an explicit zone are dropped so a
//     more-specific detected zone never shadows a stable one.
type ZonesConfig struct {
	Local         []string            `toml:"local"`          // TODO(Q1): CF-hosted zones
	Reverse       []string            `toml:"reverse"`        // explicit, stable reverse-zone apexes
	ReverseDetect string              `toml:"reverse_detect"` // off|private|global|all
	Stub          map[string][]string `toml:"stub"`           // apex -> stub resolver host:port
}

// MDNSConfig controls the LAN plane: the unicast local domain served from the mDNS view
// (alongside the always-on *.local), and how long the passive cache keeps serving a record
// after its announced TTL (serve-stale). local_domain lets clients that only understand a
// single search domain reach LAN hosts under a real name (e.g. host.lan). Empty
// local_domain serves *.local only.
type MDNSConfig struct {
	LocalDomain  string `toml:"local_domain"`  // unicast local domain, default "lan"; "" = *.local only
	StaleGrace   string `toml:"stale_grace"`   // serve past the announced TTL, default "10m"; "0" disables
	GoodbyeGrace string `toml:"goodbye_grace"` // retain after an mDNS goodbye (avahi bounce cushion), default "30s"
	// ServiceDiscovery enables active DNS-SD querying (default on): splitdnsd periodically
	// multicasts the standard Bonjour service-discovery query so quiet devices (printers,
	// casts, home speakers) and their services surface reliably instead of aging out. Set
	// false to stay a pure passive listener (e.g. to add zero query traffic on a segment
	// with a fussy mDNS reflector).
	ServiceDiscovery bool `toml:"service_discovery"`
}

// LocalDomainLabel returns the normalized bare local-domain label (lowercased, no dots),
// or "" when disabled.
func (m MDNSConfig) LocalDomainLabel() string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(m.LocalDomain)), ".")
}

// StaleGraceDuration resolves stale_grace (default 10m; unparsable => default).
func (m MDNSConfig) StaleGraceDuration() time.Duration {
	return parseDurOr(m.StaleGrace, 10*time.Minute)
}

// GoodbyeGraceDuration resolves goodbye_grace (default 30s; unparsable => default).
func (m MDNSConfig) GoodbyeGraceDuration() time.Duration {
	return parseDurOr(m.GoodbyeGrace, 30*time.Second)
}

func parseDurOr(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return def
}

// VHostConfig configures the reverse-proxy redirect (R3). The reverse proxy can be
// any product (nginx, Caddy, Traefik, …); only its address and an optional vhost-list
// feed are needed. With no ProxyV4/ProxyV6 set, the redirect is disabled and names
// are served authoritatively.
type VHostConfig struct {
	Feed    string `toml:"feed"`     // reverse-proxy vhost-list endpoint, e.g. 192.0.2.10:818
	ProxyV4 string `toml:"proxy_v4"` // reverse-proxy IPv4 redirect target, e.g. 192.0.2.10
	ProxyV6 string `toml:"proxy_v6"` // reverse-proxy IPv6 redirect target (optional)
	// ExcludeZones are apexes NOT subject to the naked/www/vhost redirect (they serve
	// their real records/tunnel addresses instead). Site-specific, so configured here
	// rather than hardcoded — keeps private zone names out of the source.
	ExcludeZones []string `toml:"exclude_zones"`
}

// CFConfig holds the two scoped Cloudflare tokens (Q8). EditTokenFile empty =>
// DDNS disabled. BaseURL is injectable for the mock CF API in tests.
type CFConfig struct {
	ReadTokenFile string `toml:"read_token_file"`
	EditTokenFile string `toml:"edit_token_file"`
	BaseURL       string `toml:"base_url"`
	// TunnelSuffixes are CNAME-target suffixes that mark a flatten-able tunnel/proxy
	// CNAME (the record is replaced by the owner's presented A/AAAA). Default is
	// Cloudflare Tunnel only; add others (e.g. a game/DDoS proxy) in config.
	TunnelSuffixes []string `toml:"tunnel_suffixes"`
}

// ResolvedTunnelSuffixes returns the configured tunnel CNAME suffixes normalized to
// label-aligned FQDN form (leading + trailing dot), defaulting to Cloudflare Tunnel.
func (c CFConfig) ResolvedTunnelSuffixes() []string {
	src := c.TunnelSuffixes
	if len(src) == 0 {
		src = []string{"cfargotunnel.com"}
	}
	out := make([]string, 0, len(src))
	for _, s := range src {
		s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
		if s != "" {
			out = append(out, "."+s+".")
		}
	}
	return out
}

// DDNSConfig configures the guarded write-back (R9/Q9). Default off + dry-run.
// Rate is a Go duration string (e.g. "10m"); use RateDuration to resolve it.
//
// Authorization model (D7, defense-in-depth): write-back is push-driven. Three trigger
// paths exist and ALL are authenticated:
//   - the authenticated local channel — splitdns-notify(8) over NotifySocket, with
//     an SO_PEERCRED check (peer uid must be root, the daemon's own uid, or a
//     configured NotifyUIDs entry). This is the primary, always-trusted path.
//   - a TSIG-signed announcement (RFC 8945) carrying a valid MAC for one of TSIGKeys.
//     This is authenticated cryptographically, so it is honored regardless of source
//     address — the recommended path for off-box notifiers (it cannot be spoofed).
//   - an unsigned mDNS announcement whose SOURCE address falls in TrustedSources —
//     a weaker, source-IP-based trust (spoofable) kept for convenience on a trusted
//     LAN. Set RequireSignature to disable this path so ONLY signed (or socket)
//     announcements may trigger write-back. Announcements from any other source still
//     update the *.local view but are inert for DDNS.
//
// Eligible remains an allowlist of writable host FQDNs; empty = deny-all on the live
// path (forced dry-run, see internal/ddns — D8). Default off + dry-run.
type DDNSConfig struct {
	Enabled          bool      `toml:"enabled"`
	DryRun           bool      `toml:"dry_run"`
	Rate             string    `toml:"rate"`
	Eligible         []string  `toml:"eligible"`           // allowlist of writable FQDNs; empty = deny-all (D8)
	TrustedSources   []string  `toml:"trusted_sources"`    // CIDRs whose UNSIGNED announcements may trigger DDNS (D7); empty = socket/signed-only
	RequireSignature bool      `toml:"require_signature"`  // if true, only TSIG-signed (or socket) announcements may trigger DDNS
	TSIGKeys         []TSIGKey `toml:"tsig_keys"`          // shared HMAC keys authenticating signed announcements (RFC 8945)
	NotifySocket     string    `toml:"notify_socket"`      // authenticated unix-socket path; empty disables it (D7)
	NotifyUIDs       []int     `toml:"notify_uids"`        // extra peer uids allowed on the socket (root + daemon uid always allowed)
	NotifyGroups     []string  `toml:"notify_groups"`      // groups whose members may trigger via the socket (POSIX-ACL granted; no key needed)
	NotifySocketMode string    `toml:"notify_socket_mode"` // octal socket permission (default "0660")
}

// TSIGKey is a shared HMAC key authenticating DDNS-trigger announcements (RFC 8945).
// Secret is the base64-encoded key (the standard TSIG encoding); SecretFile reads the
// base64 secret from a file instead (preferred on the resolver — keeps the key out of a
// world-readable config; mode it 0400 splitdns:splitdns). Algorithm defaults to
// hmac-sha256; on the resolver it is advisory (verification reads the algorithm from the
// signed message) and is the algorithm splitdns-notify(8) signs with.
type TSIGKey struct {
	Name       string `toml:"name"`
	Secret     string `toml:"secret"`
	SecretFile string `toml:"secret_file"`
	Algorithm  string `toml:"algorithm"`
}

// TrustedSourceSet parses TrustedSources into a matcher. Empty yields a set that
// matches nothing (socket/signed-only DDNS triggering).
func (d DDNSConfig) TrustedSourceSet() (*netmatch.Set, error) {
	return netmatch.ParseSet(d.TrustedSources)
}

// TSIGKeyset resolves TSIGKeys into a canonical-name -> base64-secret map for TSIG
// verification, reading any SecretFile entries. The result is nil when no keys are
// configured (signature-based triggering simply unavailable). A key missing a name or
// secret is an error so a misconfiguration fails loudly at startup.
func (d DDNSConfig) TSIGKeyset() (map[string]string, error) {
	if len(d.TSIGKeys) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(d.TSIGKeys))
	for i, k := range d.TSIGKeys {
		name := CanonicalTSIGName(k.Name)
		if name == "." {
			return nil, fmt.Errorf("ddns.tsig_keys[%d]: missing name", i)
		}
		secret := strings.TrimSpace(k.Secret)
		if secret == "" && k.SecretFile != "" {
			b, err := os.ReadFile(k.SecretFile)
			if err != nil {
				return nil, fmt.Errorf("ddns.tsig_keys[%d] (%s): %w", i, k.Name, err)
			}
			secret = strings.TrimSpace(string(b))
		}
		if secret == "" {
			return nil, fmt.Errorf("ddns.tsig_keys[%d] (%s): empty secret", i, k.Name)
		}
		out[name] = secret
	}
	return out, nil
}

// CanonicalTSIGName lowercases a TSIG key name and ensures a single trailing dot so the
// notifier and resolver agree on the lookup key regardless of how it was written.
func CanonicalTSIGName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")) + "."
}

// ResolveNotifyGroups maps configured ddns.notify_groups names to a gid -> name set,
// collecting any names that do not resolve (so the caller can warn and carry on rather
// than fail — an unknown group must never take DNS down). Resolution uses the local
// group database (pure-Go with CGO disabled), so it sees local groups but not
// LDAP/SSS-backed ones.
func ResolveNotifyGroups(names []string) (gids map[uint32]string, unknown []string) {
	gids = map[uint32]string{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		g, err := user.LookupGroup(name)
		if err != nil {
			unknown = append(unknown, name)
			continue
		}
		id, err := strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			unknown = append(unknown, name)
			continue
		}
		gids[uint32(id)] = name
	}
	return gids, unknown
}

// NotifyConfig holds defaults for the splitdns-notify(8) helper. Servers are the
// resolver unicast targets (host or host:port; default port 5353) an announcement is
// sent to when the caller passes no -server flag (empty => multicast only). The TSIG
// fields, when set, make the helper cryptographically SIGN its announcements so the
// resolver can authenticate them regardless of source IP; TSIGSecretFile reads the
// base64 secret from a file instead of inlining it.
type NotifyConfig struct {
	Servers        []string `toml:"servers"`
	Socket         string   `toml:"socket"` // resolver unix-socket path the helper connects to (default /run/splitdns/notify.sock); -socket overrides
	TSIGKeyName    string   `toml:"tsig_key"`
	TSIGSecret     string   `toml:"tsig_secret"`
	TSIGSecretFile string   `toml:"tsig_secret_file"`
	TSIGAlgorithm  string   `toml:"tsig_algorithm"`
}

// RateDuration parses the configured min-interval-per-host.
func (d DDNSConfig) RateDuration() (time.Duration, error) {
	if d.Rate == "" {
		return 0, nil
	}
	return time.ParseDuration(d.Rate)
}

// DiagConfig is the diagnostics HTTP endpoint (R10), localhost-only by default. The
// read-only views are always available; the DANGEROUS control actions (flush cache,
// force-refresh, restart, …) are OFF unless allow_control is set, and are then honored
// only with a matching control_password OR a loopback bind (never unauthenticated on a
// non-loopback address).
type DiagConfig struct {
	// Addr is a host:port (family-pinned like [listen]) OR a Unix socket: a path
	// beginning with "/" or "@", or a "unix:/path" form. A Unix socket is local-only and
	// filesystem-permission-controlled (mode 0660), and counts as loopback for controls.
	Addr string `toml:"addr"`
	// Allow optionally restricts which source IPs (CIDRs) may reach the endpoint. Empty
	// allows all (the default). Unix-socket clients are always allowed (local).
	Allow []string `toml:"allow"`
	// SocketMode is the octal permission for a Unix-socket bind (e.g. "0660", "0666").
	// Empty uses 0660. Loosen it (e.g. "0666") when a reverse proxy in another container
	// must reach the socket across a uid boundary.
	SocketMode string `toml:"socket_mode"`
	// AllowControl is the master switch for the mutating control actions. Default false.
	AllowControl bool `toml:"allow_control"`
	// ControlPassword (or ControlPasswordFile, which wins) gates the control actions.
	// Empty means "no password" — controls are then honored ONLY on a loopback bind.
	ControlPassword     string `toml:"control_password"`
	ControlPasswordFile string `toml:"control_password_file"`
}

// EncryptedConfig is the OPT-IN encrypted client front-end (DoT/DoH) plus its DDR
// advertising (RFC 9462). Disabled by default. When enabled it terminates DNS-over-TLS
// and/or DNS-over-HTTPS for LAN clients using an operator-provided certificate for the
// Authentication Domain Name (ADN); a failure to load the cert degrades to Do53-only
// (fail-closed) rather than taking the daemon down.
type EncryptedConfig struct {
	Enabled  bool   `toml:"enabled"`
	CertFile string `toml:"cert_file"` // PEM cert chain for the ADN
	KeyFile  string `toml:"key_file"`  // PEM private key, mode 0400 splitdns:splitdns
	ADN      string `toml:"adn"`       // Authentication Domain Name (a cert SAN)
	// Mode/Addresses mirror [listen]: "" inherits [listen].mode; "explicit" needs addresses.
	Mode      string   `toml:"mode"`
	Addresses []string `toml:"addresses"`
	// AdvertiseDDR emits the SVCB designation at _dns.resolver.arpa (default follows Enabled
	// via Default()). Turn off to run the encrypted listeners without DDR discovery.
	AdvertiseDDR bool `toml:"advertise_ddr"`
	// IPv4Hint/IPv6Hint override the DDR address hints (and the ADN A/AAAA). Empty uses the
	// encrypted listeners' own bound local-scope addresses.
	IPv4Hint []string `toml:"ipv4_hint"`
	IPv6Hint []string `toml:"ipv6_hint"`

	DoT DoTConfig `toml:"dot"`
	DoH DoHConfig `toml:"doh"`
}

// DoTConfig is the DNS-over-TLS listener (RFC 7858), default port 853.
type DoTConfig struct {
	Enabled bool `toml:"enabled"`
	Port    int  `toml:"port"`
}

// DoHConfig is the DNS-over-HTTPS listener (RFC 8484), default port 443, path /dns-query.
type DoHConfig struct {
	Enabled bool   `toml:"enabled"`
	Port    int    `toml:"port"`
	Path    string `toml:"path"`
}

// ADNFqdn returns the ADN as a lowercased FQDN with trailing dot (as the resolver stores
// and compares it), or "" if unset.
func (e EncryptedConfig) ADNFqdn() string {
	if e.ADN == "" {
		return ""
	}
	return dns.Fqdn(strings.ToLower(e.ADN))
}

// LoadCert loads and validates the ADN cert+key pair (parse + not expired).
func (e EncryptedConfig) LoadCert() (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(e.CertFile, e.KeyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return tls.Certificate{}, fmt.Errorf("parse leaf: %w", err)
		}
		cert.Leaf = leaf
	}
	if time.Now().After(leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}
	return cert, nil
}

// CacheConfig holds the warm-start cache location plus the forward-path answer cache
// tunables. TTL flooring/capping uses the DNS-best-practice defaults (RFC 2308/8767/
// 9520) baked into the anscache package; only the high-level knobs are exposed here.
type CacheConfig struct {
	Dir        string `toml:"dir"`
	Answers    bool   `toml:"answers"`     // enable the forward-path answer cache (default true)
	MaxEntries int    `toml:"max_entries"` // answer-cache LRU capacity (default 10000)
	ServeStale bool   `toml:"serve_stale"` // serve expired data on upstream failure, RFC 8767 (default true)
}

// Default returns the fail-safe defaults. Per Q7 the default access policy
// allows any private/local client, and listen mode binds only local-scope
// addresses. Inventory/credential fields are empty until populated from config.
func Default() Config {
	return Config{
		Listen: ListenConfig{Mode: "private-auto", Port: 53, UDP: true, TCP: true},
		Access: AccessConfig{Allow: append([]string(nil), netmatch.DefaultPrivateClients...)},
		Upstream: UpstreamConfig{
			// Public DNSSEC-validating resolvers, queried over DoT. An audited one-shot
			// cleartext fallback is available but OFF by default (secure-by-default; opt
			// in with cleartext_fallback=true). Override in config.
			Servers:           []string{"1.1.1.1", "8.8.8.8"},
			CleartextFallback: false,
			Breaker:           true,
		},
		// VHost/topology defaults are intentionally EMPTY so the source stays pristine
		// (no site IPs). The live config supplies real values.
		VHost: VHostConfig{},
		// LAN plane: serve host.lan (a single-search-domain-friendly local name) alongside
		// *.local, and keep records ~10m past their announced TTL (serve-stale) with a short
		// cushion after an mDNS goodbye so an avahi bounce doesn't blink hosts out.
		MDNS:       MDNSConfig{LocalDomain: "lan", StaleGrace: "10m", GoodbyeGrace: "30s", ServiceDiscovery: true},
		Cloudflare: CFConfig{ReadTokenFile: "/etc/splitdns/cloudflare-read.token"},
		DDNS:       DDNSConfig{Enabled: false, DryRun: true, Rate: "10m", NotifySocket: "/run/splitdns/notify.sock"},
		Diag:       DiagConfig{Addr: "127.0.0.1:8080"},
		Cache:      CacheConfig{Dir: "/var/lib/splitdns", Answers: true, MaxEntries: 10000, ServeStale: true},
		// Encrypted client front-end OFF by default; if enabled, both transports come up on
		// their standard ports and DDR is advertised.
		Encrypted: EncryptedConfig{
			Enabled:      false,
			AdvertiseDDR: true,
			DoT:          DoTConfig{Enabled: true, Port: 853},
			DoH:          DoHConfig{Enabled: true, Port: 443, Path: "/dns-query"},
		},
	}
}

// Load reads the TOML file at path and layers it over Default(). A missing file
// is not an error (defaults apply); a malformed file is. Strict decoding rejects
// unknown keys so typos fail loudly rather than silently doing nothing.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("config: read %q: %w", path, err)
	}
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config: parse %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("config: %q: %w", path, err)
	}
	return cfg, nil
}

// LoadNotify reads just the [notify] table for the splitdns-notify(8) helper, which
// runs on hosts that have no full splitdnsd config (and should not need one). It
// decodes leniently — unknown tables are ignored — so the same call works against a
// dedicated notify.toml (only [notify]) or a server's splitdnsd.toml. A missing file
// yields a zero NotifyConfig and no error (the helper then falls back to flags and its
// socket→multicast defaults). Any tsig_secret_file is read and folded into TSIGSecret.
func LoadNotify(path string) (NotifyConfig, error) {
	var doc struct {
		Notify NotifyConfig `toml:"notify"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NotifyConfig{}, nil
		}
		return NotifyConfig{}, fmt.Errorf("notify-config: read %q: %w", path, err)
	}
	// Lenient (no DisallowUnknownFields): a full splitdnsd.toml has many other tables.
	if err := toml.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
		return NotifyConfig{}, fmt.Errorf("notify-config: parse %q: %w", path, err)
	}
	n := doc.Notify
	n.TSIGSecret = strings.TrimSpace(n.TSIGSecret)
	if n.TSIGSecret == "" && n.TSIGSecretFile != "" {
		b, err := os.ReadFile(n.TSIGSecretFile)
		if err != nil {
			return n, fmt.Errorf("notify-config: tsig_secret_file: %w", err)
		}
		n.TSIGSecret = strings.TrimSpace(string(b))
	}
	return n, nil
}

// Validate checks structural invariants and that CIDR lists parse.
func (c Config) Validate() error {
	if c.Listen.Port <= 0 || c.Listen.Port > 65535 {
		return fmt.Errorf("listen.port %d out of range", c.Listen.Port)
	}
	if !c.Listen.UDP && !c.Listen.TCP {
		return fmt.Errorf("listen: at least one of udp/tcp must be enabled")
	}
	if c.Listen.Mode == "explicit" && len(c.Listen.Addresses) == 0 {
		return fmt.Errorf("listen.mode=explicit requires listen.addresses")
	}
	if _, err := netmatch.ParseSet(c.Access.Allow); err != nil {
		return fmt.Errorf("access.allow: %w", err)
	}
	if _, err := netmatch.ParseSet(c.Access.Refuse); err != nil {
		return fmt.Errorf("access.refuse: %w", err)
	}
	if _, err := c.DDNS.RateDuration(); err != nil {
		return fmt.Errorf("ddns.rate: %w", err)
	}
	if _, err := c.DDNS.TrustedSourceSet(); err != nil {
		return fmt.Errorf("ddns.trusted_sources: %w", err)
	}
	if _, err := c.DDNS.TSIGKeyset(); err != nil {
		return fmt.Errorf("ddns: %w", err)
	}
	if c.DDNS.NotifySocketMode != "" {
		if _, err := strconv.ParseUint(c.DDNS.NotifySocketMode, 8, 32); err != nil {
			return fmt.Errorf("ddns.notify_socket_mode %q is not octal (e.g. \"0660\")", c.DDNS.NotifySocketMode)
		}
	}
	if err := c.Encrypted.validate(); err != nil {
		return fmt.Errorf("encrypted: %w", err)
	}
	return nil
}

// validate checks the encrypted front-end config. A disabled block never fails; an enabled
// one must name at least one transport, load a valid (parseable, unexpired) cert, and have
// sane ports/ADN/path. Loading the cert here means -check-config catches a bad/expired cert
// at ExecStartPre, before the daemon even starts.
func (e EncryptedConfig) validate() error {
	if !e.Enabled {
		return nil
	}
	if !e.DoT.Enabled && !e.DoH.Enabled {
		return fmt.Errorf("enabled but neither dot nor doh is enabled")
	}
	if e.CertFile == "" || e.KeyFile == "" {
		return fmt.Errorf("cert_file and key_file are required when enabled")
	}
	if _, err := e.LoadCert(); err != nil {
		return fmt.Errorf("cert: %w", err)
	}
	if e.ADN == "" || dns.Fqdn(e.ADN) == "." {
		return fmt.Errorf("adn is required when enabled")
	}
	if _, ok := dns.IsDomainName(e.ADN); !ok {
		return fmt.Errorf("adn %q is not a valid domain name", e.ADN)
	}
	if e.DoT.Enabled && (e.DoT.Port <= 0 || e.DoT.Port > 65535) {
		return fmt.Errorf("dot.port %d out of range", e.DoT.Port)
	}
	if e.DoH.Enabled {
		if e.DoH.Port <= 0 || e.DoH.Port > 65535 {
			return fmt.Errorf("doh.port %d out of range", e.DoH.Port)
		}
		if !strings.HasPrefix(e.DoH.Path, "/") {
			return fmt.Errorf("doh.path %q must start with /", e.DoH.Path)
		}
	}
	if e.Mode == "explicit" && len(e.Addresses) == 0 {
		return fmt.Errorf("mode=explicit requires addresses")
	}
	return nil
}

// ResolveReverseZones returns the final set of reverse-zone apexes the server is
// authoritative for, honoring ReverseMode. It also returns any auto-detected
// prefixes that were REFUSED for being non-boundary-aligned, so the caller can
// warn the operator to configure them explicitly (the over/under-representation
// guard). Explicit entries are trusted as-is.
func (c Config) ResolveReverseZones() (zones []string, refused []netip.Prefix, err error) {
	scope := c.Zones.ReverseDetect
	if scope == "" {
		scope = revzone.ScopeOff
	}
	if !revzone.ValidScope(scope) {
		return nil, nil, fmt.Errorf("zones.reverse_detect %q unknown", scope)
	}
	// Explicit, stable zones are trusted as-is.
	explicit := make([]string, 0, len(c.Zones.Reverse))
	set := map[string]bool{}
	for _, z := range c.Zones.Reverse {
		z = ensureDot(strings.ToLower(strings.TrimSpace(z)))
		if z != "" && !set[z] {
			set[z] = true
			explicit = append(explicit, z)
		}
	}
	// Dynamically detected zones, with containment dedup against explicit ones.
	if scope != revzone.ScopeOff {
		pfxs, e := revzone.DetectPrefixes(scope)
		if e != nil {
			return nil, nil, e
		}
		derived, un := revzone.Derive(pfxs)
		refused = append(refused, un...)
		for _, z := range derived {
			covered := false
			for _, e := range explicit {
				if revzone.Contains(e, z) {
					covered = true
					break
				}
			}
			if !covered {
				set[z] = true
			}
		}
	}
	for z := range set {
		zones = append(zones, z)
	}
	sort.Strings(zones)
	return zones, refused, nil
}

func ensureDot(s string) string {
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// AccessPolicy builds the runtime allow/deny matcher from the config.
func (c Config) AccessPolicy() (netmatch.Access, error) {
	allow, err := netmatch.ParseSet(c.Access.Allow)
	if err != nil {
		return netmatch.Access{}, err
	}
	refuse, err := netmatch.ParseSet(c.Access.Refuse)
	if err != nil {
		return netmatch.Access{}, err
	}
	return netmatch.Access{Allow: allow, Refuse: refuse}, nil
}
