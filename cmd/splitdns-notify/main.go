// Command splitdns-notify pushes a public-IP change to the splitdns resolver.
//
// A trusted process that knows a public address just changed (a DHCP-client hook, a
// PPP up-script, a router event) runs
//
//	splitdns-notify <hostname> <addr>...
//
// to announce <hostname>.local. with the new A/AAAA addresses. The resolver's
// mDNS source receives the announcement and mirrors the change to Cloudflare for
// the matching non-proxied records (see splitdnsd(8), the ddns section).
//
// It is a single static binary with no third-party runtime dependency, and the
// resolver target is taken from configuration or a flag rather than hardcoded, so the
// source and package stay pristine. The wire shape is an ordinary authoritative mDNS
// response (QR=1, AA=1) carrying the A/AAAA answers, sent by unicast to the configured
// resolver(s) and (by default) multicast to the local segment. The receiver ignores the
// sender, so no privileged source port is required.
//
// Delivery is fire-and-forget UDP (plus an optional local unix socket): a single
// datagram, never a connection, so a slow or unreachable resolver can never block the
// caller. To authenticate that datagram without a round-trip — defeating UDP source-IP
// spoofing of a DDNS trigger — configure a shared TSIG key (RFC 8945); the announcement
// is then HMAC-signed and the resolver honors it regardless of source address. TSIG is
// opt-in: with no key configured the helper still works (socket → multicast by default).
// Run `splitdns-notify --genkey` to mint a key and print both config snippets.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/config"
)

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

const (
	mcast4 = "224.0.0.251"
	mcast6 = "ff02::fb"

	// defaultNotifySocket is the built-in resolver socket path. It matches the resolver's
	// own [ddns].notify_socket default, so neither side needs configuring on a stock setup.
	defaultNotifySocket = "/run/splitdns/notify.sock"
)

// configCandidates are searched (in order) when no -config is given: a dedicated
// notify file first, then a server host's full config (so one file serves both).
var configCandidates = []string{
	"/etc/splitdns/notify.toml",
	"/etc/splitdns/splitdnsd.toml",
}

// effectiveSocket resolves the resolver socket path: an explicit -socket flag wins, then
// [notify].socket from the config, then the built-in default. Use -no-socket to disable
// the socket entirely; an empty result here never happens (the default is non-empty).
func effectiveSocket(flagVal, cfgVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if cfgVal != "" {
		return cfgVal
	}
	return defaultNotifySocket
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(argv []string, out, errOut *os.File) int {
	fs := flag.NewFlagSet("splitdns-notify", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var (
		cfgPath     = fs.String("config", "", "config file for [notify] (default: /etc/splitdns/notify.toml then splitdnsd.toml)")
		port        = fs.Int("port", 5353, "mDNS UDP port for every target")
		ttl         = fs.Uint("ttl", 900, "advertised record TTL in seconds; MUST exceed your re-announce interval (splitdnsd drops the record when it elapses) — comfortably above the longest interval avoids a resolve gap")
		noMulticast = fs.Bool("no-multicast", false, "do not announce to the link-local mDNS multicast groups")
		cacheFlush  = fs.Bool("cache-flush", false, "set the mDNS cache-flush bit so receivers replace prior records")
		quiet       = fs.Bool("quiet", false, "suppress per-target progress and soft-error messages")
		verbose     = fs.Bool("verbose", false, "explain what is sent, how, signed or not, and whether each path succeeded")
		socketFlag  = fs.String("socket", "", "authenticated unix socket on the local resolver (overrides [notify].socket; default "+defaultNotifySocket+")")
		noSocket    = fs.Bool("no-socket", false, "do not attempt the local authenticated unix socket")
		tsigKey     = fs.String("tsig-key", "", "TSIG key name to sign with (overrides config); requires a secret from config or -tsig-secret-file")
		tsigSecFile = fs.String("tsig-secret-file", "", "file holding the base64 TSIG secret (overrides config)")
		noTSIG      = fs.Bool("no-tsig", false, "do not sign even if a TSIG key is configured")
		genKey      = fs.Bool("genkey", false, "generate a fresh TSIG key, print config snippets for both ends, and exit")
	)
	fs.BoolVar(verbose, "v", false, "shorthand for -verbose")
	var servers stringList
	fs.Var(&servers, "server", "unicast resolver target host[:port] (repeatable); overrides config")
	fs.Usage = func() {
		fmt.Fprintf(errOut, "usage: splitdns-notify [flags] <hostname> <addr>...\n\n"+
			"Announce <hostname>.local. with the given A/AAAA addresses to the splitdns\n"+
			"resolver so it mirrors the change to Cloudflare. Addresses may be given as\n"+
			"separate arguments or space-separated within one argument.\n\n"+
			"  splitdns-notify --genkey [name]   mint a TSIG key + print both config blocks\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	rest := fs.Args()

	// --genkey: mint a key and print ready-to-paste config for notifier + resolver.
	if *genKey {
		name := "splitdns-notify"
		if len(rest) > 0 && rest[0] != "" {
			name = rest[0]
		}
		return genTSIGKey(name, out, errOut)
	}

	vf := func(format string, a ...any) {
		if *verbose {
			fmt.Fprintf(errOut, "notify: "+format+"\n", a...)
		}
	}

	if len(rest) < 2 {
		fs.Usage()
		return 2
	}

	host := normalizeHost(rest[0])
	addrs, err := parseAddrs(rest[1:])
	if err != nil {
		fmt.Fprintf(errOut, "splitdns-notify: %v\n", err)
		return 2
	}

	// Resolve config (servers + optional TSIG key + socket). A missing file is not an error.
	cfgUsed, ncfg := loadNotifyConfig(*cfgPath, errOut, *quiet, vf)

	// Effective socket path: an explicit -socket wins, else [notify].socket, else the
	// built-in default (which matches the resolver's [ddns].notify_socket default).
	socketPath := effectiveSocket(*socketFlag, ncfg.Socket)

	msg, err := buildAnnouncement(host, addrs, uint32(*ttl), *cacheFlush)
	if err != nil {
		fmt.Fprintf(errOut, "splitdns-notify: %v\n", err)
		return 2
	}

	// Sign with TSIG when a key is configured (flags override config), unless -no-tsig.
	keyName, secret, algo := resolveTSIG(ncfg, *tsigKey, *tsigSecFile, errOut)
	signed := false
	var packed []byte
	if !*noTSIG && keyName != "" && secret != "" {
		algoFQ := tsigAlgorithm(algo)
		if algoFQ == "" {
			fmt.Fprintf(errOut, "splitdns-notify: unsupported tsig algorithm %q (use hmac-sha256/-sha512/-sha1)\n", algo)
			return 2
		}
		msg.SetTsig(config.CanonicalTSIGName(keyName), algoFQ, 300, time.Now().Unix())
		b, _, gerr := dns.TsigGenerate(msg, secret, "", false)
		if gerr != nil {
			fmt.Fprintf(errOut, "splitdns-notify: tsig sign: %v\n", gerr)
			return 1
		}
		packed, signed = b, true
		vf("signing: TSIG key %q (%s)", config.CanonicalTSIGName(keyName), algoFQ)
	} else {
		b, perr := msg.Pack()
		if perr != nil {
			fmt.Fprintf(errOut, "splitdns-notify: pack: %v\n", perr)
			return 2
		}
		packed = b
		switch {
		case *noTSIG && keyName != "":
			vf("signing: disabled by -no-tsig (key %q present)", keyName)
		case keyName != "" && secret == "":
			vf("signing: key %q named but no secret resolved — sending UNSIGNED", keyName)
		default:
			vf("signing: none (no TSIG key configured — DDNS trigger relies on the socket or trusted_sources)")
		}
	}

	if cfgUsed != "" {
		vf("config: %s", cfgUsed)
	} else {
		vf("config: none found (flags + socket/multicast defaults)")
	}

	// Resolve unicast targets: explicit -server wins; else the config's [notify].
	unicast := []string(servers)
	if len(unicast) == 0 {
		unicast = ncfg.Servers
	}
	targets := buildTargets(unicast, *port, !*noMulticast)
	useSocket := !*noSocket && socketPath != ""
	vf("targets: socket=%v (%s) unicast=%d multicast=%v", useSocket, socketPath, len(unicast), !*noMulticast)

	sent, failed := 0, 0

	// First path: the authenticated local unix socket (peer-cred checked by the daemon) —
	// the only channel that may trigger DDNS without a trusted source or a signature. The
	// unicast/multicast targets below are ALWAYS also attempted (they are the LAN-wide mDNS
	// announcement), so this is not a socket-or-UDP fallback; off-box the socket simply is
	// not present and the UDP paths carry the announcement.
	if useSocket {
		if err := sendUnix(packed, socketPath); err != nil {
			if !*quiet {
				fmt.Fprintf(errOut, "splitdns-notify: socket %s unavailable: %v\n", socketPath, err)
			}
		} else {
			sent++
			if !*quiet {
				fmt.Fprintf(out, "announced %s (%d addr) -> %s (authenticated)\n", host, len(addrs), socketPath)
			}
		}
	}

	if len(targets) == 0 && sent == 0 {
		fmt.Fprintf(errOut, "splitdns-notify: no delivery path (socket failed and no UDP targets; give -server or drop -no-multicast)\n")
		return 1
	}
	for _, t := range targets {
		if err := sendTo(packed, t.addr); err != nil {
			failed++
			if !*quiet {
				fmt.Fprintf(errOut, "splitdns-notify: %s: %v\n", t.label, err)
			}
			continue
		}
		sent++
		if !*quiet {
			suffix := ""
			if signed {
				suffix = " (signed)"
			}
			fmt.Fprintf(out, "announced %s (%d addr) -> %s%s\n", host, len(addrs), t.label, suffix)
		}
	}
	vf("result: %d sent, %d failed%s", sent, failed, map[bool]string{true: ", signed", false: ", UNSIGNED"}[signed])
	if sent == 0 {
		fmt.Fprintf(errOut, "splitdns-notify: all %d target(s) failed\n", failed)
		return 1
	}
	return 0
}

// normalizeHost lowercases and rewrites any host into a single-label .local. FQDN: a
// trailing ".local" or ".local." is folded away and re-added so callers may pass
// "host", "host.local", or "host.local.".
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimSuffix(h, ".local")
	return h + ".local."
}

// parseAddrs flattens the address arguments (each may be space-separated) and
// validates every entry as an IP literal.
func parseAddrs(args []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, arg := range args {
		for _, tok := range strings.Fields(arg) {
			a, err := netip.ParseAddr(tok)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q", tok)
			}
			out = append(out, a.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no addresses given")
	}
	return out, nil
}

// buildAnnouncement constructs the authoritative mDNS response.
func buildAnnouncement(host string, addrs []netip.Addr, ttl uint32, cacheFlush bool) (*dns.Msg, error) {
	class := uint16(dns.ClassINET)
	if cacheFlush {
		class |= 0x8000 // mDNS cache-flush bit (RFC 6762 §10.2)
	}
	m := new(dns.Msg)
	m.Response = true
	m.Authoritative = true
	for _, a := range addrs {
		hdr := dns.RR_Header{Name: host, Class: class, Ttl: ttl}
		if a.Is4() {
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IP(a.AsSlice())})
		} else {
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(a.AsSlice())})
		}
	}
	if len(m.Answer) == 0 {
		return nil, fmt.Errorf("no answers built")
	}
	return m, nil
}

type target struct {
	addr  *net.UDPAddr
	label string
}

// buildTargets resolves unicast host[:port] entries and, unless disabled, appends
// the IPv4 multicast group plus one IPv6 multicast target per multicast-capable
// interface (link-local ff02::fb requires a zone).
func buildTargets(unicast []string, port int, multicast bool) []target {
	var ts []target
	for _, hp := range unicast {
		hp = strings.TrimSpace(hp)
		if hp == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(hp); err != nil {
			hp = net.JoinHostPort(hp, strconv.Itoa(port))
		}
		ua, err := net.ResolveUDPAddr("udp", hp)
		if err != nil {
			continue
		}
		ts = append(ts, target{addr: ua, label: hp})
	}
	if multicast {
		ts = append(ts, target{
			addr:  &net.UDPAddr{IP: net.ParseIP(mcast4), Port: port},
			label: net.JoinHostPort(mcast4, strconv.Itoa(port)),
		})
		ifaces, _ := net.Interfaces()
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
				continue
			}
			ts = append(ts, target{
				addr:  &net.UDPAddr{IP: net.ParseIP(mcast6), Port: port, Zone: ifi.Name},
				label: fmt.Sprintf("[%s%%%s]:%d", mcast6, ifi.Name, port),
			})
		}
	}
	return ts
}

func sendTo(packed []byte, addr *net.UDPAddr) error {
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(packed)
	return err
}

// sendUnix delivers the announcement over the authenticated unix socket. The daemon
// reads the same packed mDNS message and SO_PEERCRED-checks this process.
func sendUnix(packed []byte, path string) error {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Write(packed)
	return err
}

// loadNotifyConfig resolves and loads the [notify] config, returning the path actually
// used ("" if none) and the parsed config. An explicit -config that fails to load is a
// soft error (we continue with multicast-only); auto-discovery silently skips missing
// candidates.
func loadNotifyConfig(explicit string, errOut *os.File, quiet bool, vf func(string, ...any)) (string, config.NotifyConfig) {
	if explicit != "" {
		n, err := config.LoadNotify(explicit)
		if err != nil {
			if !quiet {
				fmt.Fprintf(errOut, "splitdns-notify: %v (continuing with socket + multicast defaults)\n", err)
			}
			return "", config.NotifyConfig{}
		}
		return explicit, n
	}
	for _, p := range configCandidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		n, err := config.LoadNotify(p)
		if err != nil {
			vf("config: %s present but unreadable: %v", p, err)
			continue
		}
		return p, n
	}
	return "", config.NotifyConfig{}
}

// resolveTSIG merges config + flag overrides into the key name, secret, and algorithm
// to sign with. Flags win over config so a one-off run can override the deployed key.
func resolveTSIG(n config.NotifyConfig, flagKey, flagSecFile string, errOut *os.File) (name, secret, algo string) {
	name = n.TSIGKeyName
	secret = n.TSIGSecret
	algo = n.TSIGAlgorithm
	if flagKey != "" {
		name = flagKey
	}
	if flagSecFile != "" {
		b, err := os.ReadFile(flagSecFile)
		if err != nil {
			fmt.Fprintf(errOut, "splitdns-notify: -tsig-secret-file: %v\n", err)
		} else {
			secret = strings.TrimSpace(string(b))
		}
	}
	return name, strings.TrimSpace(secret), algo
}

// tsigAlgorithm maps a config algorithm string to the fully-qualified miekg/dns
// constant, defaulting to hmac-sha256. Returns "" for an unsupported algorithm.
func tsigAlgorithm(s string) string {
	switch strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) {
	case "", "hmac-sha256":
		return dns.HmacSHA256
	case "hmac-sha512":
		return dns.HmacSHA512
	case "hmac-sha1":
		return dns.HmacSHA1
	default:
		return ""
	}
}

// genTSIGKey mints a random 256-bit secret and prints copy-paste config for both the
// notifier (notify.toml) and the resolver (splitdnsd.toml [ddns]). The secret is
// printed once; it never touches disk here, so the operator places it deliberately.
func genTSIGKey(name string, out, errOut *os.File) int {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fmt.Fprintf(errOut, "splitdns-notify: genkey: %v\n", err)
		return 1
	}
	secret := base64.StdEncoding.EncodeToString(raw)
	fmt.Fprintf(out, `# Shared TSIG key %q (hmac-sha256). Keep the secret private and identical on both ends.

# --- notifier: /etc/splitdns/notify.toml ---
[notify]
# servers      = ["resolver.lan"]   # unicast target(s); optional if multicast reaches the resolver
tsig_key     = %q
tsig_secret  = %q

# --- resolver: add to /etc/splitdns/splitdnsd.toml under [ddns] ---
# tsig_keys = [
#   { name = %q, secret = %q },
# ]
# require_signature = true   # optional: reject UNSIGNED DDNS triggers (trusted_sources alone no longer suffices)
`, name, name, secret, name, secret)
	return 0
}
