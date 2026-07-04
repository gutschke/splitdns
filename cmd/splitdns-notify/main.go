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
//
// With --listen it instead runs as a small relay daemon: it reads "<host> <addr>..."
// datagrams from a unix socket (systemd socket activation, or -listen-socket) and
// announces each, reusing the same signing/delivery config. This lets an UNPRIVILEGED
// caller — e.g. a DHCP lease hook running as the DHCP server's user — trigger an announce
// by sending one datagram, while the TSIG key stays in this one small service.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
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
		listen      = fs.Bool("listen", false, "relay mode: read \"<host> <addr>...\" datagrams from a unix socket (systemd socket activation, or -listen-socket) and announce each")
		listenSock  = fs.String("listen-socket", "", "with -listen and no systemd socket activation, the unixgram socket path to create and read from")
		relaySock   = fs.String("relay", "", "client mode: send the \"<host> <addr>...\" arguments as one datagram to this relay socket (see -listen) and exit; uses no config or keys")
	)
	fs.BoolVar(verbose, "v", false, "shorthand for -verbose")
	var servers stringList
	fs.Var(&servers, "server", "unicast resolver target host[:port] (repeatable); overrides config")
	fs.Usage = func() {
		fmt.Fprintf(errOut, "usage: splitdns-notify [flags] <hostname> <addr>...\n"+
			"       splitdns-notify --listen            (relay daemon; reads datagrams from a socket)\n\n"+
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

	// --relay: minimal client — forward the arguments to a relay socket (see -listen) and
	// exit. No config, no keys, no network; a DHCP lease hook uses this (no socat/nc needed)
	// so an unprivileged caller triggers a signed announce without holding any credentials.
	if *relaySock != "" {
		if len(rest) < 2 {
			fs.Usage()
			return 2
		}
		return sendToRelay(*relaySock, rest, errOut)
	}

	vf := func(format string, a ...any) {
		if *verbose {
			fmt.Fprintf(errOut, "notify: "+format+"\n", a...)
		}
	}

	// Resolve the delivery config once (independent of the host being announced): config
	// file, socket path, TSIG key, and unicast/multicast targets. In --listen mode this is
	// reused for every datagram; in one-shot mode it delivers a single announcement.
	cfgUsed, ncfg := loadNotifyConfig(*cfgPath, errOut, *quiet, vf)
	socketPath := effectiveSocket(*socketFlag, ncfg.Socket)
	keyName, secret, algo := resolveTSIG(ncfg, *tsigKey, *tsigSecFile, errOut)
	unicast := []string(servers)
	if len(unicast) == 0 {
		unicast = ncfg.Servers
	}
	ann := &announcer{
		ttl: uint32(*ttl), cacheFlush: *cacheFlush,
		keyName: keyName, secret: secret, algo: algo, noTSIG: *noTSIG,
		useSocket: !*noSocket && socketPath != "", socketPath: socketPath,
		targets: buildTargets(unicast, *port, !*noMulticast),
	}
	if cfgUsed != "" {
		vf("config: %s", cfgUsed)
	} else {
		vf("config: none found (flags + socket/multicast defaults)")
	}
	vf("targets: socket=%v (%s) unicast=%d multicast=%v", ann.useSocket, socketPath, len(unicast), !*noMulticast)

	// --listen: relay/daemon mode. Keeps the TSIG key in ONE small service so an
	// unprivileged writer (a DHCP lease hook) just sends a datagram and needs no announce
	// credentials. Triggered by the flag or by systemd socket activation (LISTEN_FDS).
	if *listen || os.Getenv("LISTEN_FDS") != "" {
		return runListen(*listenSock, ann, out, errOut, *quiet, vf)
	}

	// One-shot: announce the host/addrs given on the command line.
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
	res, signed, serr := ann.send(host, addrs)
	if serr != nil {
		fmt.Fprintf(errOut, "splitdns-notify: %v\n", serr)
		return 2
	}
	if len(res) == 0 {
		fmt.Fprintf(errOut, "splitdns-notify: no delivery path (no socket and no UDP targets; give -server or drop -no-multicast)\n")
		return 1
	}
	sent, failed := 0, 0
	for _, r := range res {
		if r.err != nil {
			failed++
			if !*quiet {
				fmt.Fprintf(errOut, "splitdns-notify: %s: %v\n", r.label, r.err)
			}
			continue
		}
		sent++
		if !*quiet {
			switch {
			case r.socket:
				fmt.Fprintf(out, "announced %s (%d addr) -> %s (authenticated)\n", host, len(addrs), r.label)
			case signed:
				fmt.Fprintf(out, "announced %s (%d addr) -> %s (signed)\n", host, len(addrs), r.label)
			default:
				fmt.Fprintf(out, "announced %s (%d addr) -> %s\n", host, len(addrs), r.label)
			}
		}
	}
	vf("result: %d sent, %d failed%s", sent, failed, map[bool]string{true: ", signed", false: ", UNSIGNED"}[signed])
	if sent == 0 {
		fmt.Fprintf(errOut, "splitdns-notify: all %d target(s) failed\n", failed)
		return 1
	}
	return 0
}

// announcer holds the resolved delivery config and turns a (host, addrs) pair into a
// signed (or plain) mDNS announcement delivered to the local socket + UDP targets. It is
// built once and reused for every one-shot run or every relayed datagram.
type announcer struct {
	ttl        uint32
	cacheFlush bool
	keyName    string
	secret     string
	algo       string
	noTSIG     bool
	useSocket  bool
	socketPath string
	targets    []target
}

// deliveryResult is one target's outcome (err==nil means delivered).
type deliveryResult struct {
	label  string
	socket bool
	err    error
}

// send builds, signs (a fresh TSIG timestamp each call), and delivers the announcement,
// returning a per-target result plus whether it was signed. A build/sign error returns
// early; individual target failures are reported in the results, not the error.
func (a *announcer) send(host string, addrs []netip.Addr) (res []deliveryResult, signed bool, err error) {
	msg, err := buildAnnouncement(host, addrs, a.ttl, a.cacheFlush)
	if err != nil {
		return nil, false, err
	}
	packed, signed, err := a.pack(msg)
	if err != nil {
		return nil, false, err
	}
	if a.useSocket {
		res = append(res, deliveryResult{label: a.socketPath, socket: true, err: sendUnix(packed, a.socketPath)})
	}
	for _, t := range a.targets {
		res = append(res, deliveryResult{label: t.label, err: sendTo(packed, t.addr)})
	}
	return res, signed, nil
}

// pack TSIG-signs the message when a key + secret are configured (unless noTSIG), else
// returns the plain wire bytes. Signing stamps the current time on every call.
func (a *announcer) pack(msg *dns.Msg) (packed []byte, signed bool, err error) {
	if !a.noTSIG && a.keyName != "" && a.secret != "" {
		algoFQ := tsigAlgorithm(a.algo)
		if algoFQ == "" {
			return nil, false, fmt.Errorf("unsupported tsig algorithm %q (use hmac-sha256/-sha512/-sha1)", a.algo)
		}
		msg.SetTsig(config.CanonicalTSIGName(a.keyName), algoFQ, 300, time.Now().Unix())
		b, _, gerr := dns.TsigGenerate(msg, a.secret, "", false)
		if gerr != nil {
			return nil, false, fmt.Errorf("tsig sign: %w", gerr)
		}
		return b, true, nil
	}
	b, perr := msg.Pack()
	if perr != nil {
		return nil, false, fmt.Errorf("pack: %w", perr)
	}
	return b, false, nil
}

// runListen is the relay daemon: it reads "<host> <addr>..." datagrams from a unix socket
// and announces each via ann. It never blocks on a slow reader (datagrams) and treats a
// malformed line as a skip, so a bad message can never take the relay down. Returns 0 on
// a clean shutdown (SIGTERM/SIGINT), non-zero only if the socket could not be acquired.
func runListen(sockPath string, ann *announcer, out, errOut *os.File, quiet bool, vf func(string, ...any)) int {
	pc, cleanup, err := listenSocket(sockPath)
	if err != nil {
		fmt.Fprintf(errOut, "splitdns-notify: --listen: %v\n", err)
		return 1
	}
	defer cleanup()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sigCh; pc.Close() }()

	if !quiet {
		fmt.Fprintf(errOut, "splitdns-notify: relay listening (socket=%v, %d UDP target(s))\n", ann.useSocket, len(ann.targets))
	}
	sdNotifyReady()
	return relayLoop(pc, ann, vf)
}

// relayLoop reads "<host> <addr>..." datagrams from pc and announces each via ann until pc
// is closed (returns 0). A malformed or unparsable line is skipped, never fatal, so one
// bad message cannot take the relay down.
func relayLoop(pc net.PacketConn, ann *announcer, vf func(string, ...any)) int {
	buf := make([]byte, 4096)
	for {
		n, _, rerr := pc.ReadFrom(buf)
		if rerr != nil {
			return 0 // socket closed on shutdown
		}
		line := strings.TrimSpace(string(buf[:n]))
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			vf("relay: ignoring malformed message %q", line)
			continue
		}
		host := normalizeHost(f[0])
		addrs, aerr := parseAddrs(f[1:])
		if aerr != nil {
			vf("relay: %v in %q", aerr, line)
			continue
		}
		res, signed, serr := ann.send(host, addrs)
		if serr != nil {
			vf("relay: %s: %v", host, serr)
			continue
		}
		sent, failed := 0, 0
		for _, r := range res {
			if r.err != nil {
				failed++
			} else {
				sent++
			}
		}
		vf("relay: %s (%d addr) -> %d sent, %d failed%s", host, len(addrs), sent, failed,
			map[bool]string{true: ", signed", false: ""}[signed])
	}
}

// listenSocket returns the relay's datagram socket: systemd socket activation (the fd
// passed as LISTEN_FDS, at SD_LISTEN_FDS_START=3) when present — so systemd owns the
// socket path and its permissions — otherwise a fresh unixgram socket bound at sockPath.
func listenSocket(sockPath string) (net.PacketConn, func(), error) {
	if os.Getenv("LISTEN_FDS") != "" {
		f := os.NewFile(3, "notify-relay")
		if f == nil {
			return nil, nil, fmt.Errorf("socket activation: no fd 3")
		}
		pc, err := net.FilePacketConn(f)
		f.Close() // FilePacketConn keeps its own dup of the fd
		if err != nil {
			return nil, nil, fmt.Errorf("socket activation: %w", err)
		}
		return pc, func() { pc.Close() }, nil
	}
	if sockPath == "" {
		return nil, nil, fmt.Errorf("no socket: set -listen-socket or use systemd socket activation")
	}
	_ = os.Remove(sockPath) // clear a stale socket from an unclean exit
	pc, err := net.ListenPacket("unixgram", sockPath)
	if err != nil {
		return nil, nil, err
	}
	return pc, func() { pc.Close(); os.Remove(sockPath) }, nil
}

// sdNotifyReady sends systemd's READY=1 if launched under Type=notify (NOTIFY_SOCKET set).
// It is a best-effort no-op otherwise, so the binary keeps zero dependencies.
func sdNotifyReady() {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return
	}
	c, err := net.Dial("unixgram", path)
	if err != nil {
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte("READY=1"))
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

// sendToRelay forwards the "<host> <addr>..." arguments as one datagram to a splitdns-notify
// relay socket (see -listen). It needs no config or TSIG key, so an unprivileged caller (a
// DHCP lease hook running as the DHCP server's user) can trigger a signed announce without
// holding any announce credentials of its own — and without a socat/nc dependency.
func sendToRelay(sock string, args []string, errOut *os.File) int {
	c, err := net.Dial("unixgram", sock)
	if err != nil {
		fmt.Fprintf(errOut, "splitdns-notify: --relay %s: %v\n", sock, err)
		return 1
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(strings.Join(args, " "))); err != nil {
		fmt.Fprintf(errOut, "splitdns-notify: --relay: %v\n", err)
		return 1
	}
	return 0
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
