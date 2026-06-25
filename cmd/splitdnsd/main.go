// Command splitdnsd is a standalone split-horizon DNS resolver for a trusted LAN.
// It wires the two atomic.Pointer planes (Snapshot for zones, MDNSView for *.local)
// that the hot path reads, parses flags, installs signal handling, and starts the
// listeners, control-plane workers, and forwarder. See ARCHITECTURE.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/anscache"
	"github.com/gutschke/splitdns/internal/cfapi"
	"github.com/gutschke/splitdns/internal/config"
	"github.com/gutschke/splitdns/internal/ddns"
	"github.com/gutschke/splitdns/internal/diag"
	"github.com/gutschke/splitdns/internal/forwarder"
	"github.com/gutschke/splitdns/internal/loglimit"
	"github.com/gutschke/splitdns/internal/mdns"
	"github.com/gutschke/splitdns/internal/mirror"
	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
	"github.com/gutschke/splitdns/internal/qlog"
	"github.com/gutschke/splitdns/internal/resolver"
	"github.com/gutschke/splitdns/internal/server"
	"github.com/gutschke/splitdns/internal/supervisor"
	"github.com/gutschke/splitdns/internal/vhost"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// state holds the published zone Snapshot plane. The hot path loads it (and the
// mDNS view, owned by the mdns.Source) atomically per request and never locks
// (§2.1, §2.2). The CF mirror/builder will Store newer snapshots here.
type state struct {
	snapshot atomic.Pointer[model.Snapshot]
}

func main() {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")
		configPath  = flag.String("config", "/etc/splitdns/splitdnsd.toml", "path to config file")
		checkConfig = flag.Bool("check-config", false, "validate config and print the resolved listen set, then exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("splitdnsd %s\n", version)
		return
	}

	// Rate-limit floods of an identical message (e.g. a wedged loop logging the same
	// line every iteration) to one per interval, carrying a suppressed=N count, while
	// distinct messages always pass — so the journal stays scannable under load.
	base := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(loglimit.New(base, 5*time.Second, 0))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("config load failed", "path", *configPath, "err", err)
		os.Exit(2)
	}

	// Resolve the listen set now (Q7: bind only local-scope addresses unless the
	// operator overrides with mode=explicit). This is also what -check-config prints.
	listen, err := netmatch.SelectListenAddrs(cfg.Listen.Mode, cfg.Listen.Addresses, cfg.Listen.Port)
	if err != nil {
		slog.Error("listen address selection failed", "err", err)
		os.Exit(2)
	}
	if *checkConfig {
		fmt.Printf("config OK: %s\n", *configPath)
		fmt.Printf("listen (%s, udp=%v tcp=%v): %v\n", cfg.Listen.Mode, cfg.Listen.UDP, cfg.Listen.TCP, listen)
		fmt.Printf("access allow: %v\n", cfg.Access.Allow)
		if len(cfg.Access.Refuse) > 0 {
			fmt.Printf("access refuse: %v\n", cfg.Access.Refuse)
		}
		detect := cfg.Zones.ReverseDetect
		if detect == "" {
			detect = "off"
		}
		revZones, refused, rerr := cfg.ResolveReverseZones()
		if rerr != nil {
			slog.Error("reverse-zone resolution failed", "err", rerr)
			os.Exit(2)
		}
		fmt.Printf("reverse zones (explicit + detect=%s): %v\n", detect, revZones)
		if len(refused) > 0 {
			fmt.Printf("reverse zones REFUSED (not boundary-aligned, configure explicitly): %v\n", refused)
		}
		return
	}

	access, err := cfg.AccessPolicy()
	if err != nil {
		slog.Error("access policy", "err", err)
		os.Exit(2)
	}
	revZones, _, _ := cfg.ResolveReverseZones()

	st := &state{}
	// Cold-start snapshot: authoritative for our reverse + stub zones, with the vhost
	// redirect target; local CF zones are EMPTY until the mirror's first build lands,
	// so those names FORWARD (returning real public answers) instead of NXDOMAIN.
	// Their suffixes are in AllowSuffix so a forwarded LAN IP is not rebind-stripped.
	st.snapshot.Store(mirror.BaseSnapshot(cfg, revZones))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// A cancelable child so the diagnostics "restart" control can trigger the same
	// graceful-shutdown path a SIGTERM would; with systemd Restart=always the unit
	// comes straight back on the new binary/config.
	ctx, requestRestart := context.WithCancel(ctx)
	defer requestRestart()

	// All long-lived control-plane workers run under the supervisor (panic recovery +
	// capped backoff + progress-liveness stall detection). They are registered below
	// and started together after the listeners bind.
	var workers []supervisor.Worker

	// DDNS writer (opt-in). Reads a host's current records straight from the in-memory
	// mirror snapshot (no extra CF calls); writes via the DNS:Edit token.
	var writer *ddns.Writer
	if cfg.DDNS.Enabled {
		recSrc := mirror.SnapshotSource{Get: st.snapshot.Load}
		w, werr := buildWriter(cfg, recSrc)
		if werr != nil {
			slog.Error("ddns writer init failed (continuing without write-back)", "err", werr)
		} else {
			writer = w
			workers = append(workers, supervisor.Worker{Name: "ddns", Ceiling: 5 * time.Minute, Run: writer.Run})
			slog.Info("ddns writer registered", "dry_run", cfg.DDNS.DryRun)
		}
	}

	// mDNS source: maintains the *.local view and turns host announcements into DDNS
	// changes. Listener best-effort (port 5353 may already be held / unprivileged).
	src := mdns.NewSource(func(host string, addrs []netip.Addr) {
		if writer != nil {
			writer.Submit(ddns.Change{Host: host, Addrs: addrs})
		}
	}, nil)
	workers = append(workers, supervisor.Worker{Name: "mdns", Ceiling: 5 * time.Minute, Run: src.Run})

	// D7: an announcement may trigger write-back via a valid TSIG signature (source-IP
	// independent, unspoofable) or — unless require_signature is set — an unsigned packet
	// whose SOURCE is in ddns.trusted_sources. Everything else still updates the *.local
	// view but is inert for DDNS.
	trustedSrc, terr := cfg.DDNS.TrustedSourceSet()
	if terr != nil {
		slog.Error("ddns.trusted_sources parse failed", "err", terr)
		os.Exit(2)
	}
	tsigKeys, kerr := cfg.DDNS.TSIGKeyset()
	if kerr != nil {
		slog.Error("ddns.tsig_keys load failed", "err", kerr)
		os.Exit(2)
	}
	if len(tsigKeys) > 0 {
		slog.Info("ddns: TSIG-authenticated triggers enabled", "keys", len(tsigKeys), "require_signature", cfg.DDNS.RequireSignature)
	}
	trusted := func(a netip.Addr) bool { return trustedSrc.Contains(a) }
	verify := mdns.NewSigVerifier(tsigKeys)
	if lis, lerr := mdns.Listen(src, 5353, trusted, verify, cfg.DDNS.RequireSignature, func(m string) { slog.Warn(m) }); lerr != nil {
		slog.Warn("mDNS listener unavailable (LAN/*.local resolution degraded)", "err", lerr)
	} else {
		defer lis.Close()
	}

	// D7: authenticated local DDNS-trigger channel. splitdns-notify(8) connects here;
	// every peer is SO_PEERCRED-checked (root + daemon uid + configured notify_uids).
	// This is the always-trusted path, independent of trusted_sources.
	if cfg.DDNS.NotifySocket != "" {
		allow := mdns.AllowUIDFunc(uint32(os.Getuid()), cfg.DDNS.NotifyUIDs)
		if nsock, nerr := mdns.ListenNotify(cfg.DDNS.NotifySocket, src, allow, func(m string) { slog.Warn(m) }); nerr != nil {
			slog.Warn("notify socket unavailable (authenticated DDNS trigger disabled)", "err", nerr)
		} else {
			// Optional group-based access: members of ddns.notify_groups may trigger DDNS
			// via the socket with no shared key — a POSIX ACL grants those groups connect
			// rights and the peer-cred handler authorizes their uid by membership.
			if len(cfg.DDNS.NotifyGroups) > 0 || cfg.DDNS.NotifySocketMode != "" {
				groups, unknown := config.ResolveNotifyGroups(cfg.DDNS.NotifyGroups)
				for _, u := range unknown {
					slog.Warn("ddns.notify_groups: group not found, skipping", "group", u)
				}
				var mode os.FileMode
				if cfg.DDNS.NotifySocketMode != "" {
					if m, merr := strconv.ParseUint(cfg.DDNS.NotifySocketMode, 8, 32); merr != nil {
						slog.Warn("ddns.notify_socket_mode not octal; using default 0660", "value", cfg.DDNS.NotifySocketMode)
					} else {
						mode = os.FileMode(m)
					}
				}
				nsock.WithGroups(groups, mode)
				if len(groups) > 0 {
					slog.Info("notify socket: group-triggered DDNS enabled (no key needed)", "groups", len(groups))
				}
			}
			defer nsock.Close()
			workers = append(workers, supervisor.Worker{Name: "notify", Ceiling: 5 * time.Minute, Run: nsock.Run})
			slog.Info("notify socket serving", "path", nsock.Path())
		}
	}

	// Forwarder (DoT primary, audited cleartext fallback).
	fwd, ferr := forwarder.Build(cfg.Upstream.Servers, cfg.Upstream.CleartextFallback,
		func(m string) { slog.Warn(m) }, forwarder.WithBreaker(cfg.Upstream.Breaker))
	if ferr != nil {
		slog.Error("forwarder init", "err", ferr)
		os.Exit(2)
	}

	// VHost feed worker (R3): fetches the reverse proxy redirect set, stripping any local-zone
	// suffix to a bare label. Republishes the snapshot's VHosts on change.
	var feed *vhost.Feed
	if cfg.VHost.Feed != "" {
		feed = vhost.New(cfg.VHost.Feed, cfg.Zones.Local, func(m string) { slog.Info(m) })
	}
	vhostProvider := func() map[string]bool {
		if feed != nil {
			return feed.Current()
		}
		return nil
	}

	// Snapshot builder + publisher. With a readable CF read token it mirrors zones
	// authoritatively; without one it publishes the base snapshot (local zones forward)
	// and still folds in the vhost set. It is the single snapshot publisher.
	var lister mirror.ZoneLister
	var cfRead *cfapi.Client // kept for the diagnostics self-test (token validity probe)
	var cache *mirror.Cache
	var fetcher mirror.SerialFetcher
	if readTok, terr := os.ReadFile(cfg.Cloudflare.ReadTokenFile); terr != nil {
		slog.Warn("CF read token unreadable; mirror disabled (local zones will forward)", "err", terr)
	} else {
		cfRead = cfapi.New(cfg.Cloudflare.BaseURL, strings.TrimSpace(string(readTok)), nil)
		lister = cfRead
		cache = mirror.NewCache(cfg.Cache.Dir, 0, func(m string) { slog.Warn(m) })
		fetcher = mirror.NewBootstrapSerialFetcher(cfg.Upstream.Servers)
	}
	builder := mirror.NewBuilder(lister, mirror.NewForwarderResolver(fwd), cfg, revZones,
		func(s *model.Snapshot) { st.snapshot.Store(s) }, cache, fetcher, vhostProvider,
		func(m string) { slog.Info(m) }, nil)
	workers = append(workers, supervisor.Worker{Name: "mirror", Ceiling: 15 * time.Minute, Run: builder.Run})
	if feed != nil {
		workers = append(workers, supervisor.Worker{Name: "vhost", Ceiling: 20 * time.Minute,
			Run: func(ctx context.Context, progress func()) { feed.Run(ctx, builder.ApplyVHosts, progress) }})
	}

	// Supervisor: panic recovery + stall detection for every worker, plus the sd_notify
	// watchdog gated on an IN-PROCESS snapshot liveness probe (immune to the inbound
	// limiter and to upstream outages). A stale primary snapshot escalates: force-restart
	// the mirror, then withhold the ping (controlled systemd restart) if it still cannot
	// publish.
	liveness := func() bool {
		snap := st.snapshot.Load()
		if snap == nil {
			return false
		}
		req := new(dns.Msg)
		req.SetQuestion("health.splitdnsd.local.", dns.TypeA)
		out := resolver.Resolve(snap, src.View(), req)
		return out.Msg != nil && len(out.Msg.Answer) > 0
	}
	// "Snapshot age" for the watchdog is time since the mirror was last confirmed CURRENT
	// (a fresh build OR a poll that found stable serials), NOT time since the last rebuild
	// — a healthy mirror with unchanged zones legitimately doesn't rebuild for hours and
	// must not be force-restarted for it. Falls back to BuiltAt before the first confirm.
	snapshotAge := func() time.Duration {
		snap := st.snapshot.Load()
		if snap == nil {
			return time.Hour
		}
		newest := snap.BuiltAt
		if c := builder.ConfirmedAt(); c.After(newest) {
			newest = c
		}
		return time.Since(newest)
	}
	sup := supervisor.New(supervisor.Options{
		Liveness: liveness, SnapshotAge: snapshotAge,
		HardCeiling: 10 * time.Minute, TripCeiling: 20 * time.Minute, BuilderName: "mirror",
		Notify: supervisor.NotifyWatchdog, WatchdogEvery: supervisor.WatchdogInterval(),
		Log: func(m string) { slog.Warn(m) },
	})
	for _, w := range workers {
		sup.Register(w)
	}
	go sup.Run(ctx)

	// Forward-path answer cache (TTL + negative + serve-stale, RFC 2308/8767/9520).
	// Authoritative/local answers never enter it; only public-upstream forwards do.
	var ansCache *anscache.Cache
	if cfg.Cache.Answers {
		cc := anscache.Defaults()
		cc.MaxEntries = cfg.Cache.MaxEntries
		cc.ServeStale = cfg.Cache.ServeStale
		ansCache = anscache.New(cc, nil)
		slog.Info("answer cache enabled", "max_entries", cc.MaxEntries, "serve_stale", cc.ServeStale)
	}

	// Query telemetry for the diagnostics console (last-N queries + per-client stats).
	queryLog := qlog.New(1024, 4096)

	// :53 front end.
	srv := server.New(server.Config{
		Access:    access,
		Snapshot:  st.snapshot.Load,
		View:      src.View,
		Forwarder: fwd,
		Cache:     ansCache,
		QueryLog:  queryLog,
		Context:   ctx, // per-request forwards cancel on shutdown; 2s budget (D4)
		Log:       func(m string) { slog.Warn(m) },
	})
	if err := srv.Start(listen, cfg.Listen.UDP, cfg.Listen.TCP); err != nil {
		slog.Error("listener start failed", "err", err)
		os.Exit(2)
	}
	defer srv.Shutdown()

	// Tell systemd (Type=notify) that startup is complete and :53 is bound.
	if err := supervisor.NotifyReady(); err != nil {
		slog.Warn("sd_notify READY failed", "err", err)
	}

	// Read-only diagnostics HTTP (R10), localhost-only by default.
	diagSrv := diag.New(cfg.Diag.Addr, st.snapshot.Load, src.View, version, func(m string) { slog.Warn(m) })
	diagSrv.WithCacheStats(func() (anscache.Stats, bool) {
		if ansCache == nil {
			return anscache.Stats{}, false
		}
		return ansCache.Stats(), true
	})
	diagSrv.WithQueryLog(queryLog)
	diagSrv.WithBackends(fwd.Backends)
	diagSrv.WithWorkers(sup.Stats)
	// Resolve a client IP to a display name from local data only (mDNS reverse view, then
	// a cached PTR) — never a fresh network lookup.
	diagSrv.WithClientNames(func(ip netip.Addr) string {
		arpa, err := dns.ReverseAddr(ip.String())
		if err != nil {
			return ""
		}
		if v := src.View(); v != nil {
			for _, rr := range v.Reverse[arpa] {
				if rr.Type == dns.TypePTR && rr.Content != "" {
					return strings.TrimSuffix(rr.Content, ".")
				}
			}
		}
		if ansCache != nil {
			if msg, ok := ansCache.Peek(anscache.Key{Name: arpa, Qtype: dns.TypePTR, Qclass: dns.ClassINET}); ok {
				for _, rr := range msg.Answer {
					if ptr, isPTR := rr.(*dns.PTR); isPTR {
						return strings.TrimSuffix(ptr.Ptr, ".")
					}
				}
			}
		}
		return ""
	})
	if cfg.Diag.SocketMode != "" {
		// Non-fatal: a bad diag.socket_mode must not stop DNS — warn and keep the default.
		if m, merr := strconv.ParseUint(cfg.Diag.SocketMode, 8, 32); merr != nil {
			slog.Warn("diag.socket_mode not octal (e.g. \"0660\"); using default 0660", "value", cfg.Diag.SocketMode, "err", merr)
		} else {
			diagSrv.WithSocketMode(os.FileMode(m))
		}
	}
	// Optional source-IP allow-list for the diagnostics endpoint. Non-fatal: a bad CIDR
	// here must not stop DNS — warn and fail SAFE (deny all) so a typo never widens access.
	if len(cfg.Diag.Allow) > 0 {
		if set, aerr := netmatch.ParseSet(cfg.Diag.Allow); aerr != nil {
			slog.Warn("diag.allow parse failed; denying all diag access (DNS unaffected)", "err", aerr)
			diagSrv.WithAccess(func(netip.Addr) bool { return false })
		} else {
			diagSrv.WithAccess(set.Contains)
			slog.Info("diag endpoint source-IP allow-list active", "cidrs", cfg.Diag.Allow)
		}
	}
	diagSrv.WithSelfTest(func(tctx context.Context) []diag.TestResult {
		var out []diag.TestResult
		run := func(name string, f func() (string, error)) {
			start := time.Now()
			detail, err := f()
			r := diag.TestResult{Name: name, OK: err == nil, Duration: time.Since(start), Detail: detail}
			if err != nil {
				r.Detail = err.Error()
			}
			out = append(out, r)
		}
		run("upstream-resolve", func() (string, error) {
			m := new(dns.Msg)
			m.SetQuestion(".", dns.TypeSOA)
			resp, err := fwd.Forward(tctx, m)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer)), nil
		})
		run("cloudflare-token", func() (string, error) {
			if cfRead == nil {
				return "skipped (no read token configured)", nil
			}
			zones, err := cfRead.Zones(tctx)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("token valid, %d zones visible", len(zones)), nil
		})
		run("local-resolve", func() (string, error) {
			snap := st.snapshot.Load()
			if snap == nil {
				return "", fmt.Errorf("no snapshot published yet")
			}
			m := new(dns.Msg)
			m.SetQuestion("health.splitdnsd.local.", dns.TypeA)
			o := resolver.Resolve(snap, src.View(), m)
			if o.Msg == nil || len(o.Msg.Answer) == 0 {
				return "", fmt.Errorf("in-process resolver returned no answer for the health record")
			}
			return "health record served from the snapshot", nil
		})
		run("answer-cache", func() (string, error) {
			if ansCache == nil {
				return "disabled", nil
			}
			cs := ansCache.Stats()
			return fmt.Sprintf("enabled: %d/%d entries, %d lookups", cs.Entries, cs.Capacity, cs.Hits+cs.Misses), nil
		})
		return out
	})
	// DDNS dry-run simulator (works even when DDNS is disabled): show the Cloudflare API
	// calls write-back WOULD make for a host announcement, without making them.
	ddnsElig := map[string]bool{}
	for _, e := range cfg.DDNS.Eligible {
		ddnsElig[strings.TrimSuffix(strings.ToLower(e), ".")] = true
	}
	ddnsSimCfg := ddns.Config{Enabled: cfg.DDNS.Enabled, DryRun: cfg.DDNS.DryRun, Eligible: ddnsElig}
	diagSrv.WithDDNSSimulate(func(sctx context.Context, host string, addrs []netip.Addr, ignoreEligible bool) ddns.SimResult {
		return ddns.Simulate(sctx, ddnsSimCfg, mirror.SnapshotSource{Get: st.snapshot.Load}, ddns.Change{Host: host, Addrs: addrs}, ignoreEligible)
	})

	if cfg.Diag.AllowControl {
		pw := cfg.Diag.ControlPassword
		if cfg.Diag.ControlPasswordFile != "" {
			if b, perr := os.ReadFile(cfg.Diag.ControlPasswordFile); perr != nil {
				slog.Warn("diag control_password_file unreadable; controls will require loopback", "err", perr)
			} else {
				pw = strings.TrimSpace(string(b))
			}
		}
		diagSrv.WithControls(diag.Controls{
			AllowControl: true,
			Password:     pw,
			FlushCache: func() {
				if ansCache != nil {
					ansCache.Flush()
				}
			},
			RefreshMirror: func() { sup.ForceRestart("mirror") },
			Restart:       requestRestart,
			SetBackend:    fwd.SetBackendEnabled,
			ResetBackends: fwd.ResetBackends,
		})
		slog.Warn("diag control actions ENABLED", "password_set", pw != "")
	}
	// The diagnostics endpoint is BEST-EFFORT and non-critical: :53 is already serving
	// by now (srv.Start above), so a diag bind failure — a missing/!writable socket
	// directory, a stale socket, a permission error on a shared reverse-proxy path — is
	// logged and otherwise ignored. DNS service is never affected by losing diagnostics.
	if derr := diagSrv.Start(ctx); derr != nil {
		slog.Warn("diag endpoint unavailable — continuing; DNS service is unaffected", "addr", cfg.Diag.Addr, "err", derr)
	} else {
		slog.Info("diag endpoint serving", "addr", diagSrv.Addr())
	}

	slog.Info("splitdnsd serving",
		"version", version,
		"listen", listen,
		"reverse_zones", revZones,
		"upstreams", cfg.Upstream.Servers,
		"ddns_enabled", cfg.DDNS.Enabled)

	<-ctx.Done()
	slog.Info("splitdnsd shutting down")

	// Shutdown watchdog. We hold no state that must persist on exit (the DDNS audit log
	// is flushed per write, the warm cache is saved after each refresh), so an orderly
	// shutdown is a nicety, not a requirement. Attempt it, but never let a wedged
	// connection — e.g. a half-open diag client, which makes http.Server.Shutdown wait
	// indefinitely — keep the process alive past the stop deadline. If graceful shutdown
	// stalls, log LOUDLY, dump goroutines so the hang is diagnosable after the fact, and
	// kill the process so systemd's stop succeeds instead of waiting for SIGKILL.
	shutdownWithDeadline(shutdownGrace, func() {
		// Bound the diag HTTP shutdown explicitly (its context was previously
		// context.Background(), i.e. unbounded — the source of the stop hang).
		dctx, cancel := context.WithTimeout(context.Background(), diagShutdownBound)
		defer cancel()
		diagSrv.Shutdown(dctx)
		srv.Shutdown()
	})
}

const (
	// shutdownGrace is the overall budget for graceful shutdown before we force-exit.
	shutdownGrace = 5 * time.Second
	// diagShutdownBound caps the diag HTTP graceful shutdown specifically.
	diagShutdownBound = 3 * time.Second
)

// shutdownWithDeadline runs shut() and returns when it completes, unless that takes
// longer than grace — in which case it logs a loud error, dumps all goroutine stacks
// to stderr (so a shutdown hang can be investigated from the journal), and force-exits.
// Split out from main and parameterized only via package-level os.Exit so it stays unit
// testable (see main_test.go, which exercises both the clean and the stalled paths).
func shutdownWithDeadline(grace time.Duration, shut func()) {
	done := make(chan struct{})
	go func() { shut(); close(done) }()
	select {
	case <-done:
	case <-time.After(grace):
		slog.Error("graceful shutdown stalled past deadline; forcing exit — INVESTIGATE the goroutine dump below",
			"deadline", grace)
		dumpGoroutines()
		osExit(1)
	}
}

// dumpGoroutines writes every goroutine's stack to stderr (the journal) so a wedged
// shutdown leaves evidence of what was stuck. It is a var so tests can stub it.
var dumpGoroutines = func() {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	os.Stderr.Write(buf[:n])
}

// osExit is a seam so tests can observe the force-exit without terminating the test
// binary; production points it at os.Exit.
var osExit = os.Exit

// buildWriter wires the DDNS writer: it reads current records from the supplied
// source (the in-memory mirror snapshot) and writes via the DNS:Edit token. NOTE:
// hardened token handling (LoadCredential/tmpfs, owner==daemon-uid, symlink refusal
// per §security) is a later step; here we read the configured 0400 file directly.
func buildWriter(cfg config.Config, recSrc ddns.RecordSource) (*ddns.Writer, error) {
	editTok, err := os.ReadFile(cfg.Cloudflare.EditTokenFile)
	if err != nil {
		return nil, fmt.Errorf("edit token: %w", err)
	}
	editor := cfapi.New(cfg.Cloudflare.BaseURL, strings.TrimSpace(string(editTok)), nil)
	rate, _ := cfg.DDNS.RateDuration()
	elig := map[string]bool{}
	for _, e := range cfg.DDNS.Eligible {
		elig[strings.TrimSuffix(strings.ToLower(e), ".")] = true
	}
	return ddns.New(ddns.Config{
		Enabled: true, DryRun: cfg.DDNS.DryRun, Rate: rate, Eligible: elig,
		TokenID: "cf-edit", GlobalBurst: 8, GlobalRefill: rate,
	}, recSrc, editor, nil, nil, func(m string) { slog.Warn(m) }), nil
}
