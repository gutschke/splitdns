// Command splitdnsd is a standalone split-horizon DNS resolver for a trusted LAN.
// It wires the two atomic.Pointer planes (Snapshot for zones, MDNSView for *.local)
// that the hot path reads, parses flags, installs signal handling, and starts the
// listeners, control-plane workers, and forwarder. See ARCHITECTURE.md.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/gutschke/splitdns/internal/encrypted"
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
	ddr      atomic.Pointer[model.DDRAdvert] // current DDR advert (nil => resolver.arpa NODATA)
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
		if cfg.Encrypted.Enabled {
			if cfg.Encrypted.DoT.Enabled {
				if a, e := encListenAddrs(cfg, cfg.Encrypted.DoT.Port); e == nil {
					fmt.Printf("encrypted DoT: %v\n", a)
				}
			}
			if cfg.Encrypted.DoH.Enabled {
				if a, e := encListenAddrs(cfg, cfg.Encrypted.DoH.Port); e == nil {
					fmt.Printf("encrypted DoH: %v path=%s\n", a, cfg.Encrypted.DoH.Path)
				}
			}
			// The cert was already parsed+expiry-checked by config.Load()'s Validate().
			cert, _ := cfg.Encrypted.LoadCert()
			fmt.Printf("encrypted adn=%s cert=%s (expires %s) advertise_ddr=%v\n",
				cfg.Encrypted.ADN, cfg.Encrypted.CertFile, cert.Leaf.NotAfter.Format(time.RFC3339), cfg.Encrypted.AdvertiseDDR)
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
	}, nil, mdns.WithServeStale(cfg.MDNS.StaleGraceDuration(), cfg.MDNS.GoodbyeGraceDuration()))
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

	// Encrypted client front-end (DoT/DoH) + DDR advertising — OPT-IN, best-effort. A cert
	// or bind failure logs and skips the encrypted plane; Do53 is unaffected (fail-closed).
	// The advert is published only after listeners bind and the cert validates, and is
	// re-synced on cert reload (SIGHUP / mtime), so a client is never sent to a dead port.
	var encMgr *encrypted.Manager
	var encReloader *encrypted.CertReloader
	if cfg.Encrypted.Enabled {
		encMgr, encReloader = startEncrypted(ctx, cfg, srv, builder, &st.ddr)
	}

	// Tell systemd (Type=notify) that startup is complete and :53 is bound. Fired after the
	// best-effort encrypted start so an optional DoT/DoH bind failure can't wedge readiness.
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
	if ansCache != nil {
		diagSrv.WithCacheEntries(ansCache.Entries)
	}
	diagSrv.WithQueryLog(queryLog)
	diagSrv.WithBackends(fwd.Backends)
	diagSrv.WithWorkers(sup.Stats)
	if encMgr != nil {
		diagSrv.WithEncrypted(func() *diag.EncStatus {
			return buildEncStatus(cfg, encReloader, encMgr, &st.ddr, st.snapshot.Load, src.View)
		})
	}
	diagSrv.WithTransportQuery(makeTransportQuery(listen, encMgr, cfg))
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
		if encMgr != nil {
			encMgr.Shutdown(dctx) // stop accepting encrypted connections before Do53
		}
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

// startEncrypted brings up the opt-in DoT/DoH listeners and wires DDR advertising. It is
// best-effort: any cert/bind failure logs and it returns whatever came up (possibly nil),
// never blocking Do53. The DDR advert is (re)published only while a valid cert is loaded
// and is re-synced on cert reload (mtime poll + SIGHUP).
func startEncrypted(ctx context.Context, cfg config.Config, handler *server.Server, builder *mirror.Builder, ddr *atomic.Pointer[model.DDRAdvert]) (*encrypted.Manager, *encrypted.CertReloader) {
	ec := cfg.Encrypted
	reloader, err := encrypted.NewCertReloader(ec.CertFile, ec.KeyFile, func(m string) { slog.Warn(m) })
	if err != nil {
		slog.Error("encrypted: certificate unavailable — DoT/DoH disabled, Do53 unaffected", "err", err)
		return nil, nil
	}
	mgr := encrypted.NewManager(handler, reloader, func(m string) { slog.Info(m) })
	dotUp, dohUp := false, false
	if ec.DoT.Enabled {
		if addrs, aerr := encListenAddrs(cfg, ec.DoT.Port); aerr != nil {
			slog.Warn("encrypted: DoT address selection failed", "err", aerr)
		} else if serr := mgr.StartDoT(addrs); serr != nil {
			slog.Warn("encrypted: DoT listener failed — continuing without it", "err", serr)
		} else {
			dotUp = true
		}
	}
	if ec.DoH.Enabled {
		if addrs, aerr := encListenAddrs(cfg, ec.DoH.Port); aerr != nil {
			slog.Warn("encrypted: DoH address selection failed", "err", aerr)
		} else if serr := mgr.StartDoH(addrs, ec.DoH.Path); serr != nil {
			slog.Warn("encrypted: DoH listener failed — continuing without it", "err", serr)
		} else {
			dohUp = true
		}
	}
	if !dotUp && !dohUp {
		return nil, nil
	}

	if ec.AdvertiseDDR {
		v4, v6 := ddrHints(ec, mgr)
		builder.SetDDRProvider(func() *model.DDRAdvert { return ddr.Load() })
		resync := func() {
			var adv *model.DDRAdvert
			if reloader.Valid() { // withdraw the advert if the cert lapses (fail-closed)
				adv = &model.DDRAdvert{ADN: ec.ADNFqdn(), V4Hints: v4, V6Hints: v6}
				if dotUp {
					adv.DoT = &model.DDREndpoint{Port: uint16(ec.DoT.Port)}
				}
				if dohUp {
					adv.DoH = &model.DDREndpoint{Port: uint16(ec.DoH.Port), Path: ec.DoH.Path}
				}
			}
			ddr.Store(adv)
			builder.Republish()
		}
		resync()
		go reloader.Run(ctx, resync)
		go func() {
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					reloader.ReloadNow(resync)
				}
			}
		}()
	}
	return mgr, reloader
}

// buildEncStatus assembles the diagnostics view of the encrypted front-end + DDR: cert
// details, listeners, the SVCB actually served, and the upgrade-readiness checklist.
func buildEncStatus(cfg config.Config, rel *encrypted.CertReloader, mgr *encrypted.Manager, ddr *atomic.Pointer[model.DDRAdvert], snap func() *model.Snapshot, view func() *model.MDNSView) *diag.EncStatus {
	ec := cfg.Encrypted
	es := &diag.EncStatus{Enabled: ec.Enabled, ADN: ec.ADN, AdvertiseDDR: ec.AdvertiseDDR, DoHPath: ec.DoH.Path, CertValid: rel.Valid()}
	notAfter, sans, ok := rel.CertInfo()
	es.SANs = sans
	if ok {
		if d := time.Until(notAfter); d < 0 {
			es.Expiry = "EXPIRED " + notAfter.Format("2006-01-02")
		} else {
			es.Expiry = fmt.Sprintf("in %dd (%s)", int(d.Hours()/24), notAfter.Format("2006-01-02"))
		}
	}
	for _, a := range mgr.DoTAddrs() {
		es.DoT = append(es.DoT, a.String())
	}
	for _, a := range mgr.DoHAddrs() {
		es.DoH = append(es.DoH, a.String())
	}
	adv := ddr.Load()
	es.DDRReady = adv != nil
	if s := snap(); s != nil { // render the SVCB actually served (reuses the resolver)
		req := new(dns.Msg)
		req.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
		if out := resolver.Resolve(s, view(), req); out.Msg != nil {
			for _, rr := range out.Msg.Answer {
				es.SVCB = append(es.SVCB, rr.String())
			}
		}
	}
	adnOK := sanMatches(sans, ec.ADN)
	hints := adv != nil && (len(adv.V4Hints) > 0 || len(adv.V6Hints) > 0)
	es.Checks = []diag.EncCheck{
		{Name: "encrypted enabled", OK: ec.Enabled},
		{Name: "certificate valid & unexpired", OK: rel.Valid(), Detail: es.Expiry},
		{Name: "ADN matches a certificate SAN", OK: adnOK, Detail: ec.ADN},
		{Name: "DoT listener up", OK: len(es.DoT) > 0},
		{Name: "DoH listener up", OK: len(es.DoH) > 0},
		{Name: "DDR advertising (SVCB served)", OK: adv != nil},
		{Name: "ADN resolves to LAN address hints", OK: hints},
	}
	return es
}

// makeTransportQuery returns the diagnostics transport tester: it issues a query at THIS
// resolver over Do53/DoT/DoH and reports the answer plus the TLS handshake (so an operator
// can see exactly why a client fails to upgrade). Encrypted transports report "not enabled"
// when the front-end is off.
func makeTransportQuery(listen []string, mgr *encrypted.Manager, cfg config.Config) func(context.Context, string, string, string) diag.TransportResult {
	adn := cfg.Encrypted.ADN
	dohPath := cfg.Encrypted.DoH.Path
	do53 := queryTarget(listen)
	var dotAddr, dohAddr string
	if mgr != nil {
		if a := mgr.DoTAddrs(); len(a) > 0 {
			dotAddr = a[0].String()
		}
		if a := mgr.DoHAddrs(); len(a) > 0 {
			dohAddr = a[0].String()
		}
	}
	return func(ctx context.Context, transport, name, qtype string) diag.TransportResult {
		res := diag.TransportResult{Transport: transport, Query: name + "/" + qtype}
		qt := dns.StringToType[qtype]
		if qt == 0 {
			qt = dns.TypeA
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qt)
		start := time.Now()
		switch transport {
		case "do53", "udp":
			res.Target = do53
			resp, _, err := (&dns.Client{Net: "udp", Timeout: 4 * time.Second}).Exchange(m, do53)
			fillAnswer(&res, resp, err)
		case "tcp":
			res.Target = do53
			resp, _, err := (&dns.Client{Net: "tcp", Timeout: 4 * time.Second}).Exchange(m, do53)
			fillAnswer(&res, resp, err)
		case "dot":
			if dotAddr == "" {
				res.Err = "DoT listener not enabled"
				break
			}
			res.Target = dotAddr
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 4 * time.Second}, "tcp", dotAddr, &tls.Config{ServerName: adn, NextProtos: []string{"dot"}})
			if err != nil {
				res.Err = "TLS: " + err.Error()
				break
			}
			defer conn.Close()
			res.TLS = tlsSummary(conn.ConnectionState())
			resp, _, err := (&dns.Client{}).ExchangeWithConn(m, &dns.Conn{Conn: conn})
			fillAnswer(&res, resp, err)
		case "doh":
			if dohAddr == "" {
				res.Err = "DoH listener not enabled"
				break
			}
			u := "https://" + dohAddr + dohPath
			res.Target = u
			wire, _ := m.Pack()
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(wire))
			req.Header.Set("Content-Type", "application/dns-message")
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: adn}}}
			hr, err := client.Do(req)
			if err != nil {
				res.Err = err.Error()
				break
			}
			defer hr.Body.Close()
			if hr.TLS != nil {
				res.TLS = tlsSummary(*hr.TLS)
			}
			if hr.StatusCode != http.StatusOK {
				res.Err = "HTTP " + hr.Status
				break
			}
			body, _ := io.ReadAll(io.LimitReader(hr.Body, 65535))
			resp := new(dns.Msg)
			if e := resp.Unpack(body); e != nil {
				res.Err = "unpack: " + e.Error()
				break
			}
			fillAnswer(&res, resp, nil)
		default:
			res.Err = "unknown transport"
		}
		res.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
		return res
	}
}

func fillAnswer(res *diag.TransportResult, resp *dns.Msg, err error) {
	if err != nil {
		res.Err = err.Error()
		return
	}
	if resp == nil {
		res.Err = "no response"
		return
	}
	res.OK = true
	res.Rcode = dns.RcodeToString[resp.Rcode]
	for _, rr := range resp.Answer {
		res.Answer = append(res.Answer, rr.String())
	}
}

func tlsSummary(cs tls.ConnectionState) string {
	ver := map[uint16]string{tls.VersionTLS12: "TLS1.2", tls.VersionTLS13: "TLS1.3"}[cs.Version]
	if ver == "" {
		ver = fmt.Sprintf("0x%04x", cs.Version)
	}
	s := ver
	if cs.NegotiatedProtocol != "" {
		s += " alpn=" + cs.NegotiatedProtocol
	}
	if len(cs.PeerCertificates) > 0 {
		s += " cert=" + cs.PeerCertificates[0].Subject.CommonName
	}
	return s
}

// queryTarget picks a reachable address for the transport tester's Do53 query — a loopback
// listener if one is bound, else the first listen address.
func queryTarget(listen []string) string {
	for _, a := range listen {
		if ap, err := netip.ParseAddrPort(a); err == nil && ap.Addr().IsLoopback() {
			return a
		}
	}
	if len(listen) > 0 {
		return listen[0]
	}
	return "127.0.0.1:53"
}

// sanMatches reports whether adn is covered by one of the cert's SAN DNS names (exact or
// a single-label wildcard).
func sanMatches(sans []string, adn string) bool {
	adn = strings.TrimSuffix(strings.ToLower(adn), ".")
	for _, s := range sans {
		s = strings.TrimSuffix(strings.ToLower(s), ".")
		if s == adn {
			return true
		}
		if strings.HasPrefix(s, "*.") && strings.HasSuffix(adn, s[1:]) && strings.Count(adn, ".") == strings.Count(s, ".") {
			return true
		}
	}
	return false
}

// encListenAddrs resolves the encrypted front-end's bind set for one transport port.
// Unlike [listen], explicit encrypted addresses are bare IPs (the port comes from
// dot.port/doh.port), so we append it here; private-auto enumeration appends it already.
func encListenAddrs(cfg config.Config, port int) ([]string, error) {
	ec := cfg.Encrypted
	mode := ec.Mode
	if mode == "" {
		mode = cfg.Listen.Mode
	}
	if mode == "explicit" {
		out := make([]string, 0, len(ec.Addresses))
		for _, h := range ec.Addresses {
			out = append(out, net.JoinHostPort(h, strconv.Itoa(port)))
		}
		return out, nil
	}
	return netmatch.SelectListenAddrs(mode, ec.Addresses, port)
}

// ddrHints returns the DDR address hints (and thus the ADN A/AAAA) split by family: the
// explicit config override if set, else the encrypted listeners' own bound addresses,
// skipping loopback/unspecified.
func ddrHints(ec config.EncryptedConfig, mgr *encrypted.Manager) (v4, v6 []netip.Addr) {
	for _, s := range ec.IPv4Hint {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			v4 = append(v4, a)
		}
	}
	for _, s := range ec.IPv6Hint {
		if a, err := netip.ParseAddr(s); err == nil && a.Is6() && !a.Is4() {
			v6 = append(v6, a)
		}
	}
	if len(v4) > 0 || len(v6) > 0 {
		return v4, v6
	}
	seen := map[netip.Addr]bool{}
	for _, a := range mgr.BoundAddrs() {
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			continue
		}
		ip := ap.Addr().Unmap()
		if ip.IsLoopback() || ip.IsUnspecified() || seen[ip] {
			continue
		}
		seen[ip] = true
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return v4, v6
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
