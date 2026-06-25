// Package bincover is the end-to-end coverage gate (design S32). It builds the REAL
// splitdnsd binary with coverage instrumentation, runs it against in-process mock
// edges (no egress), drives queries that exercise the full pipeline, SIGTERMs it to
// flush GOCOVERDIR, and asserts that the named load-bearing targets were actually
// reached by the compiled binary — and fails if one disappears (renamed/deleted).
//
// This is the only test that exercises cmd/splitdnsd/main.go (the wiring) and the
// mirror→serve path inside the actual binary. It is slow (it compiles the binary), so
// it is skipped under -short; run it via `make test-e2e-cover`.
package bincover

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/mockedge"
)

// namedTargets are the load-bearing functions the binary e2e must exercise. If a name
// vanishes from the coverage profile it has been renamed/removed — the gate fails so
// the harness is updated deliberately. (The rebind filter is covered by the unit /
// integration / chaos suites; it is not reachable through the binary's DoT-only
// forwarder without a privileged port, so it is intentionally not asserted here.)
var namedTargets = []string{
	"Resolve",             // router / query classifier (internal/resolver)
	"answerAuthoritative", // authoritative answer assembler (internal/resolver)
	"BuildZone",           // mirror zone build incl. tunnel flattening (internal/mirror)
	"ServeDNS",            // :53 front end (internal/server)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

func TestBinaryCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("bincover builds and runs the real binary; skipped in -short")
	}
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		t.Skipf("go toolchain not found at %s", goBin)
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()

	// 1. Build the real binary with coverage instrumentation.
	bin := filepath.Join(tmp, "splitdnsd.cover")
	build := exec.Command(goBin, "build", "-cover", "-mod=vendor", "-o", bin, "./cmd/splitdnsd")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build -cover: %v\n%s", err, out)
	}

	// 2. Mock Cloudflare with a regular record + a cfargotunnel CNAME (exercises the
	//    mirror's tunnel-flatten path at build time).
	cf := mockedge.NewCloudflare("tok")
	cf.AddZone("z1", "example.test")
	cf.Seed("z1", mockedge.CFRecord{Type: "A", Name: "host.example.test", Content: "203.0.113.10", TTL: 300})
	cf.Seed("z1", mockedge.CFRecord{Type: "CNAME", Name: "app.example.test", Content: "abc.cfargotunnel.com", Proxied: true, TTL: 300})
	cfSrv := cf.Start()
	defer cfSrv.Close()

	// 3. Mock upstream DNS: the bootstrap SOA fetcher uses plain UDP, so answering the
	//    zone's SOA serial here is what makes the mirror actually build.
	up, err := mockedge.NewDNS()
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	up.SetSOASerial("example.test", 2024010100)

	// 4. Config + token file, everything pointed at localhost (no egress).
	lport := freePort(t)
	dport := freePort(t)
	tokFile := filepath.Join(tmp, "cf.token")
	if err := os.WriteFile(tokFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(tmp, "splitdnsd.toml")
	cfg := "" +
		"[listen]\nmode=\"explicit\"\naddresses=[\"127.0.0.1:" + strconv.Itoa(lport) + "\"]\nudp=true\ntcp=true\n" +
		"[access]\nallow=[\"127.0.0.0/8\"]\n" +
		"[upstream]\nservers=[\"" + up.Addr() + "\"]\ncleartext_fallback=false\n" +
		"[zones]\nlocal=[\"example.test\"]\nreverse=[\"2.0.192.in-addr.arpa.\"]\n" +
		"[cloudflare]\nread_token_file=\"" + tokFile + "\"\nbase_url=\"" + cfSrv.URL + "\"\n" +
		"[diag]\naddr=\"127.0.0.1:" + strconv.Itoa(dport) + "\"\n" +
		"[cache]\ndir=\"" + tmp + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// 5. Run the binary with GOCOVERDIR set.
	covDir := filepath.Join(tmp, "covdata")
	if err := os.Mkdir(covDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	run := exec.CommandContext(ctx, bin, "-config", cfgPath)
	run.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOCOVERDIR="+covDir)
	var logs strings.Builder
	run.Stdout, run.Stderr = &logs, &logs
	if err := run.Start(); err != nil {
		t.Fatalf("start binary: %v", err)
	}

	server := "127.0.0.1:" + strconv.Itoa(lport)
	query := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
		resp, _, err := c.Exchange(m, server)
		if err != nil {
			return nil
		}
		return resp
	}

	// 6. Wait until the mirror has built (authoritative answer for the CF zone), which
	//    confirms the cfapi/builder/BuildZone path ran in the binary.
	deadline := time.Now().Add(20 * time.Second)
	built := false
	for time.Now().Before(deadline) {
		if resp := query("host.example.test", dns.TypeA); resp != nil && resp.Authoritative && len(resp.Answer) == 1 {
			built = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !built {
		run.Process.Signal(syscall.SIGTERM)
		run.Wait()
		t.Fatalf("mirror never served the authoritative CF zone; binary logs:\n%s", logs.String())
	}

	// 7. Drive the rest of the pipeline.
	query("example.test", dns.TypeSOA)           // authoritative SOA
	query("app.example.test", dns.TypeA)         // tunnel owner (flatten attempted at build)
	query("health.splitdnsd.local", dns.TypeA)   // static special
	query("unknown.local", dns.TypeA)            // *.local path
	query("1.2.0.192.in-addr.arpa", dns.TypePTR) // reverse path
	query("example.org", dns.TypeA)              // forward path (SERVFAILs, no egress)
	query("example.test", dns.TypeANY)           // minimal-ANY / assembler

	// 8. Graceful shutdown flushes the coverage profile.
	if err := run.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- run.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		run.Process.Kill()
		t.Fatalf("binary did not exit on SIGTERM; logs:\n%s", logs.String())
	}

	// 9. Read the coverage profile and assert the named targets were reached.
	cov := exec.Command(goBin, "tool", "covdata", "func", "-i="+covDir)
	cov.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	covOut, err := cov.CombinedOutput()
	if err != nil {
		t.Fatalf("covdata func: %v\n%s", err, covOut)
	}
	report := string(covOut)

	// main.go wiring must be exercised (nothing else covers it).
	if !strings.Contains(report, "cmd/splitdnsd/main.go") {
		t.Errorf("cmd/splitdnsd was not covered by the binary e2e")
	}
	for _, target := range namedTargets {
		if !targetCovered(report, target) {
			t.Errorf("named target %q was not present-and-covered in the binary e2e "+
				"(renamed/removed, or not exercised) — update the harness deliberately", target)
		}
	}
	if t.Failed() {
		t.Logf("covdata report:\n%s", report)
	}
}

// targetCovered reports whether a function named target appears in the covdata `func`
// report with non-zero coverage. Lines look like:
//
//	github.com/gutschke/splitdns/internal/resolver/resolver.go:29:  Resolve  87.5%
func targetCovered(report, target string) bool {
	for _, line := range strings.Split(report, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// fields: <file:line:col> <FuncName> <NN.N%>. FuncName may be a method form
		// like "*Server.ServeDNS", so match the bare name or the ".<name>" suffix.
		fn := fields[len(fields)-2]
		if fn != target && !strings.HasSuffix(fn, "."+target) {
			continue
		}
		pct := strings.TrimSuffix(fields[len(fields)-1], "%")
		if v, err := strconv.ParseFloat(pct, 64); err == nil && v > 0 {
			return true
		}
	}
	return false
}
