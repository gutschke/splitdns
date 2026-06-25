// Package netnstest is the network-namespace test harness (design S24). It runs an
// e2e test package inside an unprivileged user+network namespace (`unshare -Urn`),
// so the real binary/components are exercised against in-namespace mocks with
// egress STRUCTURALLY impossible — a fresh netns has only loopback, no route to the
// host or the internet. This is the load-bearing guarantee for the project's #1
// constraint: tests can never touch the production resolver or Cloudflare.
//
// Usage: a dedicated e2e test package provides
//
//	func TestMain(m *testing.M) { netnstest.RunMain(m) }
//
// and its tests call netnstest.RequireIsolated(t). When namespaces are unavailable
// (CI without userns, restrictive seccomp), the package skips cleanly.
package netnstest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

const (
	markerEnv = "SPLITDNS_NETNS_ACTIVE" // set on the re-exec'd child
	parentEnv = "SPLITDNS_NETNS_PARENT" // parent's netns inode, for the isolation check

	// IfName is the dummy, multicast-capable interface configured in the namespace.
	// It has an address but no path off-host, so multicast/mDNS code has a NIC to bind
	// and join without any egress.
	IfName = "mdns0"
	// IfAddr is the address assigned to IfName.
	IfAddr = "10.123.0.1/24"
)

// RunMain is the TestMain entry point. Outside the namespace it re-execs the test
// binary under `unshare -Urn` and forwards the exit code (skipping cleanly when
// namespaces are unavailable). Inside, it verifies isolation, configures the
// namespace, and runs the tests.
func RunMain(m *testing.M) {
	if os.Getenv(markerEnv) == "1" {
		if err := enterChild(); err != nil {
			fmt.Fprintln(os.Stderr, "netnstest:", err)
			os.Exit(1)
		}
		os.Exit(m.Run())
	}
	os.Exit(reexec())
}

// reexec relaunches this test binary inside a fresh user+net namespace.
func reexec() int {
	if _, err := exec.LookPath("unshare"); err != nil {
		fmt.Fprintln(os.Stderr, "netnstest: unshare unavailable; skipping netns e2e")
		return 0
	}
	// Probe whether an unprivileged user+net namespace can actually be created here.
	// On many CI runners userns uid-mapping is restricted (`unshare: write failed
	// /proc/self/uid_map: Operation not permitted`), and unshare then exits non-zero
	// BEFORE exec'ing the test binary — indistinguishable by exit code from a genuine
	// test failure. Probing first lets a missing capability SKIP cleanly. The probe
	// mirrors the real flags so it fails iff the real re-exec would.
	if err := exec.Command("unshare", "-Urn", "--", "true").Run(); err != nil {
		fmt.Fprintln(os.Stderr, "netnstest: user+net namespaces unavailable here ("+err.Error()+"); skipping netns e2e")
		return 0
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "netnstest: os.Executable:", err)
		return 1
	}
	parent, _ := os.Readlink("/proc/self/ns/net")

	args := append([]string{"-Urn", "--", exe}, os.Args[1:]...)
	cmd := exec.Command("unshare", args...)
	cmd.Env = append(os.Environ(), markerEnv+"=1", parentEnv+"="+parent)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	err = cmd.Run()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	// Could not create the namespace (userns disabled, seccomp, etc.). Skip rather
	// than fail the whole build — these are best-effort e2e gates.
	fmt.Fprintln(os.Stderr, "netnstest: cannot create netns ("+err.Error()+"); skipping")
	return 0
}

// enterChild runs the isolation pre-flight and configures the namespace.
func enterChild() error {
	// Same-inode pre-flight (S24): our netns MUST differ from the parent's. If they
	// match, the unshare did not take effect and we could be about to reconfigure /
	// drop egress on the REAL host network — refuse to touch anything.
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("read self netns: %w", err)
	}
	if parent := os.Getenv(parentEnv); parent != "" && parent == self {
		return fmt.Errorf("ABORT: netns inode %s == parent — not isolated, refusing to configure networking", self)
	}
	return setup()
}

// setup brings up loopback and a dummy multicast NIC. No default route is added, so
// egress stays impossible.
func setup() error {
	for _, c := range [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "add", IfName, "type", "dummy"},
		{"ip", "link", "set", IfName, "multicast", "on"}, // dummies aren't multicast by default
		{"ip", "link", "set", IfName, "up"},
		{"ip", "addr", "add", IfAddr, "dev", IfName},
	} {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("setup %v: %w: %s", c, err, out)
		}
	}
	return nil
}

// RequireIsolated skips the test unless it is running inside the harness namespace
// (so a stray direct invocation without RunMain does not run e2e logic on the host).
func RequireIsolated(t *testing.T) {
	t.Helper()
	if os.Getenv(markerEnv) != "1" {
		t.Skip("netnstest: not inside an isolated network namespace")
	}
}
