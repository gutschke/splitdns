package revzone

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestPrefixSetChanged(t *testing.T) {
	a := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}
	b := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}
	if PrefixSetChanged(a, b) {
		t.Fatal("identical sets reported as changed")
	}
	c := []netip.Prefix{netip.MustParsePrefix("2001:db8:abcd:1200::/64")}
	if !PrefixSetChanged(a, c) {
		t.Fatal("different sets reported as unchanged")
	}
}

// TestWatcherFiresOnChange simulates a DYNAMIC GUA prefix changing under the
// watcher and asserts onChange fires once on first scan and again on the change,
// but not on a repeat of the same set.
func TestWatcherFiresOnChange(t *testing.T) {
	seq := [][]netip.Prefix{
		{netip.MustParsePrefix("2001:db8:1::/64")},  // initial GUA
		{netip.MustParsePrefix("2001:db8:1::/64")},  // unchanged -> no fire
		{netip.MustParsePrefix("2001:db8:99::/64")}, // ISP changed prefix -> fire
	}
	var mu sync.Mutex
	i := 0
	scan := func() ([]netip.Prefix, error) {
		mu.Lock()
		defer mu.Unlock()
		p := seq[i]
		if i < len(seq)-1 {
			i++
		}
		return append([]netip.Prefix(nil), p...), nil
	}
	var got [][]netip.Prefix
	var gmu sync.Mutex
	onChange := func(p []netip.Prefix) {
		gmu.Lock()
		got = append(got, p)
		gmu.Unlock()
	}
	w := NewWatcher(scan, 5*time.Millisecond, onChange, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	w.Run(ctx)

	gmu.Lock()
	defer gmu.Unlock()
	if len(got) != 2 {
		t.Fatalf("onChange fired %d times, want 2 (initial + one change); got=%v", len(got), got)
	}
	if got[0][0].String() != "2001:db8:1::/64" || got[1][0].String() != "2001:db8:99::/64" {
		t.Fatalf("unexpected change sequence: %v", got)
	}
}

// TestClassifyAndFilterScopes pins the pure detection core: a host with a
// private /16, a ULA /64, and a GUA /64 yields the right prefixes per scope, and
// loopback/link-local are always dropped.
func TestClassifyAndFilterScopes(t *testing.T) {
	addrs := []net.Addr{
		ipnet("192.168.5.125/24"),           // RFC1918 private (generic)
		ipnet("fd2c:1a2b:3c4d::125/64"),     // ULA private
		ipnet("2001:db8:abcd:1200::125/64"), // global-unicast (doc range)
		ipnet("127.0.0.1/8"),                // loopback -> always dropped
		ipnet("fe80::1/64"),                 // link-local -> always dropped
		ipnet("169.254.1.1/16"),             // link-local -> always dropped
	}
	count := func(scope string) int { return len(classifyAndFilter(addrs, scope)) }
	if n := count(ScopeOff); n != 0 {
		t.Errorf("ScopeOff = %d, want 0", n)
	}
	if n := count(ScopePrivate); n != 2 { // /16 + ULA /64
		t.Errorf("ScopePrivate = %d, want 2", n)
	}
	if n := count(ScopeGlobal); n != 1 { // GUA /64 only
		t.Errorf("ScopeGlobal = %d, want 1", n)
	}
	if n := count(ScopeAll); n != 3 {
		t.Errorf("ScopeAll = %d, want 3", n)
	}
}

func TestContains(t *testing.T) {
	parent := "d.4.c.3.b.2.a.1.c.2.d.f.ip6.arpa."
	child := "0.0.0.0.d.4.c.3.b.2.a.1.c.2.d.f.ip6.arpa." // a /64 inside the /48
	if !Contains(parent, child) {
		t.Error("a /64 inside the /48 should be Contains()=true (so it is deduped)")
	}
	if Contains(child, parent) {
		t.Error("parent is not contained in child")
	}
	if !Contains(parent, parent) {
		t.Error("a zone contains itself")
	}
}

func ipnet(cidr string) *net.IPNet {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	n.IP = ip // keep the host address so AddrFromSlice sees the real IP
	return n
}
