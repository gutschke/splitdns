package mdns

import (
	"testing"
	"time"

	"github.com/gutschke/splitdns/internal/model"
)

// fwd maps a host's view addresses to their trust tag (content -> Trusted).
func fwd(v *model.MDNSView, host string) map[string]bool {
	out := map[string]bool{}
	for _, r := range v.Forward[host] {
		out[r.Content] = r.Trusted
	}
	return out
}

func ann(host string, ttl uint32, addrs ...string) Announcement {
	return Announcement{Host: host, Addrs: ma(addrs...), TTL: ttl}
}

// TestTrustWeakNotPersistent: a source-IP (weak) announcement updates the volatile view and
// may trigger DDNS, but earns NO trusted-store entry — so it expires on the liveness clock.
func TestTrustWeakNotPersistent(t *testing.T) {
	c := NewCache(nil)
	t0 := time.Unix(1000, 0)
	c.Apply(ann("hestia", 120, "10.0.0.40"), t0, TrustWeak)
	if got := fwd(c.View(t0), "hestia"); got["10.0.0.40"] != false {
		t.Fatalf("weak announce should be self-announced (Trusted=false), got %v", got)
	}
	// After the volatile entry expires there is nothing left — weak trust is not persistent.
	c.Expire(t0.Add(10 * time.Minute))
	if got := fwd(c.View(t0.Add(10*time.Minute)), "hestia"); len(got) != 0 {
		t.Fatalf("weak entry must not persist after expiry, got %v", got)
	}
}

// TestTrustStrongPersists: a strong (TSIG/peer-cred) allocation survives host-down — the
// volatile entry expires but the trusted store keeps serving it, tagged Trusted.
func TestTrustStrongPersists(t *testing.T) {
	c := NewCache(nil) // trustedGrace 0 => hold until withdrawal
	t0 := time.Unix(2000, 0)
	c.Apply(ann("hestia", 120, "10.0.0.40"), t0, TrustStrong)
	c.Expire(t0.Add(time.Hour)) // volatile long gone
	got := fwd(c.View(t0.Add(time.Hour)), "hestia")
	if got["10.0.0.40"] != true || len(got) != 1 {
		t.Fatalf("trusted allocation must persist as Trusted=true when down, got %v", got)
	}
}

// TestTrustSpoofedGoodbyeImmune: an untrusted goodbye/announcement can neither remove nor
// downgrade a trusted address (closes the spoofed-goodbye DoS on a static host).
func TestTrustSpoofedGoodbyeImmune(t *testing.T) {
	c := NewCache(nil)
	c.goodbyeGrace = 5 * time.Minute
	t0 := time.Unix(3000, 0)
	c.Apply(ann("hestia", 120, "10.0.0.40"), t0, TrustStrong)
	// Attacker: an untrusted goodbye (TTL=0) for the same host.
	c.Apply(ann("hestia", 0, "10.0.0.40"), t0.Add(10*time.Second), TrustNone)
	c.Expire(t0.Add(time.Hour))
	got := fwd(c.View(t0.Add(time.Hour)), "hestia")
	if got["10.0.0.40"] != true {
		t.Fatalf("untrusted goodbye must not evict the trusted address, got %v", got)
	}
}

// TestTrustPerAddress: a self-announced spoof for a trusted host is tagged self-announced and
// never launders into trust; the trusted address stays trusted alongside it.
func TestTrustPerAddress(t *testing.T) {
	c := NewCache(nil)
	t0 := time.Unix(4000, 0)
	c.Apply(ann("hestia", 120, "10.0.0.40"), t0, TrustStrong)
	c.Apply(ann("hestia", 120, "6.6.6.6"), t0.Add(10*time.Second), TrustNone) // outside burst
	got := fwd(c.View(t0.Add(11*time.Second)), "hestia")
	if got["10.0.0.40"] != true {
		t.Fatalf("trusted address lost its tag: %v", got)
	}
	if trusted, ok := got["6.6.6.6"]; !ok || trusted {
		t.Fatalf("self-announced spoof must be present and untrusted, got %v", got)
	}
}

// TestTrustWithdrawal: a strong goodbye (TTL=0) withdraws the trusted allocation.
func TestTrustWithdrawal(t *testing.T) {
	c := NewCache(nil)
	t0 := time.Unix(5000, 0)
	c.Apply(ann("hestia", 120, "10.0.0.40"), t0, TrustStrong)
	c.Apply(ann("hestia", 0, "10.0.0.40"), t0.Add(10*time.Second), TrustStrong) // trusted withdrawal
	c.Expire(t0.Add(time.Hour))
	if got := fwd(c.View(t0.Add(time.Hour)), "hestia"); len(got) != 0 {
		t.Fatalf("trusted withdrawal must remove the allocation, got %v", got)
	}
}

// TestTrustReconcileRenumber: a fresh strong announcement (outside the burst window) REPLACES
// the trusted set, so a renumber drops the old address.
func TestTrustReconcileRenumber(t *testing.T) {
	c := NewCache(nil)
	t0 := time.Unix(6000, 0)
	c.Apply(ann("hestia", 120, "10.0.0.40"), t0, TrustStrong)
	c.Apply(ann("hestia", 120, "10.0.0.50"), t0.Add(time.Minute), TrustStrong)
	got := fwd(c.View(t0.Add(time.Minute)), "hestia")
	if got["10.0.0.50"] != true || len(got) != 1 {
		t.Fatalf("renumber must reconcile to the new trusted address only, got %v", got)
	}
}

// TestTrustMaxBound: the trusted store honors maxTrusted, evicting the oldest to admit a new
// host (a name flood cannot grow it without limit).
func TestTrustMaxBound(t *testing.T) {
	c := NewCache(nil)
	c.maxTrusted = 2
	t0 := time.Unix(7000, 0)
	c.Apply(ann("a", 120, "10.0.0.1"), t0, TrustStrong)
	c.Apply(ann("b", 120, "10.0.0.2"), t0.Add(time.Second), TrustStrong)
	c.Apply(ann("cc", 120, "10.0.0.3"), t0.Add(2*time.Second), TrustStrong) // evicts oldest (a)
	c.mu.Lock()
	n := len(c.trusted)
	_, hasA := c.trusted["a"]
	c.mu.Unlock()
	if n != 2 || hasA {
		t.Fatalf("maxTrusted=2 must evict oldest; len=%d hasA=%v", n, hasA)
	}
}

// TestTrustGraceCap: with a finite trustedGrace, an unrefreshed trusted entry is dropped after
// the cap (backstop for a trusted channel that vanished without a withdrawal).
func TestTrustGraceCap(t *testing.T) {
	c := NewCache(nil)
	c.trustedGrace = time.Hour
	t0 := time.Unix(8000, 0)
	c.Apply(ann("hestia", 120, "10.0.0.40"), t0, TrustStrong)
	c.Expire(t0.Add(2 * time.Hour)) // past the cap
	if got := fwd(c.View(t0.Add(2*time.Hour)), "hestia"); len(got) != 0 {
		t.Fatalf("trusted entry must drop past trustedGrace, got %v", got)
	}
}
