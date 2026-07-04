package mdns

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// announce builds a minimal mDNS response advertising host.local -> ip.
func odAnnounce(host, ip string) []byte {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: host + ".local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
		A:   net.ParseIP(ip),
	}}
	b, _ := m.Pack()
	return b
}

func TestOnDemandCompletion(t *testing.T) {
	src := NewSource(nil, nil, WithOnDemand(500*time.Millisecond))
	var sent int32
	src.SetSender(func([]byte) { atomic.AddInt32(&sent, 1) })

	go func() {
		time.Sleep(30 * time.Millisecond)
		src.HandlePacket(odAnnounce("printer", "10.0.0.9"), false)
	}()
	if !src.Resolve(context.Background(), "printer", netip.Addr{}) {
		t.Error("Resolve should report the host appeared")
	}
	if n := atomic.LoadInt32(&sent); n != 1 {
		t.Errorf("queries sent = %d, want 1", n)
	}
}

func TestOnDemandTimeout(t *testing.T) {
	src := NewSource(nil, nil, WithOnDemand(60*time.Millisecond))
	var sent int32
	src.SetSender(func([]byte) { atomic.AddInt32(&sent, 1) })
	if src.Resolve(context.Background(), "ghost", netip.Addr{}) {
		t.Error("Resolve should time out with no reply")
	}
	if n := atomic.LoadInt32(&sent); n != 1 {
		t.Errorf("queries sent = %d, want 1", n)
	}
}

// N concurrent callers for the same host emit ONE query and all wake on completion.
func TestOnDemandSingleFlight(t *testing.T) {
	src := NewSource(nil, nil, WithOnDemand(500*time.Millisecond))
	var sent int32
	src.SetSender(func([]byte) { atomic.AddInt32(&sent, 1) })

	var wg sync.WaitGroup
	res := make([]bool, 6)
	for i := range res {
		wg.Add(1)
		go func(i int) { defer wg.Done(); res[i] = src.Resolve(context.Background(), "nas", netip.Addr{}) }(i)
	}
	time.Sleep(40 * time.Millisecond)
	src.HandlePacket(odAnnounce("nas", "10.0.0.5"), false)
	wg.Wait()

	if n := atomic.LoadInt32(&sent); n != 1 {
		t.Errorf("single-flight: queries sent = %d, want 1", n)
	}
	for i, r := range res {
		if !r {
			t.Errorf("waiter %d got false", i)
		}
	}
}

// A second miss for the same name within the window emits no second query.
func TestOnDemandSuppression(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	src := NewSource(nil, func() time.Time { return now }, WithOnDemand(40*time.Millisecond))
	var sent int32
	src.SetSender(func([]byte) { atomic.AddInt32(&sent, 1) })
	src.Resolve(context.Background(), "x", netip.Addr{}) // sends, then times out
	src.Resolve(context.Background(), "x", netip.Addr{}) // suppressed (recently queried)
	if n := atomic.LoadInt32(&sent); n != 1 {
		t.Errorf("suppression: queries sent = %d, want 1", n)
	}
	if st := src.OnDemandStats(); st.Emitted != 1 || st.Suppressed != 1 {
		t.Errorf("stats = %+v, want emitted 1 suppressed 1", st)
	}
}

func TestOnDemandDisabled(t *testing.T) {
	src := NewSource(nil, nil) // no WithOnDemand
	src.SetSender(func([]byte) { t.Error("disabled on-demand must not send") })
	if src.Resolve(context.Background(), "x", netip.Addr{}) {
		t.Error("disabled Resolve must return false")
	}
	if src.OnDemandStats().Enabled {
		t.Error("stats should report disabled")
	}
}

func TestODBucket(t *testing.T) {
	b := &odBucket{}
	now := time.Unix(1_000_000, 0)
	n := 0
	for i := 0; i < 5; i++ { // starts full → burst of 3
		if b.allow(now, 1, 3) {
			n++
		}
	}
	if n != 3 {
		t.Errorf("burst allowed %d, want 3", n)
	}
	now = now.Add(2 * time.Second) // refill 2 tokens at 1/s
	m := 0
	for i := 0; i < 5; i++ {
		if b.allow(now, 1, 3) {
			m++
		}
	}
	if m != 2 {
		t.Errorf("post-refill allowed %d, want 2", m)
	}
}
