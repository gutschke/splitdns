package server

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
)

type onDemandFunc func(context.Context, string, netip.Addr) bool

func (f onDemandFunc) Resolve(ctx context.Context, label string, client netip.Addr) bool {
	return f(ctx, label, client)
}

// A LocalMiss triggers OnDemand.Resolve, and the handler re-resolves against the reloaded
// view — so a host the solicitation "found" is served on the same request.
func TestOnDemandServesFoundHost(t *testing.T) {
	var mu sync.Mutex
	fwd := map[string][]model.RR{}
	snap := &model.Snapshot{LocalDomain: "lan"}
	var calls int32

	od := onDemandFunc(func(_ context.Context, label string, _ netip.Addr) bool {
		atomic.AddInt32(&calls, 1)
		mu.Lock() // simulate the quiet host answering the solicitation
		fwd[label] = []model.RR{{Type: dns.TypeA, Class: dns.ClassINET, TTL: 120, Content: "10.0.0.9"}}
		mu.Unlock()
		return true
	})
	s := New(Config{
		Access:   netmatch.Access{Allow: mustSet(t, "127.0.0.0/8")},
		Snapshot: func() *model.Snapshot { return snap },
		View: func() *model.MDNSView {
			mu.Lock()
			defer mu.Unlock()
			cp := map[string][]model.RR{}
			for k, v := range fwd {
				cp[k] = v
			}
			return &model.MDNSView{Forward: cp}
		},
		OnDemand: od,
	})
	if err := s.Start([]string{"127.0.0.1:0"}, true, false); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("printer.lan.", dns.TypeA)
	r, err := dns.Exchange(m, s.BoundAddrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("rcode=%d answers=%d, want NOERROR+1 (on-demand populated the view)", r.Rcode, len(r.Answer))
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("OnDemand.Resolve calls = %d, want 1", n)
	}
}

// When the solicitation finds nothing, the handler serves the plain NXDOMAIN.
func TestOnDemandMissStaysNXDOMAIN(t *testing.T) {
	snap := &model.Snapshot{LocalDomain: "lan"}
	var calls int32
	od := onDemandFunc(func(context.Context, string, netip.Addr) bool { atomic.AddInt32(&calls, 1); return false })
	s := New(Config{
		Access:   netmatch.Access{Allow: mustSet(t, "127.0.0.0/8")},
		Snapshot: func() *model.Snapshot { return snap },
		View:     func() *model.MDNSView { return &model.MDNSView{Forward: map[string][]model.RR{}} },
		OnDemand: od,
	})
	if err := s.Start([]string{"127.0.0.1:0"}, true, false); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("ghost.lan.", dns.TypeA)
	r, err := dns.Exchange(m, s.BoundAddrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeNameError {
		t.Errorf("rcode=%d, want NXDOMAIN", r.Rcode)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("OnDemand.Resolve calls = %d, want 1", n)
	}
}
