package forwarder

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// mockUpstream starts a loopback UDP DNS server that answers every A query with the
// given content, and returns its address plus a stop func.
func mockUpstream(t *testing.T, content string) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A " + content)
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	return pc.LocalAddr().String(), func() { srv.Shutdown() }
}

func queryA(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func TestForwardUDP(t *testing.T) {
	addr, stop := mockUpstream(t, "203.0.113.123")
	defer stop()

	f := NewWithUpstreams([]Upstream{{Addr: addr, Net: "udp"}}, nil, false, nil)
	resp, err := f.Forward(context.Background(), queryA("example.org."))
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "203.0.113.123" {
		t.Fatalf("unexpected answer: %v", resp.Answer)
	}
}

func TestCleartextFallback(t *testing.T) {
	addr, stop := mockUpstream(t, "203.0.113.7")
	defer stop()

	// Primary is a DoT endpoint that will fail (nothing listening / no TLS); the
	// cleartext UDP fallback must take over when enabled.
	dead := Upstream{Addr: "127.0.0.1:9", Net: "tcp-tls", ServerName: "nope.example"}
	f := NewWithUpstreams([]Upstream{dead}, []Upstream{{Addr: addr, Net: "udp"}}, true, nil)
	resp, err := f.Forward(context.Background(), queryA("example.org."))
	if err != nil {
		t.Fatalf("fallback Forward: %v", err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "203.0.113.7" {
		t.Fatalf("fallback unexpected answer: %v", resp.Answer)
	}

	// With cleartext disabled, the same dead DoT primary must error, not downgrade.
	f2 := NewWithUpstreams([]Upstream{dead}, []Upstream{{Addr: addr, Net: "udp"}}, false, nil)
	if _, err := f2.Forward(context.Background(), queryA("example.org.")); err == nil {
		t.Fatalf("cleartext disabled: expected error, got success")
	}
}

func TestForwardToStub(t *testing.T) {
	addr, stop := mockUpstream(t, "192.0.2.61")
	defer stop()
	f := NewWithUpstreams([]Upstream{{Addr: "127.0.0.1:9", Net: "udp"}}, nil, false, nil)
	resp, err := f.ForwardTo(context.Background(), []string{addr}, queryA("host.sub.example.com."))
	if err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("stub answer missing: %v", resp.Answer)
	}
}

func TestBuildDerivesDoTAndFallback(t *testing.T) {
	f, err := Build([]string{"1.1.1.1", "8.8.8.8:53"}, true, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(f.primary) != 2 || f.primary[0].Net != "tcp-tls" {
		t.Fatalf("expected 2 DoT primaries, got %+v", f.primary)
	}
	if f.primary[0].Addr != "1.1.1.1:853" || f.primary[0].ServerName != "cloudflare-dns.com" {
		t.Errorf("DoT endpoint wrong: %+v", f.primary[0])
	}
	if f.fallback[0].Addr != "1.1.1.1:53" || f.fallback[0].Net != "udp" {
		t.Errorf("fallback wrong: %+v", f.fallback[0])
	}
}
