package resolver

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// FuzzResolveName drives the hot-path classifier with arbitrary query names and
// types against an empty snapshot/view. Resolve is a pure function on attacker-
// supplied names (every forwarded query reaches it), so it must never panic and
// must always return a well-formed Outcome (exactly one of Msg/Forward/Stub).
func FuzzResolveName(f *testing.F) {
	for _, s := range []string{
		"example.com.", "a.b.c.local.", "1.2.0.192.in-addr.arpa.",
		"", ".", "..", "\x00", "xn--", "*.example.com.", "WWW.Example.COM",
	} {
		f.Add(s, uint16(dns.TypeA))
	}
	snap := &model.Snapshot{}
	view := &model.MDNSView{}

	f.Fuzz(func(t *testing.T, name string, qtype uint16) {
		req := new(dns.Msg)
		req.Question = []dns.Question{{Name: name, Qtype: qtype, Qclass: dns.ClassINET}}

		out := Resolve(snap, view, req) // must not panic

		modes := 0
		if out.Msg != nil {
			modes++
		}
		if out.Forward {
			modes++
		}
		if len(out.Stub) > 0 {
			modes++
		}
		if modes > 1 {
			t.Errorf("Resolve returned %d concurrent modes for %q/%d", modes, name, qtype)
		}
	})
}
