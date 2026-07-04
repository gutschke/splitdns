package mdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestBuildDiscoveryQuery(t *testing.T) {
	b := buildDiscoveryQuery([]string{"_ipp._tcp", "_googlecast._tcp", "_ipp._tcp"}) // dup ignored
	if b == nil {
		t.Fatal("nil query")
	}
	var m dns.Msg
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	if m.Response {
		t.Error("discovery packet must be a query (QR=0)")
	}
	want := map[string]bool{serviceEnum: false, "_ipp._tcp.local.": false, "_googlecast._tcp.local.": false}
	for _, q := range m.Question {
		if _, ok := want[q.Name]; ok {
			if q.Qtype != dns.TypePTR {
				t.Errorf("%s qtype = %d, want PTR", q.Name, q.Qtype)
			}
			want[q.Name] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("missing question %q", n)
		}
	}
}

func TestParseServiceTypes(t *testing.T) {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.PTR{Hdr: dns.RR_Header{Name: serviceEnum, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120}, Ptr: "_ipp._tcp.local."},
		&dns.PTR{Hdr: dns.RR_Header{Name: serviceEnum, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120}, Ptr: "_googlecast._tcp.local."},
		// An INSTANCE ptr (owner is a service type, not the enum) must NOT be treated as a type.
		&dns.PTR{Hdr: dns.RR_Header{Name: "_ipp._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120}, Ptr: "Printer._ipp._tcp.local."},
	}
	b, _ := m.Pack()
	got := parseServiceTypes(b)
	set := map[string]bool{}
	for _, x := range got {
		set[x] = true
	}
	if len(got) != 2 || !set["_ipp._tcp"] || !set["_googlecast._tcp"] {
		t.Errorf("types = %v, want exactly [_ipp._tcp _googlecast._tcp]", got)
	}
}

// The Source emits a discovery query and folds learned types into the next query.
func TestSourceServiceDiscovery(t *testing.T) {
	var sent [][]byte
	src := NewSource(nil, func() time.Time { return time.Unix(1_000_000, 0) }, WithServiceDiscovery(time.Minute))
	src.SetSender(func(b []byte) { sent = append(sent, b) })

	src.sendQuery()
	if len(sent) != 1 {
		t.Fatalf("queries sent = %d, want 1", len(sent))
	}
	var q0 dns.Msg
	if err := q0.Unpack(sent[0]); err != nil || len(q0.Question) < 2 {
		t.Fatalf("first query malformed: %v (%d questions)", err, len(q0.Question))
	}

	// Learn a non-common type from an enumeration response.
	resp := new(dns.Msg)
	resp.Response = true
	resp.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: serviceEnum, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120}, Ptr: "_customthing._tcp.local."}}
	rb, _ := resp.Pack()
	src.HandlePacket(rb, false)

	sent = nil
	src.sendQuery()
	var q1 dns.Msg
	q1.Unpack(sent[0])
	found := false
	for _, qq := range q1.Question {
		if qq.Name == "_customthing._tcp.local." {
			found = true
		}
	}
	if !found {
		t.Error("a learned service type must be queried on the next round")
	}
}

// With discovery disabled (default), no query is emitted even if a sender is wired.
func TestSourceDiscoveryDisabled(t *testing.T) {
	src := NewSource(nil, func() time.Time { return time.Unix(1_000_000, 0) }) // no WithServiceDiscovery
	sent := 0
	src.SetSender(func([]byte) { sent++ })
	src.sendQuery()
	if sent != 0 {
		t.Errorf("passive source sent %d queries, want 0", sent)
	}
}
