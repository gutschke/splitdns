package mockedge

import (
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSMock is a loopback DNS server that plays both edge DNS roles: a forwarding
// UPSTREAM (configurable A/AAAA answers) and an AUTHORITATIVE server answering SOA
// serial queries (the SOAPoller bootstrap path). Faults (drop/delay/rcode) are
// injectable to drive timeout/SERVFAIL/breaker tests.
type DNSMock struct {
	mu        sync.Mutex
	a         map[string][]string // lower fqdn -> A contents
	aaaa      map[string][]string // lower fqdn -> AAAA contents
	soaSerial map[string]uint32   // lower fqdn -> SOA serial
	drop      bool
	delay     time.Duration
	rcode     int

	srv  *dns.Server
	addr string
}

// NewDNS starts a UDP DNS server on 127.0.0.1:0 and returns it; call Close to stop.
func NewDNS() (*DNSMock, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &DNSMock{
		a: map[string][]string{}, aaaa: map[string][]string{}, soaSerial: map[string]uint32{},
		rcode: dns.RcodeSuccess, addr: pc.LocalAddr().String(),
	}
	d.srv = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(d.handle)}
	started := make(chan struct{})
	d.srv.NotifyStartedFunc = func() { close(started) }
	go d.srv.ActivateAndServe()
	<-started
	return d, nil
}

// Addr is the host:port to point a forwarder/poller at.
func (d *DNSMock) Addr() string { return d.addr }

// Close stops the server.
func (d *DNSMock) Close() { d.srv.Shutdown() }

// SetA sets the A answers for name (fqdn-normalized, lowercased).
func (d *DNSMock) SetA(name string, ips ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.a[dns.Fqdn(lower(name))] = ips
}

// SetAAAA sets the AAAA answers for name.
func (d *DNSMock) SetAAAA(name string, ips ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.aaaa[dns.Fqdn(lower(name))] = ips
}

// SetSOASerial makes the server authoritative for zone's SOA with the given serial.
func (d *DNSMock) SetSOASerial(zone string, serial uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.soaSerial[dns.Fqdn(lower(zone))] = serial
}

// SetFault controls failure behavior: drop (no reply → client timeout), delay before
// replying, and/or a non-zero rcode (e.g. dns.RcodeServerFailure). Zero values reset.
func (d *DNSMock) SetFault(drop bool, delay time.Duration, rcode int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drop, d.delay, d.rcode = drop, delay, rcode
	if rcode == 0 {
		d.rcode = dns.RcodeSuccess
	}
}

func (d *DNSMock) handle(w dns.ResponseWriter, r *dns.Msg) {
	d.mu.Lock()
	drop, delay, rcode := d.drop, d.delay, d.rcode
	var a, aaaa []string
	var serial uint32
	var haveSOA bool
	if len(r.Question) == 1 {
		q := r.Question[0]
		name := lower(q.Name)
		a, aaaa = d.a[name], d.aaaa[name]
		serial, haveSOA = d.soaSerial[name]
	}
	d.mu.Unlock()

	if drop {
		return // silent: exercise client timeout
	}
	if delay > 0 {
		time.Sleep(delay)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	if rcode != dns.RcodeSuccess {
		m.Rcode = rcode
		w.WriteMsg(m)
		return
	}
	if len(r.Question) == 1 {
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			for _, ip := range a {
				if rr, err := dns.NewRR(q.Name + " 60 IN A " + ip); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeAAAA:
			for _, ip := range aaaa {
				if rr, err := dns.NewRR(q.Name + " 60 IN AAAA " + ip); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeSOA:
			if haveSOA {
				m.Authoritative = true
				rr := &dns.SOA{
					Hdr: dns.RR_Header{Name: dns.Fqdn(q.Name), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
					Ns:  "ns1." + dns.Fqdn(q.Name), Mbox: "hostmaster." + dns.Fqdn(q.Name),
					Serial:  serial,
					Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 300,
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	w.WriteMsg(m)
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
