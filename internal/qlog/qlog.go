// Package qlog is the in-memory query telemetry the diagnostics console reads: a
// bounded ring buffer of the most recent queries (who asked, what, how it resolved,
// how long it took) plus per-client counters and decision totals. It holds NO query
// contents beyond the question name/type and the client address, and never persists —
// it is a debugging aid, cleared on restart.
package qlog

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Decision is how a query was ultimately handled.
type Decision string

const (
	Local    Decision = "local"    // answered from the snapshot (authoritative/static/mDNS)
	CacheHit Decision = "cache"    // served fresh from the answer cache
	Stale    Decision = "stale"    // served stale (RFC 8767) because the upstream failed
	Forward  Decision = "forward"  // forwarded to a public upstream
	Stub     Decision = "stub"     // forwarded to a stub-zone resolver
	Refused  Decision = "refused"  // client not permitted (access policy)
	Servfail Decision = "servfail" // upstream/resolution failure
	Dropped  Decision = "dropped"  // shed by the inbound concurrency limiter
)

// Entry is one recorded query.
type Entry struct {
	Seq      uint64 // monotonic id assigned at Record time (stable key for live updates)
	Time     time.Time
	Client   netip.Addr
	Name     string
	Qtype    string
	Decision Decision
	Rcode    string
	Latency  time.Duration
}

// ClientStat aggregates one client's activity.
type ClientStat struct {
	Client   netip.Addr
	Count    uint64
	LastSeen time.Time
}

// Totals is a point-in-time rollup.
type Totals struct {
	Total      uint64
	ByDecision map[Decision]uint64
	Clients    int
}

// Log is a bounded, concurrency-safe query telemetry buffer.
type Log struct {
	maxClients int

	mu      sync.Mutex
	ring    []Entry
	next    int
	count   int
	clients map[netip.Addr]*ClientStat
	total   uint64
	byDec   map[Decision]uint64
}

// New builds a Log retaining the last `size` queries (default 512) and tracking up to
// `maxClients` distinct clients (default 4096; further clients still count in totals).
func New(size, maxClients int) *Log {
	if size <= 0 {
		size = 512
	}
	if maxClients <= 0 {
		maxClients = 4096
	}
	return &Log{
		maxClients: maxClients,
		ring:       make([]Entry, size),
		clients:    map[netip.Addr]*ClientStat{},
		byDec:      map[Decision]uint64{},
	}
}

// Record appends an entry. Nil-safe so the hot path can call it unconditionally.
func (l *Log) Record(e Entry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total++
	e.Seq = l.total
	l.ring[l.next] = e
	l.next = (l.next + 1) % len(l.ring)
	if l.count < len(l.ring) {
		l.count++
	}
	l.byDec[e.Decision]++
	if e.Client.IsValid() {
		if cs := l.clients[e.Client]; cs != nil {
			cs.Count++
			cs.LastSeen = e.Time
		} else if len(l.clients) < l.maxClients {
			l.clients[e.Client] = &ClientStat{Client: e.Client, Count: 1, LastSeen: e.Time}
		}
	}
}

// Recent returns up to n entries, most-recent first.
func (l *Log) Recent(n int) []Entry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > l.count {
		n = l.count
	}
	out := make([]Entry, 0, n)
	idx := l.next - 1
	for i := 0; i < n; i++ {
		if idx < 0 {
			idx += len(l.ring)
		}
		out = append(out, l.ring[idx])
		idx--
	}
	return out
}

// TopClients returns up to n clients ranked by query count (ties broken by address).
func (l *Log) TopClients(n int) []ClientStat {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]ClientStat, 0, len(l.clients))
	for _, cs := range l.clients {
		out = append(out, *cs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Client.String() < out[j].Client.String()
	})
	if n > 0 && n < len(out) {
		out = out[:n]
	}
	return out
}

// Totals returns the rollup counters.
func (l *Log) Totals() Totals {
	if l == nil {
		return Totals{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	bd := make(map[Decision]uint64, len(l.byDec))
	for k, v := range l.byDec {
		bd[k] = v
	}
	return Totals{Total: l.total, ByDecision: bd, Clients: len(l.clients)}
}
