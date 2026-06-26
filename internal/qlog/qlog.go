// Package qlog is the in-memory query telemetry the diagnostics console reads: a
// bounded ring buffer of the most recent queries (who asked, what, how it resolved,
// how long it took) plus per-client activity scores and decision totals. It holds NO
// query contents beyond the question name/type and the client address, and never
// persists — it is a debugging aid, cleared on restart.
//
// Per-client and per-name activity is a time-DECAYED rolling score, not a lifetime
// total: each query adds 1, and the accumulated weight halves every HalfLife. So the
// "busiest clients" and their "top names" reflect RECENT activity — a host that was
// chatty yesterday and went quiet fades out instead of staying pinned at the top. Decay
// is applied lazily (on record/read) from a single per-client timestamp, so it costs no
// background work. Cold clients and names are pruned once their score falls below a
// floor, which (together with the maxClients and per-client name caps) keeps total
// memory bounded regardless of traffic — see the cap constants below.
package qlog

import (
	"math"
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

// NameCount is one query name and its decayed recent-activity score (rounded).
type NameCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// ClientStat aggregates one client's recent activity. Count is the decayed score
// (rounded) — roughly "queries within the last few HalfLifes", not a lifetime total.
// TopNames is populated only by TopClients (for the clients it returns).
type ClientStat struct {
	Client   netip.Addr
	Count    uint64
	LastSeen time.Time
	TopNames []NameCount
}

// clientAgg is the internal per-client accumulator. score and the per-name scores are
// decayed lazily from a single timestamp (decayAt), so each tracked name costs only a
// float64 (no per-name clock). lastSeen is the real wall-clock of the last query, kept
// undecayed for display.
type clientAgg struct {
	client   netip.Addr
	score    float64            // decayed activity score
	names    map[string]float64 // decayed per-name scores
	lastSeen time.Time
	decayAt  time.Time // time score/names were last decayed to
}

// Memory bounds. The hard ceiling on tracked state is maxClients × perClientNames name
// scores; with the defaults that is 4096 × 32 ≈ 131k float64 scores (~a few MB worst
// case, adversarial). Decay-driven pruning keeps the live set far smaller in practice
// (a LAN resolver tracks a handful of active clients). The recent-query ring is a
// separate fixed bound (size entries).
const (
	perClientNames = 32   // hard cap on distinct names tracked per client
	nameFloor      = 0.05 // prune a name once its decayed score drops below this
	clientFloor    = 0.05 // prune a client likewise, freeing its maxClients slot
)

// defaultHalfLife is the decay time constant: accumulated activity weight halves over
// this span, so the "busiest" views track roughly the last ~tens of minutes of traffic.
const defaultHalfLife = 10 * time.Minute

// Totals is a point-in-time rollup.
type Totals struct {
	Total      uint64
	ByDecision map[Decision]uint64
	Clients    int
}

// Log is a bounded, concurrency-safe query telemetry buffer.
type Log struct {
	maxClients int
	lambda     float64 // decay rate (ln2 / halfLife.Seconds()); 0 disables decay
	now        func() time.Time

	mu      sync.Mutex
	ring    []Entry
	next    int
	count   int
	clients map[netip.Addr]*clientAgg
	total   uint64
	byDec   map[Decision]uint64
}

// Option customizes a Log (mainly for tests injecting a clock/half-life).
type Option func(*Log)

// WithClock injects the clock used for decay-on-read (deterministic tests). The decay
// base for a recorded query is the entry's own Time; this clock is used by TopClients.
func WithClock(now func() time.Time) Option { return func(l *Log) { l.now = now } }

// WithHalfLife overrides the decay half-life (<=0 disables decay: lifetime totals).
func WithHalfLife(d time.Duration) Option {
	return func(l *Log) {
		if d <= 0 {
			l.lambda = 0
		} else {
			l.lambda = math.Ln2 / d.Seconds()
		}
	}
}

// New builds a Log retaining the last `size` queries (default 512) and tracking up to
// `maxClients` distinct clients (default 4096; further clients still count in totals).
func New(size, maxClients int, opts ...Option) *Log {
	if size <= 0 {
		size = 512
	}
	if maxClients <= 0 {
		maxClients = 4096
	}
	l := &Log{
		maxClients: maxClients,
		lambda:     math.Ln2 / defaultHalfLife.Seconds(),
		now:        time.Now,
		ring:       make([]Entry, size),
		clients:    map[netip.Addr]*clientAgg{},
		byDec:      map[Decision]uint64{},
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// decayTo ages ca's scores to time t (no-op if decay is disabled or t precedes the last
// decay), pruning any name whose score falls below nameFloor. Caller holds l.mu.
func (l *Log) decayTo(ca *clientAgg, t time.Time) {
	if l.lambda == 0 || ca.decayAt.IsZero() {
		ca.decayAt = t
		return
	}
	dt := t.Sub(ca.decayAt).Seconds()
	if dt <= 0 {
		return
	}
	f := math.Exp(-l.lambda * dt)
	ca.decayAt = t
	ca.score *= f
	for name, s := range ca.names {
		s *= f
		if s < nameFloor {
			delete(ca.names, name)
		} else {
			ca.names[name] = s
		}
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
		ca := l.clients[e.Client]
		if ca == nil {
			if len(l.clients) >= l.maxClients {
				return // already counted in totals; just not tracked per-client
			}
			ca = &clientAgg{client: e.Client, names: map[string]float64{}, decayAt: e.Time}
			l.clients[e.Client] = ca
		}
		l.decayTo(ca, e.Time) // age existing weight before adding this query's
		ca.score++
		ca.lastSeen = e.Time
		if e.Name != "" {
			// Decay above may have pruned cold names, freeing slots; a known name always
			// keeps counting, a new one only while under the per-client cap.
			if _, seen := ca.names[e.Name]; seen || len(ca.names) < perClientNames {
				ca.names[e.Name]++
			}
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

// topNamesPerClient caps how many of a client's hottest names TopClients returns.
const topNamesPerClient = 5

// TopClients returns up to n clients ranked by decayed recent-activity score (ties
// broken by address), each carrying its TopNames (most-asked names, hottest first). It
// decays every client to the current time first, and prunes any client (and its names)
// that has gone cold — so polling it both reports and bounds the live set.
func (l *Log) TopClients(n int) []ClientStat {
	if l == nil {
		return nil
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	aggs := make([]*clientAgg, 0, len(l.clients))
	for addr, ca := range l.clients {
		l.decayTo(ca, now)
		if l.lambda != 0 && ca.score < clientFloor {
			delete(l.clients, addr) // gone cold: forget it (frees a maxClients slot)
			continue
		}
		aggs = append(aggs, ca)
	}
	sort.Slice(aggs, func(i, j int) bool {
		if aggs[i].score != aggs[j].score {
			return aggs[i].score > aggs[j].score
		}
		return aggs[i].client.String() < aggs[j].client.String()
	})
	if n > 0 && n < len(aggs) {
		aggs = aggs[:n]
	}
	out := make([]ClientStat, 0, len(aggs))
	for _, ca := range aggs {
		out = append(out, ClientStat{
			Client:   ca.client,
			Count:    scoreCount(ca.score),
			LastSeen: ca.lastSeen,
			TopNames: topNames(ca.names, topNamesPerClient),
		})
	}
	return out
}

// scoreCount rounds a decayed score for display, never reporting 0 for a tracked entry
// (anything we still hold has been queried recently enough to count as at least one).
func scoreCount(s float64) uint64 {
	if n := uint64(math.Round(s)); n > 0 {
		return n
	}
	return 1
}

// topNames returns the k hottest names from m by decayed score, hottest first (ties:
// name order). Ranking uses the raw float score; the rounded value is only for display.
func topNames(m map[string]float64, k int) []NameCount {
	if len(m) == 0 {
		return nil
	}
	type ns struct {
		name  string
		score float64
	}
	all := make([]ns, 0, len(m))
	for name, s := range m {
		all = append(all, ns{name, s})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].score != all[j].score {
			return all[i].score > all[j].score
		}
		return all[i].name < all[j].name
	})
	if k > 0 && k < len(all) {
		all = all[:k]
	}
	nc := make([]NameCount, len(all))
	for i, a := range all {
		nc[i] = NameCount{Name: a.name, Count: scoreCount(a.score)}
	}
	return nc
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
