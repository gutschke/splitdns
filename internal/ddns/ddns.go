// Package ddns is the isolated, opt-in dynamic-DNS writer (requirement R9, design
// §4.4). It is the ONLY component that holds the Cloudflare DNS:Edit token and the
// only one that mutates Cloudflare. It lives off the hot path: a bounded,
// drop-oldest channel feeds a single goroutine that reconciles a host's public
// addresses against its non-proxied Cloudflare records.
//
// Authorization is push-driven: a trusted process announces a host's new public
// address via splitdns-notify(8); the mDNS source turns that into a Change and
// submits it here. Every write is guarded (opt-in flag, per-host + global rate
// limit, optional eligibility allowlist) and recorded in a hash-chained audit log.
// In the sandbox the writer is structurally unreachable (no egress, no edit token).
package ddns

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
	"github.com/gutschke/splitdns/internal/netmatch"
)

// Change is a public-IP change announcement for one bare short host label
// (e.g. "edge"), carrying that host's new desired address set. Addresses are
// filtered to genuinely-public ones inside Reconcile.
type Change struct {
	Host  string
	Addrs []netip.Addr
}

// RecordSource resolves a bare short host label to its CURRENT non-proxied A/AAAA
// Cloudflare records across all mirrored zones (the cross-source JOIN, §4.4). The
// returned model.RR values carry ZoneID/RecordID/Proxied/Content needed for precise
// edits. Implemented by the CF mirror snapshot or, standalone, by internal/cfapi.
type RecordSource interface {
	RecordsForHost(ctx context.Context, shortHost string) ([]model.RR, error)
}

// Editor applies the three Cloudflare mutations the writer needs. Implemented by
// internal/cfapi (real) and by fakes in tests.
type Editor interface {
	Create(ctx context.Context, zoneID, name string, typ uint16, content string) (recordID string, err error)
	Update(ctx context.Context, zoneID, recordID, name string, typ uint16, content string) error
	Delete(ctx context.Context, zoneID, recordID string) error
}

// Config holds the resolved guard settings.
type Config struct {
	Enabled  bool
	DryRun   bool
	Rate     time.Duration   // minimum interval between writes for a given host
	Eligible map[string]bool // optional FQDN allowlist (sans trailing dot); empty = any announced public host
	TokenID  string          // short NON-secret identifier of the edit token, for the audit trail

	// GlobalBurst/GlobalRefill bound the aggregate write rate across all hosts so a
	// storm of announcements cannot hammer the API. Zero values disable the global
	// bucket (per-host gating still applies).
	GlobalBurst  int
	GlobalRefill time.Duration // one global token replenished per this interval
}

// Outcome categorizes what a single Reconcile decided, for logging/metrics/tests.
type Outcome string

const (
	OutcomeDisabled    Outcome = "disabled"
	OutcomeNotEligible Outcome = "not-eligible"
	OutcomeNoPublic    Outcome = "no-public-addrs"
	OutcomeUnchanged   Outcome = "unchanged"
	OutcomeRateLimited Outcome = "rate-limited"
	OutcomeDryRun      Outcome = "dry-run"
	OutcomeApplied     Outcome = "applied"
	OutcomeError       Outcome = "error"
)

// chanCap is the bounded, drop-oldest queue depth (design §3: cap=64 drop-oldest).
const chanCap = 64

// Writer is the DDNS write-back engine.
type Writer struct {
	cfg   Config
	src   RecordSource
	ed    Editor
	audit *Audit
	now   func() time.Time
	log   func(string)

	ch       chan Change
	submitMu sync.Mutex // serializes the try/drop-oldest/retry sequence (D11)

	mu         sync.Mutex
	lastByHost map[string]time.Time
	global     *tokenBucket
}

// New builds a Writer. now/log may be nil (defaults applied). audit may be nil
// (a no-op sink is used).
func New(cfg Config, src RecordSource, ed Editor, audit *Audit, now func() time.Time, log func(string)) *Writer {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = func(string) {}
	}
	if audit == nil {
		audit = NewAudit(nil, cfg.TokenID)
	}
	// Safety gate (D8): an empty eligibility allowlist is treated as DENY-all for
	// live writes, not allow-all. A live writer with no allowlist could rewrite ANY
	// announced public host across every mirrored zone, so we force dry-run and warn
	// loudly rather than silently arm that. Set ddns.eligible to enable real writes.
	if cfg.Enabled && !cfg.DryRun && len(cfg.Eligible) == 0 {
		log("ddns: REFUSING live writes — eligibility allowlist is empty (would permit " +
			"writing ANY announced host); forcing dry_run. Set ddns.eligible to enable writes.")
		cfg.DryRun = true
	}
	w := &Writer{
		cfg:        cfg,
		src:        src,
		ed:         ed,
		audit:      audit,
		now:        now,
		log:        log,
		ch:         make(chan Change, chanCap),
		lastByHost: map[string]time.Time{},
	}
	if cfg.GlobalBurst > 0 && cfg.GlobalRefill > 0 {
		w.global = &tokenBucket{cap: float64(cfg.GlobalBurst), tokens: float64(cfg.GlobalBurst), refillPer: cfg.GlobalRefill, last: now()}
	}
	return w
}

// Submit enqueues a Change without blocking. If the queue is full the OLDEST
// pending change is dropped to make room (design §3 drop-oldest) — newer public-IP
// information always supersedes older.
func (w *Writer) Submit(c Change) {
	// Serialize the whole try/drop-oldest/retry: without this lock two concurrent
	// Submits can interleave so the just-enqueued (newest) change is the one dropped,
	// losing the freshest public-IP info (D11).
	w.submitMu.Lock()
	defer w.submitMu.Unlock()
	select {
	case w.ch <- c:
		return
	default:
	}
	select {
	case <-w.ch: // drop oldest
	default:
	}
	select {
	case w.ch <- c:
	default:
	}
}

// Run drains the queue until ctx is cancelled. One reconcile at a time keeps CF
// writes serialized and the audit chain well-ordered. progress (nil-safe) is called
// after each reconcile and on an idle heartbeat so the supervisor's stall-detector
// can distinguish "idle" from "wedged".
func (w *Writer) Run(ctx context.Context, progress func()) {
	if progress == nil {
		progress = func() {}
	}
	hb := time.NewTicker(30 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-w.ch:
			if _, err := w.Reconcile(ctx, c); err != nil {
				w.log(fmt.Sprintf("ddns: reconcile %s: %v", c.Host, err))
			}
			progress()
		case <-hb.C:
			progress()
		}
	}
}

// Reconcile resolves the host's current records, computes the minimal edit plan to
// converge them to the announced public addresses, applies it under the guards, and
// audits the result. It is safe to call directly (tests do).
func (w *Writer) Reconcile(ctx context.Context, c Change) (Outcome, error) {
	if !w.cfg.Enabled {
		return OutcomeDisabled, nil
	}
	host := strings.ToLower(strings.TrimSpace(c.Host))

	// Filter the announced addresses to genuinely-public ones (single source of
	// truth, shared with the rebind filter).
	desired := make([]netip.Addr, 0, len(c.Addrs))
	for _, a := range c.Addrs {
		if netmatch.IsDDNSEligible(a) {
			desired = append(desired, a.Unmap())
		}
	}
	// If NOTHING in the announcement is a public address, treat it as irrelevant and
	// do nothing — never let an empty desired set delete a host's existing records.
	if len(desired) == 0 {
		return OutcomeNoPublic, nil
	}

	records, err := w.src.RecordsForHost(ctx, host)
	if err != nil {
		return OutcomeError, fmt.Errorf("record source: %w", err)
	}
	// Belt-and-suspenders: keep only non-proxied A/AAAA even if the source already
	// filtered (a synthetic/proxied record must never be DDNS-eligible, §4.4).
	records = filterEligibleRecords(records, w.cfg.Eligible)
	if len(records) == 0 {
		// Nothing we are permitted/able to update for this host.
		return OutcomeNotEligible, nil
	}

	plan := buildPlan(records, desired)
	if plan.empty() {
		return OutcomeUnchanged, nil
	}

	// Rate guards (per-host min interval + global token bucket) — only consumed when
	// there is real work to do.
	now := w.now()
	w.mu.Lock()
	if w.cfg.Rate > 0 {
		if last, ok := w.lastByHost[host]; ok && now.Sub(last) < w.cfg.Rate {
			w.mu.Unlock()
			w.auditOutcome(host, plan, OutcomeRateLimited, "per-host interval")
			return OutcomeRateLimited, nil
		}
	}
	if w.global != nil && !w.global.allow(now) {
		w.mu.Unlock()
		w.auditOutcome(host, plan, OutcomeRateLimited, "global bucket")
		return OutcomeRateLimited, nil
	}
	w.lastByHost[host] = now
	w.mu.Unlock()

	if w.cfg.DryRun {
		w.auditOutcome(host, plan, OutcomeDryRun, "")
		return OutcomeDryRun, nil
	}

	if err := w.apply(ctx, host, plan); err != nil {
		w.auditOutcome(host, plan, OutcomeError, err.Error())
		return OutcomeError, err
	}
	w.auditOutcome(host, plan, OutcomeApplied, "")
	return OutcomeApplied, nil
}

// SimCall is one Cloudflare API call the writer WOULD make. It carries NO CF object IDs
// (ZoneID/RecordID are redacted, matching the diagnostics endpoint's policy).
type SimCall struct {
	Op      string `json:"op"`            // "update" | "create" | "delete"
	Name    string `json:"name"`          // record FQDN
	Type    string `json:"type"`          // "A" | "AAAA"
	Content string `json:"content"`       // new address (empty for delete)
	Old     string `json:"old,omitempty"` // previous content (update only)
}

// SimResult reports what a DDNS reconcile WOULD do for an announcement, without writing.
type SimResult struct {
	Host     string    `json:"host"`
	Outcome  string    `json:"outcome"`      // would-apply | unchanged | no-public-addrs | not-eligible | error
	Enabled  bool      `json:"ddns_enabled"` // is write-back actually turned on?
	DryRun   bool      `json:"dry_run"`      // would a real run be (effectively) dry-run?
	Override bool      `json:"override"`     // explore mode: the eligibility allowlist was IGNORED
	Calls    []SimCall `json:"calls"`
	Note     string    `json:"note,omitempty"`
}

// Simulate computes the Cloudflare API calls write-back WOULD make for an announcement,
// WITHOUT making them and regardless of whether DDNS is enabled. It runs the real planning
// path (public-address filter, eligibility allowlist, minimal-edit plan).
//
// When ignoreEligible is true it runs in EXPLORE mode: it BYPASSES the eligibility
// allowlist, answering "what would write-back do if this host were allowed?" — a planning
// aid for admins setting policy up before any allowlist exists. Explore never writes and
// never bypasses the public-address safety filter (a private/LAN address is always
// dropped). The result carries guiding notes so the difference between "as configured" and
// "explore" is unambiguous.
func Simulate(ctx context.Context, cfg Config, src RecordSource, c Change, ignoreEligible bool) SimResult {
	res := SimResult{
		Host:     strings.ToLower(strings.TrimSpace(c.Host)),
		Enabled:  cfg.Enabled,
		Override: ignoreEligible,
	}
	// Effective dry-run: an empty eligible allowlist forces deny-all/dry-run in production
	// (D8), so report dry-run even when dry_run is configured false.
	res.DryRun = cfg.DryRun || (cfg.Enabled && len(cfg.Eligible) == 0)

	// Public-address filter — NEVER bypassed, even in explore mode: a private/LAN address
	// must never be presented as something write-back would publish.
	desired := make([]netip.Addr, 0, len(c.Addrs))
	dropped := 0
	for _, a := range c.Addrs {
		if netmatch.IsDDNSEligible(a) {
			desired = append(desired, a.Unmap())
		} else {
			dropped++
		}
	}
	if len(desired) == 0 {
		res.Outcome = string(OutcomeNoPublic)
		if dropped > 0 {
			res.Note = "every announced address is private/non-routable; DDNS only ever publishes public addresses, so there is nothing to write."
		}
		return res
	}

	records, err := src.RecordsForHost(ctx, res.Host)
	if err != nil {
		res.Outcome = string(OutcomeError)
		res.Note = err.Error()
		return res
	}

	eligible := cfg.Eligible
	if ignoreEligible {
		eligible = nil // explore: ignore the allowlist
	}
	filtered := filterEligibleRecords(records, eligible)
	if len(filtered) == 0 {
		res.Outcome = string(OutcomeNotEligible)
		if !ignoreEligible && len(cfg.Eligible) > 0 && len(filterEligibleRecords(records, nil)) > 0 {
			res.Note = "this host has records but is NOT on the [ddns] eligible allowlist — switch to Explore to see what write-back would do, then add it to eligible to make it real."
		} else {
			res.Note = "DDNS write-back only UPDATES a host's existing non-proxied A/AAAA records to track a changing public IP. It never creates new hostnames, and never manages other record types — MX/TXT/CNAME are static records you configure in Cloudflare (splitdns mirrors them read-only). This host has no A/AAAA record to update; simulate a host that already has one to see write-back."
		}
		return res
	}

	p := buildPlan(filtered, desired)
	if p.empty() {
		res.Outcome = string(OutcomeUnchanged)
		return res
	}
	res.Outcome = "would-apply"
	for _, e := range p.edits {
		res.Calls = append(res.Calls, SimCall{Op: "update", Name: e.rec.Name, Type: dns.TypeToString[typeOf(e.addr)], Content: e.addr.String(), Old: e.rec.Content})
	}
	for _, cr := range p.creates {
		res.Calls = append(res.Calls, SimCall{Op: "create", Name: cr.name, Type: dns.TypeToString[typeOf(cr.addr)], Content: cr.addr.String()})
	}
	for _, d := range p.deletes {
		res.Calls = append(res.Calls, SimCall{Op: "delete", Name: d.Name, Type: dns.TypeToString[d.Type], Content: ""})
	}
	// Tell the admin whether these calls would happen for real, and what to change.
	switch {
	case ignoreEligible && len(cfg.Eligible) > 0 && len(filterEligibleRecords(records, cfg.Eligible)) == 0:
		res.Note = "EXPLORE ONLY: this host is NOT on the [ddns] eligible allowlist, so production write-back would SKIP it. Add it to eligible to make this real."
	case len(cfg.Eligible) == 0:
		res.Note = "the [ddns] eligible allowlist is empty, so production write-back is in forced dry-run (deny-all) — these calls would NOT be sent until you add this host to eligible."
	case !cfg.Enabled:
		res.Note = "DDNS is disabled ([ddns] enabled=false); these calls would be sent once write-back is enabled."
	case cfg.DryRun:
		res.Note = "DDNS is in dry-run ([ddns] dry_run=true); these calls would be sent once dry_run=false."
	}
	return res
}

// apply executes the plan: edit-in-place reused IDs first, then surplus creates and
// deletes (design §4.4 edit strategy).
func (w *Writer) apply(ctx context.Context, host string, p plan) error {
	for _, e := range p.edits {
		if err := w.ed.Update(ctx, e.rec.ZoneID, e.rec.RecordID, e.rec.Name, typeOf(e.addr), e.addr.String()); err != nil {
			return fmt.Errorf("update %s/%s: %w", e.rec.ZoneID, e.rec.RecordID, err)
		}
	}
	for _, cr := range p.creates {
		if _, err := w.ed.Create(ctx, cr.zoneID, cr.name, typeOf(cr.addr), cr.addr.String()); err != nil {
			return fmt.Errorf("create %s %s: %w", cr.name, cr.addr, err)
		}
	}
	for _, d := range p.deletes {
		if err := w.ed.Delete(ctx, d.ZoneID, d.RecordID); err != nil {
			return fmt.Errorf("delete %s/%s: %w", d.ZoneID, d.RecordID, err)
		}
	}
	return nil
}

func (w *Writer) auditOutcome(host string, p plan, outcome Outcome, detail string) {
	w.audit.Append(w.now(), host, p.describe(), string(outcome), detail)
}

// --- plan construction (pure) ---

type editOp struct {
	rec  model.RR
	addr netip.Addr
}

type createOp struct {
	zoneID string
	name   string
	addr   netip.Addr
}

type plan struct {
	edits   []editOp
	creates []createOp
	deletes []model.RR
}

func (p plan) empty() bool {
	return len(p.edits) == 0 && len(p.creates) == 0 && len(p.deletes) == 0
}

// describe renders a stable "old→new" summary for the audit trail.
func (p plan) describe() string {
	var b strings.Builder
	for _, e := range p.edits {
		fmt.Fprintf(&b, "edit %s:%s %s->%s; ", short(e.rec.ZoneID), short(e.rec.RecordID), e.rec.Content, e.addr)
	}
	for _, c := range p.creates {
		fmt.Fprintf(&b, "create %s:%s +%s; ", short(c.zoneID), c.name, c.addr)
	}
	for _, d := range p.deletes {
		fmt.Fprintf(&b, "delete %s:%s -%s; ", short(d.ZoneID), short(d.RecordID), d.Content)
	}
	return strings.TrimSpace(b.String())
}

// buildPlan computes the minimal set of edits/creates/deletes to converge the
// existing records to the desired public address set. It uses an edit-in-place
// strategy (reuse record IDs, only create/delete the surplus — minimizing churn and
// transient NXDOMAIN windows) and pairs WITHIN address family: an A is only ever edited
// to another A, an AAAA to another AAAA. Pairing across families (or in a nondeterministic
// order) could flip a record's type in place; family-aware, sorted pairing avoids that
// while keeping the reuse semantics.
func buildPlan(records []model.RR, desired []netip.Addr) plan {
	curSet := map[string]bool{}
	for _, r := range records {
		curSet[normAddr(r.Content)] = true
	}
	desiredSet := map[string]bool{}
	addedByFam := map[bool][]netip.Addr{} // key: is6
	for _, a := range desired {
		s := a.String()
		if desiredSet[s] {
			continue // dedup
		}
		desiredSet[s] = true
		if !curSet[s] {
			addedByFam[a.Is6()] = append(addedByFam[a.Is6()], a)
		}
	}
	deletedByFam := map[bool][]model.RR{}
	for _, r := range records {
		if !desiredSet[normAddr(r.Content)] {
			is6 := r.Type == dns.TypeAAAA
			deletedByFam[is6] = append(deletedByFam[is6], r)
		}
	}

	var p plan
	zoneID, name := records[0].ZoneID, records[0].Name
	for _, fam := range []bool{false, true} { // v4 then v6, deterministic
		added := addedByFam[fam]
		deleted := deletedByFam[fam]
		sort.Slice(added, func(i, j int) bool { return added[i].String() < added[j].String() })
		sort.Slice(deleted, func(i, j int) bool { return deleted[i].Content < deleted[j].Content })
		n := min(len(added), len(deleted))
		for i := 0; i < n; i++ {
			p.edits = append(p.edits, editOp{rec: deleted[i], addr: added[i]})
		}
		for i := n; i < len(added); i++ {
			p.creates = append(p.creates, createOp{zoneID: zoneID, name: name, addr: added[i]})
		}
		for i := n; i < len(deleted); i++ {
			p.deletes = append(p.deletes, deleted[i])
		}
	}
	return p
}

// filterEligibleRecords keeps only non-proxied A/AAAA records, and — when an
// allowlist is configured — only those whose FQDN is listed.
func filterEligibleRecords(records []model.RR, allow map[string]bool) []model.RR {
	out := records[:0:0]
	for _, r := range records {
		if r.Proxied {
			continue
		}
		if r.Type != dns.TypeA && r.Type != dns.TypeAAAA {
			continue
		}
		if len(allow) > 0 && !allow[strings.TrimSuffix(strings.ToLower(r.Name), ".")] {
			continue
		}
		out = append(out, r)
	}
	return out
}

func typeOf(a netip.Addr) uint16 {
	if a.Is4() {
		return dns.TypeA
	}
	return dns.TypeAAAA
}

// normAddr canonicalizes an address literal so CF's representation and ours compare
// equal (e.g. "2001:DB8::1" == "2001:db8::1"); non-IP content is returned verbatim.
func normAddr(s string) string {
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		return a.Unmap().String()
	}
	return s
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// tokenBucket is a minimal monotonic-clock token bucket (no external dependency).
type tokenBucket struct {
	cap       float64
	tokens    float64
	refillPer time.Duration
	last      time.Time
}

func (b *tokenBucket) allow(now time.Time) bool {
	if b.refillPer <= 0 {
		return true
	}
	if !b.last.IsZero() {
		gained := now.Sub(b.last).Seconds() / b.refillPer.Seconds()
		b.tokens = mathMin(b.cap, b.tokens+gained)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

func mathMin(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
