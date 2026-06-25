package ddns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Audit is an append-only, tamper-evident DDNS audit log (design §4.4). Each entry
// is sequence-numbered and carries the hash of the previous entry; an entry's own
// hash chains the next one. Because the threat model is resolver compromise, a bare
// append-only file is not enough: a verifier can detect truncation or rewrite by
// recomputing the chain. Entries are emitted as one JSON object per line.
//
// The same lines should also be forwarded to journald/syslog by the caller; this
// type only owns the chained file/byte sink (nil sink => chain maintained in memory
// only, which the tests use).
type Audit struct {
	mu      sync.Mutex
	w       io.Writer
	tokenID string
	seq     uint64
	prev    string // hex sha256 of the previous entry ("" for genesis)
}

// Entry is one audit record. Hash/PrevHash/Seq are filled by Append.
type Entry struct {
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev"`
	Hash     string `json:"hash"`
	Time     string `json:"time"`
	TokenID  string `json:"token_id"`
	Host     string `json:"host"`
	Change   string `json:"change"` // "old->new" summary of the plan
	Result   string `json:"result"`
	Detail   string `json:"detail,omitempty"`
}

// NewAudit returns an Audit writing chained JSON lines to w (may be nil).
func NewAudit(w io.Writer, tokenID string) *Audit {
	return &Audit{w: w, tokenID: tokenID}
}

// Append adds an entry, advancing the hash chain. It never returns an error to the
// caller (audit must not break a write path); a sink error is best-effort dropped.
func (a *Audit) Append(t time.Time, host, change, result, detail string) Entry {
	a.mu.Lock()
	defer a.mu.Unlock()

	e := Entry{
		Seq:      a.seq,
		PrevHash: a.prev,
		Time:     t.UTC().Format(time.RFC3339Nano),
		TokenID:  a.tokenID,
		Host:     host,
		Change:   change,
		Result:   result,
		Detail:   detail,
	}
	e.Hash = chainHash(a.prev, e)

	a.seq++
	a.prev = e.Hash
	if a.w != nil {
		if b, err := json.Marshal(e); err == nil {
			b = append(b, '\n')
			_, _ = a.w.Write(b)
		}
	}
	return e
}

// chainHash = sha256(prevHash || canonical-payload), where the payload excludes the
// Hash field itself.
func chainHash(prev string, e Entry) string {
	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
		e.Seq, e.PrevHash, e.Time, e.TokenID, e.Host, e.Change, e.Result, e.Detail)
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0})
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain checks that a slice of entries forms an unbroken hash chain with
// contiguous sequence numbers starting at 0. Returns the index of the first broken
// entry and false, or (-1, true) if intact. Used by an external verifier and tests.
func VerifyChain(entries []Entry) (int, bool) {
	prev := ""
	for i, e := range entries {
		if e.Seq != uint64(i) {
			return i, false
		}
		if e.PrevHash != prev {
			return i, false
		}
		if chainHash(prev, e) != e.Hash {
			return i, false
		}
		prev = e.Hash
	}
	return -1, true
}
