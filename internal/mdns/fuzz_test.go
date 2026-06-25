package mdns

import (
	"testing"
)

// FuzzParsePacket feeds arbitrary bytes to the mDNS packet parser — the single most
// attacker-influenceable surface (any host on the LAN can send these). It must never
// panic, and every announcement it yields must be internally well-formed.
func FuzzParsePacket(f *testing.F) {
	// Seeds: a real announcement, a query, and garbage.
	f.Add(announceSeed())
	f.Add([]byte{0x00})
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		anns := ParsePacket(b) // must not panic
		for _, a := range anns {
			if a.Host == "" {
				t.Errorf("announcement with empty host from %v", b)
			}
			for _, addr := range a.Addrs {
				if !addr.IsValid() {
					t.Errorf("announcement carries an invalid address")
				}
			}
		}
	})
}

// announceSeed builds one valid packet without needing *testing.T (corpus seed).
func announceSeed() []byte {
	// Minimal hand-rolled is fragile; reuse the same shape announce() builds but
	// tolerate pack errors by returning a tiny non-nil seed.
	return []byte{
		0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x04, 't', 'e', 's', 't', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 192, 0, 2, 10,
	}
}
