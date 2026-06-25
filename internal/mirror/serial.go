package mirror

// serialLt reports whether SOA serial a is strictly older than b under RFC 1982
// sequence-space arithmetic (NOT a plain integer compare). Current CF serials sit
// near the uint32 midpoint (~2.4e9), so a wraparound or CF-side reset is realistic
// over the system's lifetime; a naive a<b would freeze refreshes after a wrap.
func serialLt(a, b uint32) bool {
	return a != b && (b-a) < 0x80000000
}

// SerialState tracks, per zone, the serial we last successfully FETCHED RECORDS at,
// and whether records have ever been fetched. Fetched is keyed on records-present,
// not serial-present: a zone whose serial was persisted but whose records were never
// fetched (a serial-without-records state) must still force exactly one fetch.
type SerialState struct {
	Last    uint32
	Fetched bool
}

// ShouldFetch reports whether an observed authoritative serial requires a record
// fetch: always on a zone that has never fetched records, otherwise only when the
// observed serial is strictly newer than the last fetched one (RFC 1982).
func (s SerialState) ShouldFetch(observed uint32) bool {
	if !s.Fetched {
		return true
	}
	return serialLt(s.Last, observed)
}
