package mirror

import "testing"

func TestSerialLt(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{10, 20, true},
		{20, 10, false},
		{5, 5, false},
		{0, 1, true},
		// Wraparound: a just below the uint32 max is OLDER than a small b.
		{0xFFFFFFFB, 3, true},
		{3, 0xFFFFFFFB, false},
	}
	for _, c := range cases {
		if got := serialLt(c.a, c.b); got != c.want {
			t.Errorf("serialLt(%d,%d) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestShouldFetch(t *testing.T) {
	// Cold (never fetched records) => always fetch, even with a known serial.
	s := SerialState{Last: 100, Fetched: false}
	if !s.ShouldFetch(100) {
		t.Fatalf("cold state must fetch even at the same serial (records-present keyed)")
	}
	// After a fetch at N: same serial => no fetch; newer => fetch.
	s = SerialState{Last: 100, Fetched: true}
	if s.ShouldFetch(100) {
		t.Errorf("same serial must NOT refetch")
	}
	if !s.ShouldFetch(101) {
		t.Errorf("newer serial must refetch")
	}
	if s.ShouldFetch(99) {
		t.Errorf("older serial must NOT refetch")
	}
}
