package vhost

import (
	"testing"
)

// FuzzNormalize fuzzes the reverse-proxy feed line parser. The feed is fetched over the
// network from the reverse proxy, so a corrupt/hostile line must never panic, and
// any label it accepts must be a valid single hostname label.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{
		"shop.example.com", "www.example.com.", "# comment", "", "   ",
		"example.com", "a.b.c.example.com", "UPPER.Example.COM",
		"bad label", "-leading", "trailing-", "\x00", strRepeat("a", 300),
	} {
		f.Add(s)
	}
	feed := New("127.0.0.1:818", []string{"example.com", "lan.example.com"}, nil)

	f.Fuzz(func(t *testing.T, line string) {
		name, ok := feed.normalize(line) // must not panic
		if ok {
			if name == "" {
				t.Errorf("normalize accepted but returned empty label for %q", line)
			}
			if !label.MatchString(name) {
				t.Errorf("normalize accepted %q -> %q which is not a valid label", line, name)
			}
		}
	})
}

func strRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
