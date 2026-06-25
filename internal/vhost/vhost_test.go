package vhost

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// serve starts a TCP listener that writes body to each connection then closes.
func serve(t *testing.T, body string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(body))
			c.Close()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestNormalizeForms(t *testing.T) {
	f := New("", []string{"example.com", "example.net"}, nil)
	cases := map[string]string{
		"foo":              "foo",
		"foo.example.com":  "foo",
		"foo.example.com.": "foo",
		"BAR.example.net":  "bar",
		"  spaced  ":       "spaced",
	}
	for in, want := range cases {
		got, ok := f.normalize(in)
		if !ok || got != want {
			t.Errorf("normalize(%q) = (%q,%v), want (%q,true)", in, got, ok, want)
		}
	}
	// Rejected: apex itself, multi-label outside a known zone, invalid chars, comment.
	for _, bad := range []string{"example.com", "a.b.other.org", "bad_underscore", "# comment", ""} {
		if _, ok := f.normalize(bad); ok {
			t.Errorf("normalize(%q) should be rejected", bad)
		}
	}
}

func TestFetchSet(t *testing.T) {
	addr, stop := serve(t, "blog\nwiki.example.com\nshop.example.com.\n@\nexample.com\n")
	defer stop()
	f := New(addr, []string{"example.com"}, nil)
	set, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	want := map[string]bool{"blog": true, "wiki": true, "shop": true}
	// "@" is not a valid label; "example.com" is the apex — both dropped.
	if len(set) != len(want) {
		t.Fatalf("set = %v, want %v", set, want)
	}
	for k := range want {
		if !set[k] {
			t.Errorf("missing %q in %v", k, set)
		}
	}
}

func TestOverCapRejected(t *testing.T) {
	big := strings.Repeat("h"+strings.Repeat("o", 60)+"\n", 2000) // > 64 KB
	addr, stop := serve(t, big)
	defer stop()
	f := New(addr, nil, nil)
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatalf("over-cap feed must be rejected, not partially parsed")
	}
}

func TestPollKeepsPreviousOnFailure(t *testing.T) {
	addr, stop := serve(t, "blog\nwiki\n")
	f := New(addr, nil, func(string) {})
	changes := 0
	f.poll(context.Background(), func() { changes++ })
	if changes != 1 || len(f.Current()) != 2 {
		t.Fatalf("first poll: changes=%d set=%v", changes, f.Current())
	}
	stop() // kill the feed; next poll fails

	f.poll(context.Background(), func() { changes++ })
	if changes != 1 {
		t.Errorf("failed poll must not change the published set, changes=%d", changes)
	}
	if len(f.Current()) != 2 {
		t.Errorf("previous set must be retained on failure, got %v", f.Current())
	}
}

func TestPollNoChangeNoCallback(t *testing.T) {
	addr, stop := serve(t, "blog\nwiki\n")
	defer stop()
	f := New(addr, nil, nil)
	changes := 0
	f.poll(context.Background(), func() { changes++ })
	f.poll(context.Background(), func() { changes++ }) // identical set
	if changes != 1 {
		t.Errorf("unchanged set must not fire onChange twice, changes=%d", changes)
	}
}

func TestDeadlineApplied(t *testing.T) {
	// A listener that accepts but never writes; the read deadline must end the fetch.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()
	f := New(ln.Addr().String(), nil, nil)
	f.deadline = 200 * time.Millisecond
	start := time.Now()
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatalf("expected a deadline error")
	}
	if time.Since(start) > time.Second {
		t.Errorf("read deadline not enforced (took %v)", time.Since(start))
	}
}
