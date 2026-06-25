package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTSIGKeyset(t *testing.T) {
	dir := t.TempDir()
	secFile := filepath.Join(dir, "edge.key")
	if err := os.WriteFile(secFile, []byte("ZmlsZS1zZWNyZXQtdmFsdWU=\n"), 0o400); err != nil {
		t.Fatal(err)
	}

	// No keys => nil map, no error (signing simply unavailable).
	if m, err := (DDNSConfig{}).TSIGKeyset(); err != nil || m != nil {
		t.Errorf("empty keyset = (%v, %v), want (nil, nil)", m, err)
	}

	// Inline secret + secret-file both resolve, keyed by canonical (lowercase, dotted) name.
	d := DDNSConfig{TSIGKeys: []TSIGKey{
		{Name: "Inline", Secret: "aW5saW5lLXNlY3JldA=="},
		{Name: "edge.example.com", SecretFile: secFile},
	}}
	m, err := d.TSIGKeyset()
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	if m["inline."] != "aW5saW5lLXNlY3JldA==" {
		t.Errorf("inline secret = %q", m["inline."])
	}
	if m["edge.example.com."] != "ZmlsZS1zZWNyZXQtdmFsdWU=" {
		t.Errorf("file secret = %q (want trimmed file contents)", m["edge.example.com."])
	}

	// A named key with no secret anywhere is a loud error.
	if _, err := (DDNSConfig{TSIGKeys: []TSIGKey{{Name: "x"}}}).TSIGKeyset(); err == nil {
		t.Error("missing secret should error")
	}
	// A key with no name is a loud error.
	if _, err := (DDNSConfig{TSIGKeys: []TSIGKey{{Secret: "yyy"}}}).TSIGKeyset(); err == nil {
		t.Error("missing name should error")
	}
	// A secret file that does not exist is a loud error (fail at startup, not silently).
	if _, err := (DDNSConfig{TSIGKeys: []TSIGKey{{Name: "x", SecretFile: "/no/such/file"}}}).TSIGKeyset(); err == nil {
		t.Error("missing secret file should error")
	}
}

func TestLoadNotify(t *testing.T) {
	dir := t.TempDir()
	secFile := filepath.Join(dir, "notify.key")
	if err := os.WriteFile(secFile, []byte("ZmlsZQ==\n"), 0o400); err != nil {
		t.Fatal(err)
	}

	// A dedicated notify.toml with only [notify], secret inline.
	p := filepath.Join(dir, "notify.toml")
	if err := os.WriteFile(p, []byte(`
[notify]
servers = ["resolver.lan", "10.0.0.1:5353"]
socket = "/run/custom/notify.sock"
tsig_key = "k1"
tsig_secret = "aW5saW5l"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadNotify(p)
	if err != nil {
		t.Fatalf("LoadNotify: %v", err)
	}
	if len(n.Servers) != 2 || n.TSIGKeyName != "k1" || n.TSIGSecret != "aW5saW5l" {
		t.Errorf("notify = %+v", n)
	}
	if n.Socket != "/run/custom/notify.sock" {
		t.Errorf("socket = %q, want /run/custom/notify.sock", n.Socket)
	}

	// Secret file is folded into TSIGSecret when no inline secret is given.
	p2 := filepath.Join(dir, "notify2.toml")
	if err := os.WriteFile(p2, []byte("[notify]\ntsig_key=\"k2\"\ntsig_secret_file=\""+secFile+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n2, err := LoadNotify(p2)
	if err != nil {
		t.Fatalf("LoadNotify(file secret): %v", err)
	}
	if n2.TSIGSecret != "ZmlsZQ==" {
		t.Errorf("file secret = %q, want trimmed file contents", n2.TSIGSecret)
	}

	// A missing file is not an error (helper falls back to flags/defaults).
	if n3, err := LoadNotify(filepath.Join(dir, "absent.toml")); err != nil || n3.TSIGKeyName != "" {
		t.Errorf("absent file = (%+v, %v), want zero/nil", n3, err)
	}

	// A full splitdnsd.toml is read leniently for just its [notify] table.
	p4 := filepath.Join(dir, "splitdnsd.toml")
	if err := os.WriteFile(p4, []byte("[listen]\nport = 53\n[notify]\nservers=[\"r\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n4, err := LoadNotify(p4)
	if err != nil {
		t.Fatalf("LoadNotify(full): %v", err)
	}
	if len(n4.Servers) != 1 || n4.Servers[0] != "r" {
		t.Errorf("notify from full config = %+v", n4)
	}
}
