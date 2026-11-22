package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPersistTrustedDefaultOn: trusted-store persistence is on unless explicitly disabled,
// including when the [mdns] table is present but does not mention it.
func TestPersistTrustedDefaultOn(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"absent":   "",
		"other":    "[mdns]\ntrusted_grace = \"24h\"\n",
		"disabled": "[mdns]\npersist_trusted = false\n",
	} {
		p := filepath.Join(dir, name+".toml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if want := name != "disabled"; cfg.MDNS.PersistTrusted != want {
			t.Fatalf("%s: persist_trusted = %v, want %v", name, cfg.MDNS.PersistTrusted, want)
		}
	}
}
