package golden

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGoldens runs every fixture under testdata/ (synthetic, committed) and, when
// present, the operator's real captured fixtures. Those live OUTSIDE the repo by
// default (../splitdns-private/goldens/); an in-tree local/goldens/ is honored as a
// fallback. A fixture file is one parity case.
func TestGoldens(t *testing.T) {
	dirs := []string{"testdata"}
	for _, cand := range []string{
		filepath.Join("..", "..", "..", "splitdns-private", "goldens"),
		filepath.Join("..", "..", "local", "goldens"),
	} {
		if _, err := os.Stat(cand); err == nil {
			dirs = append(dirs, cand)
		}
	}
	ran := 0
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, f := range files {
			ran++
			t.Run(filepath.Base(f), func(t *testing.T) { Run(t, f) })
		}
	}
	if ran == 0 {
		t.Fatal("no golden fixtures found")
	}
}
