package reconciler

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPostmapMapsIncludeBothSuppressionMaps guards the postmap list: every
// Postfix hash map referenced by a rendered config must be compiled. A missing
// entry leaves the .db unbuilt and Postfix rejects every message with
// "hash:... lookup error" (v1.6.13 shipped without suppressions_in).
func TestPostmapMapsIncludeBothSuppressionMaps(t *testing.T) {
	set := map[string]bool{}
	for _, m := range postmapMaps {
		set[m] = true
	}
	for _, want := range []string{"suppressions", "suppressions_in"} {
		if !set[want] {
			t.Errorf("postmapMaps is missing %q; Postfix would reject mail with a lookup error", want)
		}
	}
}

func TestCompiledMapMissing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "suppressions_in")

	if !compiledMapMissing(p) {
		t.Fatal("missing .db should be reported as missing")
	}
	if err := os.WriteFile(p+".db", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if compiledMapMissing(p) {
		t.Fatal("existing .db reported as missing")
	}
}
