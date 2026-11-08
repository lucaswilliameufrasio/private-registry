package cargo

import "testing"

func TestSparseIndexPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
	}{
		{"A", "1/a"},
		{"AB", "2/ab"},
		{"AbC", "3/a/abc"},
		{"MyCrate", "my/cr/mycrate"},
		{"cargo-test", "ca/rg/cargo-test"},
		{"testé_fixture", "te/st/testé_fixture"},
		{"é", "2/é"},
	} {
		path, err := SparseIndexPath(tc.name)
		if err != nil || path != tc.want {
			t.Fatalf("name=%q path=%q err=%v", tc.name, path, err)
		}
	}
	for _, name := range []string{"", ".", "../crate", "crate/name", `crate\name`, "café_fixture", "TESTÉ_fixture", "crate\x00"} {
		if _, err := SparseIndexPath(name); err == nil {
			t.Fatalf("unsafe or unsupported name %q accepted", name)
		}
	}
}
