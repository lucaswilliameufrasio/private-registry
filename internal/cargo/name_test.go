package cargo

import "testing"

func TestNameIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
	}{
		{"My-Crate", "my_crate"},
		{"my_crate", "my_crate"},
		{"testé-fixture", "testé_fixture"},
	} {
		got, err := NameIdentity(tc.name)
		if err != nil || got != tc.want {
			t.Fatalf("name %q: identity=%q err=%v", tc.name, got, err)
		}
	}
	for _, invalid := range []string{"", "../outside", "café_fixture", "TESTÉ_fixture"} {
		if _, err := NameIdentity(invalid); err == nil {
			t.Fatalf("unsupported name %q was accepted", invalid)
		}
	}
}
