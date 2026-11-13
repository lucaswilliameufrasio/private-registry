package npm

import (
	"strings"
	"testing"
)

func TestValidatePackageName(t *testing.T) {
	for _, name := range []string{"@fixture/pkg", "@_scope/_pkg", "@.scope/-pkg", "@scope/a.b", "foo-bar", "foo_bar", "3foo", strings.Repeat("a", 214)} {
		if err := ValidatePackageName(name); err != nil {
			t.Fatalf("valid supported package %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"", "@Fixture/pkg", "@scope/My_Pkg", "@scope/.pkg", "@scope/café", "@scope/%61", "@scope/a/b", "foo~bar", ".foo", "_foo", "-foo", "node_modules", "favicon.ico", "http", strings.Repeat("a", 215)} {
		if err := ValidatePackageName(name); err == nil {
			t.Fatalf("invalid or unsupported package %q accepted", name)
		}
	}
}
