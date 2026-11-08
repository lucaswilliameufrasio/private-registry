package pub

import "testing"

func TestValidateName(t *testing.T) {
	for _, name := range []string{"package", "package_1", "a"} {
		if err := ValidateName(name); err != nil {
			t.Errorf("valid name %q: %v", name, err)
		}
	}
	for _, name := range []string{"", "1package", "Package", "a/b", "a__b", "a_"} {
		if err := ValidateName(name); err == nil {
			t.Errorf("accepted invalid name %q", name)
		}
	}
}

func TestVersionIdentity(t *testing.T) {
	for input, expected := range map[string]string{"1.2.3": "1.2.3", "1.2.3-rc.1+build.2": "1.2.3-rc.1"} {
		got, err := VersionIdentity(input)
		if err != nil || got != expected {
			t.Errorf("identity %q: %q %v", input, got, err)
		}
	}
	for _, version := range []string{"", "1.2", "v1.2.3", "01.2.3", "1.2.3-01", "1.2.3+", "1.2.3+foo..bar"} {
		if _, err := VersionIdentity(version); err == nil {
			t.Errorf("accepted invalid version %q", version)
		}
	}
}
