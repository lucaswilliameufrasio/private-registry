package cargo

import "testing"

func TestReceiptIndexIsBoundToRepository(t *testing.T) {
	workspace := "018f0000-0000-7000-8000-000000000001"
	repository := "018f0000-0000-7000-8000-000000000002"
	got, err := repositoryIndex("https://registry.example", workspace, repository)
	if err != nil || got != "sparse+https://registry.example/cargo/"+workspace+"/"+repository+"/index/" {
		t.Fatalf("incorrect repository index %q: %v", got, err)
	}
	for _, input := range []struct{ origin, workspace, repository string }{
		{"http://registry.example", workspace, repository},
		{"https://registry.example/path", workspace, repository},
		{"https://registry.example", "../other", repository},
		{"https://registry.example", workspace, "00000000-0000-0000-0000-000000000000"},
	} {
		if _, err := repositoryIndex(input.origin, input.workspace, input.repository); err == nil {
			t.Fatal("invalid Cargo index scope accepted")
		}
	}
}

func TestReceiptIndexCannotSubstituteAnotherRepository(t *testing.T) {
	workspace := "018f0000-0000-7000-8000-000000000001"
	first, err := repositoryIndex("https://registry.example", workspace, "018f0000-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	second, err := repositoryIndex("https://registry.example", workspace, "018f0000-0000-7000-8000-000000000003")
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("[dependencies.private_dep]\nversion = \"1\"\nregistry-index = \"" + first + "\"\n")
	metadata := []byte(`{"deps":[{"name":"private_dep","version_req":"1"}]}`)
	const defaultIndex = "https://github.com/rust-lang/crates.io-index"
	if err := ValidateManifestDependencies(manifest, metadata, first, defaultIndex); err != nil {
		t.Fatalf("current repository index rejected: %v", err)
	}
	if err := ValidateManifestDependencies(manifest, metadata, second, defaultIndex); err == nil {
		t.Fatal("another repository's index was accepted as current")
	}
}
