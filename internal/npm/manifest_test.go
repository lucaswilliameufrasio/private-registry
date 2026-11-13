package npm

import "testing"

func TestValidateManifestMetadata(t *testing.T) {
	archive := []byte(`{"name":"@fixture/pkg","version":"1.0.0","exports":{".":"./index.js"},"dependencies":{"@fixture/leaf":"^1"},"types":"index.d.ts"}`)
	for _, tc := range []struct {
		name  string
		data  string
		valid bool
	}{
		{"matching reordered", `{"types":"index.d.ts","dependencies":{"@fixture/leaf":"^1"},"exports":{".":"./index.js"},"version":"1.0.0","name":"@fixture/pkg","_id":"ignored"}`, true},
		{"different dependency", `{"name":"@fixture/pkg","version":"1.0.0","exports":{".":"./index.js"},"dependencies":{"@fixture/leaf":"^2"},"types":"index.d.ts"}`, false},
		{"missing exports", `{"name":"@fixture/pkg","version":"1.0.0","dependencies":{"@fixture/leaf":"^1"},"types":"index.d.ts"}`, false},
		{"null exports", `{"name":"@fixture/pkg","version":"1.0.0","exports":null,"dependencies":{"@fixture/leaf":"^1"},"types":"index.d.ts"}`, false},
		{"duplicate field", `{"name":"@fixture/pkg","name":"other","version":"1.0.0"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateManifestMetadata([]byte(tc.data), archive)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
}

func TestOrderedJSONEscapedKeys(t *testing.T) {
	if !equalOrderedJSON([]byte(`{">=5.0":{"*":[]},"*":{}}`), []byte(`{"\u003e=5.0":{"*":[]},"*":{}}`)) {
		t.Fatal("equivalent escaped key was rejected")
	}
	if equalOrderedJSON([]byte(`{">=5.0":{},"*":{}}`), []byte(`{"*":{},"\u003e=5.0":{}}`)) {
		t.Fatal("reordered keys were accepted")
	}
}

func TestManifestConditionalResolutionOrder(t *testing.T) {
	for _, field := range []string{"exports", "imports", "typesVersions"} {
		published := []byte(`{"` + field + `":{"node":"./node.js","default":"./default.js"}}`)
		archived := []byte(`{"` + field + `":{"default":"./default.js","node":"./node.js"}}`)
		if err := ValidateManifestMetadata(published, archived); err == nil {
			t.Fatalf("%s with reordered conditions was accepted", field)
		}
		matching := []byte(`{ "` + field + `" : { "node" : "./node.js", "default" : "./default.js" } }`)
		if err := ValidateManifestMetadata(published, matching); err != nil {
			t.Fatalf("%s with matching condition order was rejected: %v", field, err)
		}
	}
}

func TestManifestBrowserAndTypeResolutionMetadata(t *testing.T) {
	for _, field := range []string{"browser", "typesVersions", "libc"} {
		published := []byte(`{"` + field + `":"first"}`)
		archived := []byte(`{"` + field + `":"second"}`)
		if err := ValidateManifestMetadata(published, archived); err == nil {
			t.Fatalf("divergent %s was accepted", field)
		}
	}
}
