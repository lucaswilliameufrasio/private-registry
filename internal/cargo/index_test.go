package cargo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProjectIndex(t *testing.T) {
	metadata := []byte(`{"name":"parent","vers":"1.0.0","deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"^1","features":["fast"],"optional":true,"default_features":false,"kind":"build","registry":"https://example.invalid/index"},{"name":"normal","version_req":"*"}],"features":{"extra":["dep:alias"]},"links":null,"description":"ignored but preserved by caller"}`)
	entry, err := ProjectIndex(metadata, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Name != "parent" || entry.Version != "1.0.0" || len(entry.Deps) != 2 || entry.Deps[0].Name != "alias" || entry.Deps[0].Package == nil || *entry.Deps[0].Package != "original" || entry.Deps[0].Default || !entry.Deps[0].Optional || entry.Deps[0].Kind != "build" || !entry.Deps[1].Default || entry.Deps[1].Kind != "normal" || len(entry.Features["extra"]) != 1 {
		t.Fatalf("incorrect Cargo index projection: %+v", entry)
	}
	encoded, err := json.Marshal(entry)
	if err != nil || strings.Contains(string(encoded), "null") || !strings.Contains(string(encoded), `"package":"original"`) {
		t.Fatalf("unexpected Cargo index JSON: %s err=%v", encoded, err)
	}
}

func TestProjectIndexRejectsMalformedMetadata(t *testing.T) {
	for _, metadata := range []string{
		`{"name":"x","name":"other","vers":"1.0.0"}`,
		`{"name":"x","Name":"other","vers":"1.0.0"}`,
		`{"name":"x","vers":"1.0.0","deps":[{"name":"d","version_req":"1","Version_Req":"2"}]}`,
		`{"name":"x","vers":"1.0.0","deps":[{"name":"d"}]}`,
		`{"name":"x","vers":"1.0.0","deps":[{"name":"d","version_req":"*","kind":"unknown"}]}`,
		`{"name":"x","vers":"1.0.0","deps":[{"name":"d","version_req":"*","explicit_name_in_toml":""}]}`,
		`{"name":"x","vers":"1.0.0","features":{"bad":null}}`,
	} {
		if _, err := ProjectIndex([]byte(metadata), strings.Repeat("a", 64)); err == nil {
			t.Fatalf("invalid metadata accepted: %s", metadata)
		}
	}
	if _, err := ProjectIndex([]byte(`{"name":"x","vers":"1.0.0"}`), strings.Repeat("A", 64)); err == nil {
		t.Fatal("noncanonical checksum accepted")
	}
}
