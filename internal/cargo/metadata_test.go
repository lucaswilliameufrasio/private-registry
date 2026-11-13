package cargo

import (
	"strings"
	"testing"
)

func TestCheckMetadataJSON(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		valid bool
	}{
		{"object", `{"name":"example","deps":[{"name":"child","optional":false}]}`, true},
		{"escaped duplicate", `{"name":"a","\u006eame":"b"}`, false},
		{"nested duplicate", `{"deps":[{"name":"a","name":"b"}]}`, false},
		{"case variant identity", `{"name":"a","Name":"b"}`, false},
		{"case variant dependency", `{"deps":[{"name":"a","NAME":"b"}]}`, false},
		{"distinct feature names", `{"features":{"Fast":[],"fast":[]}}`, true},
		{"unpaired high surrogate", `{"name":"\ud800"}`, false},
		{"unpaired low surrogate", `{"name":"\udc00"}`, false},
		{"paired surrogates", `{"name":"\ud83d\ude80"}`, true},
		{"escaped backslash", `{"name":"\\ud800"}`, true},
		{"duplicate separate objects", `{"deps":[{"name":"a"},{"name":"b"}]}`, true},
		{"array root", `[]`, false},
		{"trailing object", `{} {}`, false},
		{"truncated", `{"deps":[`, false},
		{"too deep", `{"x":` + strings.Repeat(`[`, 33) + `0` + strings.Repeat(`]`, 33) + `}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckMetadataJSON([]byte(tc.input))
			if (err == nil) != tc.valid {
				t.Fatalf("metadata valid=%t err=%v", tc.valid, err)
			}
		})
	}
}
