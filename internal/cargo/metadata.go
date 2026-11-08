package cargo

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxMetadataDepth = 32

// CheckMetadataJSON rejects ambiguous, malformed or excessively nested JSON.
// It does not validate Cargo fields or translate metadata into an index entry.
func CheckMetadataJSON(data []byte) error {
	if len(data) == 0 || len(data) > 16<<20 || !utf8.Valid(data) {
		return errors.New("Cargo publication metadata size is invalid")
	}
	if !validJSONSurrogates(data) {
		return errors.New("Cargo publication metadata has invalid Unicode escapes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("Cargo publication metadata must be a JSON object")
	}
	if err := checkObject(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("Cargo publication metadata contains trailing data")
	}
	return checkMetadataFieldCase(data)
}

// encoding/json replaces unpaired UTF-16 surrogates with U+FFFD. Reject them
// instead so distinct wire values cannot silently become the same string.
func validJSONSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if !inString {
			if data[i] == '"' {
				inString = true
			}
			continue
		}
		if data[i] == '"' {
			inString = false
			continue
		}
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// Go's JSON decoder matches struct fields case-insensitively. Require exact
// spelling for fields consumed by the typed projection, while leaving maps such
// as feature names case-sensitive as required by the protocol.
func checkMetadataFieldCase(data []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return errors.New("Cargo publication metadata object is invalid")
	}
	if err := exactFields(object, []string{"name", "vers", "deps", "features", "links", "rust_version"}); err != nil {
		return err
	}
	if raw, found := object["deps"]; found && string(raw) != "null" {
		var dependencies []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &dependencies); err != nil {
			return errors.New("Cargo dependency metadata is invalid")
		}
		for _, dependency := range dependencies {
			if err := exactFields(dependency, []string{"name", "version_req", "features", "optional", "default_features", "target", "kind", "registry", "explicit_name_in_toml"}); err != nil {
				return err
			}
		}
	}
	return nil
}

func exactFields(object map[string]json.RawMessage, fields []string) error {
	for key := range object {
		for _, field := range fields {
			if key != field && strings.EqualFold(key, field) {
				return errors.New("Cargo publication metadata field casing is invalid")
			}
		}
	}
	return nil
}

func checkObject(decoder *json.Decoder, depth int) error {
	if depth > maxMetadataDepth {
		return errors.New("Cargo publication metadata nesting exceeds its limit")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return errors.New("Cargo publication metadata object is invalid")
		}
		if _, exists := seen[key]; exists {
			return errors.New("Cargo publication metadata contains duplicate keys")
		}
		seen[key] = struct{}{}
		if err := checkValue(decoder, depth+1); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil || token != json.Delim('}') {
		return errors.New("Cargo publication metadata object is incomplete")
	}
	return nil
}

func checkValue(decoder *json.Decoder, depth int) error {
	if depth > maxMetadataDepth {
		return errors.New("Cargo publication metadata nesting exceeds its limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("Cargo publication metadata value is invalid")
	}
	switch token {
	case json.Delim('{'):
		return checkObject(decoder, depth)
	case json.Delim('['):
		for decoder.More() {
			if err := checkValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("Cargo publication metadata array is incomplete")
		}
	case json.Delim('}'), json.Delim(']'):
		return errors.New("Cargo publication metadata value is invalid")
	}
	return nil
}
