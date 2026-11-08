package npm

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

// checkJSON rejects duplicate keys and excessive nesting, then requires exact
// spelling of the typed fields Go's decoder would otherwise match loosely.
func checkJSON(data []byte) error {
	if err := checkJSONSyntax(data); err != nil {
		return err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil || exactFields(root, []string{"_id", "name", "versions", "dist-tags", "_attachments"}) != nil {
		return errors.New("npm publish document fields are invalid")
	}
	for _, field := range []string{"versions", "_attachments"} {
		if len(root[field]) == 0 || string(root[field]) == "null" {
			continue
		}
		var objects map[string]json.RawMessage
		if err := json.Unmarshal(root[field], &objects); err != nil {
			return errors.New("npm publish object fields are invalid")
		}
		for _, value := range objects {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(value, &object); err != nil {
				return errors.New("npm publish object fields are invalid")
			}
			fields := []string{"name", "version"}
			if field == "_attachments" {
				fields = []string{"data", "length"}
			}
			if err := exactFields(object, fields); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkJSONSyntax(data []byte) error {
	if !validJSONSurrogates(data) {
		return errors.New("npm publish document has invalid Unicode escapes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("npm publish document must be an object")
	}
	if err := checkObject(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("npm publish document contains trailing data")
	}
	return nil
}

// Reject malformed UTF-16 escapes rather than letting encoding/json replace
// distinct wire values with the same Unicode replacement character.
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

func exactFields(object map[string]json.RawMessage, fields []string) error {
	for key := range object {
		for _, field := range fields {
			if key != field && strings.EqualFold(key, field) {
				return errors.New("npm publish field casing is invalid")
			}
		}
	}
	return nil
}

func checkObject(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("npm publish document nesting exceeds its limit")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return errors.New("npm publish object is invalid")
		}
		if _, exists := seen[key]; exists {
			return errors.New("npm publish object contains duplicate keys")
		}
		seen[key] = struct{}{}
		if err := checkValue(decoder, depth+1); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return errors.New("npm publish object is incomplete")
	}
	return nil
}

func checkValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("npm publish document nesting exceeds its limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("npm publish value is invalid")
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
			return errors.New("npm publish array is incomplete")
		}
	case json.Delim('}'), json.Delim(']'):
		return errors.New("npm publish value is invalid")
	}
	return nil
}
