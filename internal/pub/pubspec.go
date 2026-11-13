package pub

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// ValidatePubspec checks bounded YAML structure and the exact package identity.
// It does not validate dependency semantics or prove that a package is safe.
func ValidatePubspec(data []byte, name, version string) error {
	actualName, actualVersion, err := ParsePubspecIdentity(data)
	if err != nil {
		return err
	}
	if actualName != name || actualVersion != version {
		return errors.New("Pub manifest identity does not match")
	}
	return nil
}

// ParsePubspecIdentity validates a bounded manifest and extracts its package
// identity. It does not authorize a namespace or validate dependency semantics.
func ParsePubspecIdentity(data []byte) (string, string, error) {
	if len(data) == 0 || len(data) > 1<<20 || !utf8.Valid(data) {
		return "", "", errors.New("Pub manifest parameters are invalid")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return "", "", errors.New("Pub manifest YAML is invalid")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", "", errors.New("Pub manifest must contain one document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return "", "", errors.New("Pub manifest must be a mapping")
	}
	count := 0
	if err := inspectYAML(document.Content[0], 0, &count); err != nil {
		return "", "", err
	}
	root := document.Content[0]
	values := make(map[string]string)
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Value == "name" || key.Value == "version" {
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				return "", "", errors.New("Pub manifest identity must be strings")
			}
			values[key.Value] = value.Value
		}
	}
	if ValidateName(values["name"]) != nil {
		return "", "", errors.New("Pub manifest name is invalid")
	}
	if _, err := VersionIdentity(values["version"]); err != nil {
		return "", "", errors.New("Pub manifest version is invalid")
	}
	return values["name"], values["version"], nil
}

// PubspecJSON converts a validated manifest into bounded JSON metadata. It
// does not establish compatibility with every Pub client or dependency type.
func PubspecJSON(data []byte, name, version string) (json.RawMessage, error) {
	if err := ValidatePubspec(data, name, version); err != nil {
		return nil, err
	}
	var mapping map[string]any
	if err := yaml.Unmarshal(data, &mapping); err != nil || mapping == nil {
		return nil, errors.New("Pub manifest metadata could not be decoded")
	}
	encoded, err := json.Marshal(mapping)
	if err != nil || len(encoded) > 4<<20 {
		return nil, errors.New("Pub manifest metadata could not be encoded")
	}
	return json.RawMessage(encoded), nil
}

func inspectYAML(node *yaml.Node, depth int, count *int) error {
	(*count)++
	if depth > 64 || *count > 100000 || node.Anchor != "" || node.Kind == yaml.AliasNode {
		return errors.New("Pub manifest YAML exceeds structural limits or contains aliases")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" {
				return errors.New("Pub manifest mapping key is invalid")
			}
			if _, exists := seen[key.Value]; exists {
				return errors.New("Pub manifest contains duplicate keys")
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := inspectYAML(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}
