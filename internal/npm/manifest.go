package npm

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"unicode/utf8"
)

// ValidateManifestMetadata compares fields that affect package consumption in
// the publish document with package.json inside the archive. Differences are
// rejected conservatively; it does not claim complete npm normalization,
// dependency semantics, authorization or safety of executable content.
func ValidateManifestMetadata(published, archived []byte) error {
	for _, value := range [][]byte{published, archived} {
		if len(value) == 0 || len(value) > 16<<20 || !utf8.Valid(value) || checkJSONSyntax(value) != nil {
			return errors.New("npm package metadata is invalid")
		}
	}
	var left, right map[string]json.RawMessage
	if json.Unmarshal(published, &left) != nil || json.Unmarshal(archived, &right) != nil {
		return errors.New("npm package metadata is invalid")
	}
	fields := []string{"name", "version", "dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta", "bundledDependencies", "bundleDependencies", "exports", "imports", "main", "module", "browser", "types", "typings", "typesVersions", "bin", "engines", "os", "cpu", "libc", "scripts"}
	for _, field := range fields {
		leftValue, leftFound := left[field]
		rightValue, rightFound := right[field]
		if leftFound != rightFound {
			return errors.New("npm package metadata differs from archive")
		}
		if !leftFound {
			continue
		}
		if field == "exports" || field == "imports" || field == "typesVersions" {
			if !equalOrderedJSON(leftValue, rightValue) {
				return errors.New("npm package metadata differs from archive")
			}
			continue
		}
		var leftDecoded, rightDecoded any
		leftDecoder := json.NewDecoder(bytes.NewReader(leftValue))
		leftDecoder.UseNumber()
		rightDecoder := json.NewDecoder(bytes.NewReader(rightValue))
		rightDecoder.UseNumber()
		if leftDecoder.Decode(&leftDecoded) != nil || rightDecoder.Decode(&rightDecoded) != nil {
			return errors.New("npm package metadata differs from archive")
		}
		if field == "version" {
			publishedVersion, publishedOK := leftDecoded.(string)
			archivedVersion, archivedOK := rightDecoded.(string)
			if publishedOK && archivedOK && compatibleArchiveVersion(publishedVersion, archivedVersion) {
				continue
			}
		}
		if !reflect.DeepEqual(leftDecoded, rightDecoded) {
			return errors.New("npm package metadata differs from archive")
		}
	}
	return nil
}

// Compare tokens instead of maps: JSON escapes are equivalent, but object key
// order is retained for condition and version-selection fields.
func equalOrderedJSON(left, right []byte) bool {
	a := json.NewDecoder(bytes.NewReader(left))
	b := json.NewDecoder(bytes.NewReader(right))
	a.UseNumber()
	b.UseNumber()
	for {
		at, ae := a.Token()
		bt, be := b.Token()
		if errors.Is(ae, io.EOF) || errors.Is(be, io.EOF) {
			return errors.Is(ae, io.EOF) && errors.Is(be, io.EOF)
		}
		if ae != nil || be != nil || !reflect.DeepEqual(at, bt) {
			return false
		}
	}
}
