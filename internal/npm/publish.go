// Package npm contains experimental npm protocol boundaries. Validation does
// not authorize a request or publish a package.
package npm

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// PublishDocument is the bounded envelope and staged bytes from npm publish.
// Manifest is untrusted until archive identity and metadata are checked.
type PublishDocument struct {
	Name      string
	Version   string
	Manifest  json.RawMessage
	Tags      map[string]string
	Size      int64
	Integrity string
}

// ReadPublishDocument parses one npm publish document and decodes its single
// attachment into caller-owned staging. The caller must authorize before
// reading, cap aggregate resources, use a source whose reads can be interrupted
// by cancellation, and discard staging on every error. It must independently
// validate the archive, SemVer, name, policy and dist-tags.
func ReadPublishDocument(ctx context.Context, source io.Reader, destination io.Writer, expectedName string, maxDocument, maxArchive int64) (PublishDocument, error) {
	if ctx == nil || source == nil || destination == nil || expectedName == "" || len(expectedName) > 255 || maxDocument < 1 || maxDocument > 128<<20 || maxArchive < 1 || maxArchive > 64<<20 {
		return PublishDocument{}, errors.New("npm publish parameters are invalid")
	}
	if err := ValidatePackageName(expectedName); err != nil {
		return PublishDocument{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		return PublishDocument{}, errors.New("npm publish requires a deadline")
	}
	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, source: source}, maxDocument+1))
	if err != nil || int64(len(data)) > maxDocument || !utf8.Valid(data) {
		return PublishDocument{}, errors.New("npm publish document is invalid or exceeds its limit")
	}
	if err := checkJSON(data); err != nil {
		return PublishDocument{}, err
	}
	var document struct {
		ID          string                     `json:"_id"`
		Name        string                     `json:"name"`
		Versions    map[string]json.RawMessage `json:"versions"`
		Tags        map[string]string          `json:"dist-tags"`
		Attachments map[string]struct {
			Data   string `json:"data"`
			Length *int64 `json:"length"`
		} `json:"_attachments"`
	}
	if err := json.Unmarshal(data, &document); err != nil || document.ID != expectedName || document.Name != expectedName || len(document.Versions) != 1 || len(document.Attachments) != 1 || len(document.Tags) > 1000 {
		return PublishDocument{}, errors.New("npm publish identity or envelope is invalid")
	}
	var version string
	var manifest json.RawMessage
	for version, manifest = range document.Versions {
		break
	}
	var identity struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if !validPublishVersion(version) || json.Unmarshal(manifest, &identity) != nil || identity.Name != expectedName || identity.Version != version {
		return PublishDocument{}, errors.New("npm manifest identity is invalid")
	}
	var encoded string
	var declared *int64
	for _, attachment := range document.Attachments {
		encoded, declared = attachment.Data, attachment.Length
	}
	if declared == nil || *declared < 1 || *declared > maxArchive || len(encoded) > base64.StdEncoding.EncodedLen(int(maxArchive)) || strings.ContainsAny(encoded, "\r\n") {
		return PublishDocument{}, errors.New("npm attachment length is invalid")
	}
	hash := sha512.New()
	decoded := base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(encoded))
	size, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(&contextReader{ctx: ctx, source: decoded}, maxArchive+1))
	if err != nil || size != *declared || size > maxArchive {
		return PublishDocument{}, errors.New("npm attachment is invalid or incomplete")
	}
	return PublishDocument{Name: document.Name, Version: version, Manifest: bytes.Clone(manifest), Tags: document.Tags, Size: size, Integrity: "sha512-" + base64.StdEncoding.EncodeToString(hash.Sum(nil))}, nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}
