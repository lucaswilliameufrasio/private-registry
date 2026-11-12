package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/artifacts"
	"private-registry/internal/config"
	"private-registry/internal/oci"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

type ociHTTPFixture struct {
	authHTTPFixture
	handler    http.Handler
	owner      string
	workspace  string
	repository string
	write      string
	read       string
	staging    string
}

func newOCIHTTPFixture(t *testing.T) ociHTTPFixture {
	t.Helper()
	base := newAuthHTTPFixture(t)
	root := t.TempDir()
	store, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "oci-staging")
	service, err := oci.New(base.db, config.SQLite, base.repositoryService, store, oci.Options{StagingDirectory: staging, MaxBlobBytes: 1 << 20, MaxUploads: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := base.repositoryService.EnableFormatCreation(repositories.FormatOCI); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(base.db), base.service, base.workspaceService, base.repositoryService, base.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, OCI: service})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var owner string
	if err := base.db.QueryRow(`SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := base.workspaceService.CreateWorkspace(ctx, owner, "oci-"+uuid.NewString()[:8], "OCI")
	if err != nil {
		t.Fatal(err)
	}
	fixture := ociHTTPFixture{authHTTPFixture: base, handler: handler, owner: owner, workspace: workspace.ID, staging: staging}
	fixture.repository = fixture.createRepository(t, "images")
	fixture.write, fixture.read = fixture.tokens(t, owner, fixture.repository)
	return fixture
}

func (f ociHTTPFixture) createRepository(t *testing.T, slug string) string {
	t.Helper()
	repository, err := f.repositoryService.CreateWithFormat(context.Background(), f.owner, f.workspace, slug, slug, repositories.FormatOCI)
	if err != nil {
		t.Fatal(err)
	}
	return repository.ID
}

// tokens grants the user both roles and returns a write and a read token.
func (f ociHTTPFixture) tokens(t *testing.T, user, repository string) (string, string) {
	t.Helper()
	ctx := context.Background()
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := f.repositoryService.GrantRepositoryRole(ctx, f.owner, f.workspace, repository, user, role); err != nil {
			t.Fatal(err)
		}
	}
	write, err := f.repositoryService.IssueOCIWriteToken(ctx, user, f.workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.repositoryService.IssuePersonalReadToken(ctx, user, f.workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return write.Bearer, read.Bearer
}

func (f ociHTTPFixture) name(repository, image string) string {
	return "/v2/" + f.workspace + "/" + repository + "/" + image
}

func (f ociHTTPFixture) do(method, path, token, contentType string, body []byte, headers ...string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://registry.example"+path, bytes.NewReader(body))
	request.Host = "registry.example"
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:54321"
	if token != "" {
		// Clients authenticate with Basic; the user name is not significant.
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("token:"+token)))
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for index := 0; index+1 < len(headers); index += 2 {
		request.Header.Set(headers[index], headers[index+1])
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: response}, request)
	return response
}

func ociDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (f ociHTTPFixture) pushBlob(t *testing.T, repository, token string, content []byte) string {
	t.Helper()
	digest := ociDigest(content)
	response := f.do(http.MethodPost, f.name(repository, "app")+"/blobs/uploads/?digest="+digest, token, "application/octet-stream", content)
	if response.Code != http.StatusCreated || response.Header().Get("Docker-Content-Digest") != digest {
		t.Fatalf("monolithic blob push: status=%d body=%s", response.Code, response.Body.String())
	}
	return digest
}

func ociImageManifest(config []byte, layers ...[]byte) []byte {
	type descriptor struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	}
	document := struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Config        descriptor   `json:"config"`
		Layers        []descriptor `json:"layers"`
	}{SchemaVersion: 2, MediaType: oci.MediaTypeOCIManifest, Config: descriptor{"application/vnd.oci.image.config.v1+json", ociDigest(config), len(config)}, Layers: []descriptor{}}
	for _, layer := range layers {
		document.Layers = append(document.Layers, descriptor{"application/vnd.oci.image.layer.v1.tar+gzip", ociDigest(layer), len(layer)})
	}
	encoded, _ := json.Marshal(document)
	return encoded
}

func TestOCIPushAndPullJourney(t *testing.T) {
	f := newOCIHTTPFixture(t)
	image := f.name(f.repository, "team/app")

	if response := f.do(http.MethodGet, "/v2/", "", "", nil); response.Code != http.StatusUnauthorized || !strings.HasPrefix(response.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Fatalf("anonymous version probe: status=%d challenge=%q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
	if response := f.do(http.MethodGet, "/v2/", f.read, "", nil); response.Code != http.StatusOK {
		t.Fatalf("authenticated version probe: %d", response.Code)
	}

	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer := bytes.Repeat([]byte("synthetic layer bytes "), 4096)

	// Chunked upload: POST, two PATCH requests, PUT with the digest.
	start := f.do(http.MethodPost, image+"/blobs/uploads/", f.write, "", nil)
	location := start.Header().Get("Location")
	if start.Code != http.StatusAccepted || !strings.HasPrefix(location, image+"/blobs/uploads/") || start.Header().Get("Docker-Upload-UUID") == "" {
		t.Fatalf("upload start: status=%d location=%q", start.Code, location)
	}
	half := len(layer) / 2
	first := f.do(http.MethodPatch, location, f.write, "application/octet-stream", layer[:half], "Content-Range", fmt.Sprintf("0-%d", half-1))
	if first.Code != http.StatusAccepted || first.Header().Get("Range") != fmt.Sprintf("0-%d", half-1) {
		t.Fatalf("first chunk: status=%d range=%q", first.Code, first.Header().Get("Range"))
	}
	if outOfOrder := f.do(http.MethodPatch, location, f.write, "application/octet-stream", layer[half:], "Content-Range", fmt.Sprintf("%d-%d", half+7, len(layer)+6)); outOfOrder.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("out-of-order chunk: %d", outOfOrder.Code)
	}
	if progress := f.do(http.MethodGet, location, f.write, "", nil); progress.Code != http.StatusNoContent || progress.Header().Get("Range") != fmt.Sprintf("0-%d", half-1) {
		t.Fatalf("upload progress after rejected chunk: status=%d range=%q", progress.Code, progress.Header().Get("Range"))
	}
	if second := f.do(http.MethodPatch, location, f.write, "application/octet-stream", layer[half:], "Content-Range", fmt.Sprintf("%d-%d", half, len(layer)-1)); second.Code != http.StatusAccepted {
		t.Fatalf("second chunk: %d", second.Code)
	}
	layerDigest := ociDigest(layer)
	finish := f.do(http.MethodPut, location+"?digest="+layerDigest, f.write, "", nil)
	if finish.Code != http.StatusCreated || finish.Header().Get("Location") != image+"/blobs/"+layerDigest {
		t.Fatalf("upload finish: status=%d body=%s", finish.Code, finish.Body.String())
	}
	if again := f.do(http.MethodPut, location+"?digest="+layerDigest, f.write, "", nil); again.Code != http.StatusNotFound {
		t.Fatalf("finished upload session is still usable: %d", again.Code)
	}
	configDigest := f.pushBlob(t, f.repository, f.write, config)

	manifest := ociImageManifest(config, layer)
	manifestDigest := ociDigest(manifest)
	put := f.do(http.MethodPut, image+"/manifests/v1.0.0", f.write, oci.MediaTypeOCIManifest, manifest)
	if put.Code != http.StatusCreated || put.Header().Get("Docker-Content-Digest") != manifestDigest {
		t.Fatalf("manifest push: status=%d body=%s", put.Code, put.Body.String())
	}
	if byDigest := f.do(http.MethodPut, image+"/manifests/"+manifestDigest, f.write, oci.MediaTypeOCIManifest, manifest); byDigest.Code != http.StatusCreated {
		t.Fatalf("idempotent manifest push by digest: %d", byDigest.Code)
	}

	// Pull with the read-only token.
	head := f.do(http.MethodHead, image+"/manifests/v1.0.0", f.read, "", nil)
	if head.Code != http.StatusOK || head.Header().Get("Docker-Content-Digest") != manifestDigest || head.Header().Get("Content-Type") != oci.MediaTypeOCIManifest || head.Body.Len() != 0 {
		t.Fatalf("manifest HEAD: status=%d headers=%v", head.Code, head.Header())
	}
	for _, reference := range []string{"v1.0.0", manifestDigest} {
		got := f.do(http.MethodGet, image+"/manifests/"+reference, f.read, "", nil)
		if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), manifest) {
			t.Fatalf("manifest GET %s: status=%d", reference, got.Code)
		}
	}
	for digest, want := range map[string][]byte{layerDigest: layer, configDigest: config} {
		got := f.do(http.MethodGet, image+"/blobs/"+digest, f.read, "", nil)
		if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), want) || got.Header().Get("Docker-Content-Digest") != digest {
			t.Fatalf("blob GET %s: status=%d length=%d", digest, got.Code, got.Body.Len())
		}
	}
	if blobHead := f.do(http.MethodHead, image+"/blobs/"+layerDigest, f.read, "", nil); blobHead.Code != http.StatusOK || blobHead.Header().Get("Content-Length") != fmt.Sprint(len(layer)) {
		t.Fatalf("blob HEAD: status=%d", blobHead.Code)
	}

	// A multi-platform index over the pushed manifest, tagged separately.
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","manifests":[{"mediaType":"%s","digest":"%s","size":%d,"platform":{"architecture":"amd64","os":"linux"}}]}`, oci.MediaTypeOCIIndex, oci.MediaTypeOCIManifest, manifestDigest, len(manifest)))
	if response := f.do(http.MethodPut, image+"/manifests/latest", f.write, oci.MediaTypeOCIIndex, index); response.Code != http.StatusCreated {
		t.Fatalf("index push: status=%d body=%s", response.Code, response.Body.String())
	}
	// Tags are mutable: moving one keeps the old digest reachable by digest.
	second := ociImageManifest(config)
	if response := f.do(http.MethodPut, image+"/manifests/v1.0.0", f.write, oci.MediaTypeOCIManifest, second); response.Code != http.StatusCreated {
		t.Fatalf("tag move: %d", response.Code)
	}
	if moved := f.do(http.MethodGet, image+"/manifests/v1.0.0", f.read, "", nil); !bytes.Equal(moved.Body.Bytes(), second) {
		t.Fatal("tag did not move to the new manifest")
	}
	if old := f.do(http.MethodGet, image+"/manifests/"+manifestDigest, f.read, "", nil); old.Code != http.StatusOK {
		t.Fatalf("previous manifest lost after tag move: %d", old.Code)
	}

	tags := f.do(http.MethodGet, image+"/tags/list", f.read, "", nil)
	var listed struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(tags.Body.Bytes(), &listed); err != nil || tags.Code != http.StatusOK || listed.Name != strings.TrimPrefix(image, "/v2/") || strings.Join(listed.Tags, ",") != "latest,v1.0.0" {
		t.Fatalf("tag list: status=%d body=%s", tags.Code, tags.Body.String())
	}
	page := f.do(http.MethodGet, image+"/tags/list?n=1", f.read, "", nil)
	if !strings.Contains(page.Body.String(), `["latest"]`) || !strings.Contains(page.Header().Get("Link"), "last=latest") {
		t.Fatalf("tag pagination: body=%s link=%q", page.Body.String(), page.Header().Get("Link"))
	}
	// Tags belong to one image name inside the repository.
	if other := f.do(http.MethodGet, f.name(f.repository, "other")+"/manifests/latest", f.read, "", nil); other.Code != http.StatusNotFound {
		t.Fatalf("tag leaked across image names: %d", other.Code)
	}

	var audited int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM registry_audit_events WHERE action = 'oci_manifest.published'`).Scan(&audited); err != nil || audited < 3 {
		t.Fatalf("manifest publications were not audited: %d %v", audited, err)
	}
	if entries, err := os.ReadDir(f.staging); err != nil || len(entries) != 0 {
		t.Fatalf("upload staging was not left empty: %d %v", len(entries), err)
	}
}

func TestOCIRejectsInvalidContent(t *testing.T) {
	f := newOCIHTTPFixture(t)
	image := f.name(f.repository, "app")
	config := []byte(`{}`)
	layer := []byte("synthetic layer")
	f.pushBlob(t, f.repository, f.write, config)

	wrong := ociDigest([]byte("different bytes"))
	if response := f.do(http.MethodPost, image+"/blobs/uploads/?digest="+wrong, f.write, "application/octet-stream", layer); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DIGEST_INVALID") {
		t.Fatalf("digest mismatch: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := f.do(http.MethodHead, image+"/blobs/"+wrong, f.read, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("mismatched upload became a blob: %d", response.Code)
	}
	if response := f.do(http.MethodPost, image+"/blobs/uploads/?digest=md5:abc", f.write, "application/octet-stream", layer); response.Code != http.StatusBadRequest {
		t.Fatalf("non-sha256 digest: %d", response.Code)
	}
	if response := f.do(http.MethodPost, image+"/blobs/uploads/?digest="+ociDigest(bytes.Repeat([]byte("x"), (1<<20)+1)), f.write, "application/octet-stream", bytes.Repeat([]byte("x"), (1<<20)+1)); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized blob: %d", response.Code)
	}

	manifest := ociImageManifest(config, layer)
	if response := f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeOCIManifest, manifest); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "MANIFEST_BLOB_UNKNOWN") {
		t.Fatalf("manifest with a missing layer: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := f.do(http.MethodGet, image+"/manifests/v1", f.read, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("rejected manifest was tagged: %d", response.Code)
	}
	valid := ociImageManifest(config)
	for name, attempt := range map[string]*httptest.ResponseRecorder{
		"unsupported media type": f.do(http.MethodPut, image+"/manifests/v1", f.write, "application/vnd.docker.distribution.manifest.v1+json", valid),
		"media type mismatch":    f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeDockerManifest, valid),
		"not JSON":               f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeOCIManifest, []byte("not json")),
		"wrong digest reference": f.do(http.MethodPut, image+"/manifests/"+wrong, f.write, oci.MediaTypeOCIManifest, valid),
		"invalid tag":            f.do(http.MethodPut, image+"/manifests/.hidden", f.write, oci.MediaTypeOCIManifest, valid),
		"foreign layer":          f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeOCIManifest, []byte(fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"%s","size":2,"urls":["https://elsewhere.example/layer"]}]}`, ociDigest(config), ociDigest(config)))),
		"index of unknown child": f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeOCIIndex, []byte(fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"%s","digest":"%s","size":10}]}`, oci.MediaTypeOCIManifest, wrong))),
	} {
		if attempt.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%s", name, attempt.Code, attempt.Body.String())
		}
	}
	if response := f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeOCIManifest, bytes.Repeat([]byte(" "), oci.MaxManifestBytes+1)); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized manifest: %d", response.Code)
	}
	for _, path := range []string{image + "/manifests/v1", image + "/blobs/" + ociDigest(config)} {
		if response := f.do(http.MethodDelete, path, f.write, "", nil); response.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE %s: %d", path, response.Code)
		}
	}
	for _, path := range []string{"/v2/" + f.workspace + "/" + f.repository + "/UPPER/tags/list", "/v2/not-a-uuid/" + f.repository + "/app/tags/list", "/v2/" + f.workspace + "/" + f.repository + "/app%2Fblobs/tags/list", "/v2/_catalog"} {
		if response := f.do(http.MethodGet, path, f.read, "", nil); response.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, response.Code)
		}
	}
}

func TestOCIAuthorizationIsolation(t *testing.T) {
	f := newOCIHTTPFixture(t)
	image := f.name(f.repository, "app")
	config := []byte(`{"os":"linux"}`)
	digest := f.pushBlob(t, f.repository, f.write, config)
	manifest := ociImageManifest(config)
	if response := f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeOCIManifest, manifest); response.Code != http.StatusCreated {
		t.Fatalf("manifest push: %d", response.Code)
	}

	// No credential, garbage, and a read token used for writing.
	for name, response := range map[string]*httptest.ResponseRecorder{
		"anonymous pull":    f.do(http.MethodGet, image+"/manifests/v1", "", "", nil),
		"unknown token":     f.do(http.MethodGet, image+"/manifests/v1", "prow_"+uuid.NewString()+"."+strings.Repeat("A", 43), "", nil),
		"malformed token":   f.do(http.MethodGet, image+"/manifests/v1", "not-a-token", "", nil),
		"anonymous push":    f.do(http.MethodPost, image+"/blobs/uploads/", "", "", nil),
		"anonymous on base": f.do(http.MethodGet, "/v2/", "", "", nil),
	} {
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s: status=%d", name, response.Code)
		}
	}
	for name, response := range map[string]*httptest.ResponseRecorder{
		"read token starts upload":   f.do(http.MethodPost, image+"/blobs/uploads/", f.read, "", nil),
		"read token pushes manifest": f.do(http.MethodPut, image+"/manifests/v2", f.read, oci.MediaTypeOCIManifest, manifest),
	} {
		if response.Code != http.StatusForbidden {
			t.Errorf("%s: status=%d", name, response.Code)
		}
	}
	if response := f.do(http.MethodGet, image+"/manifests/v2", f.read, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("read token created a tag: %d", response.Code)
	}

	// A second repository in the same workspace: tokens do not cross, and a
	// digest known from the first repository is not visible or referencable.
	other := f.createRepository(t, "other")
	otherWrite, otherRead := f.tokens(t, f.owner, other)
	otherImage := f.name(other, "app")
	for name, response := range map[string]*httptest.ResponseRecorder{
		"token of another repository reads":  f.do(http.MethodGet, image+"/manifests/v1", otherRead, "", nil),
		"token of another repository writes": f.do(http.MethodPost, image+"/blobs/uploads/", otherWrite, "", nil),
	} {
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s: status=%d", name, response.Code)
		}
	}
	if response := f.do(http.MethodHead, otherImage+"/blobs/"+digest, otherRead, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("blob visible by digest from another repository: %d", response.Code)
	}
	if response := f.do(http.MethodPut, otherImage+"/manifests/v1", otherWrite, oci.MediaTypeOCIManifest, manifest); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "MANIFEST_BLOB_UNKNOWN") {
		t.Fatalf("manifest referenced a blob of another repository: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := f.do(http.MethodPost, otherImage+"/blobs/uploads/?mount="+digest+"&from="+f.workspace+"/"+f.repository+"/app", otherWrite, "", nil); response.Code != http.StatusAccepted {
		t.Fatalf("mount request did not fall back to a plain upload: %d", response.Code)
	}
	if response := f.do(http.MethodHead, otherImage+"/blobs/"+digest, otherRead, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("mount request linked a blob across repositories: %d", response.Code)
	}

	// An upload session belongs to the token owner and repository that opened it.
	start := f.do(http.MethodPost, image+"/blobs/uploads/", f.write, "", nil)
	session := strings.TrimPrefix(start.Header().Get("Location"), image+"/blobs/uploads/")
	if response := f.do(http.MethodPatch, otherImage+"/blobs/uploads/"+session, otherWrite, "application/octet-stream", []byte("x")); response.Code != http.StatusNotFound {
		t.Fatalf("upload session reachable from another repository: %d", response.Code)
	}

	// Revoking the publisher grant stops an in-flight push: the open session
	// cannot be completed and no manifest can be committed afterwards.
	if response := f.do(http.MethodPatch, image+"/blobs/uploads/"+session, f.write, "application/octet-stream", []byte("late layer")); response.Code != http.StatusAccepted {
		t.Fatalf("chunk before revocation: %d", response.Code)
	}
	if err := f.repositoryService.RevokeRepositoryRole(context.Background(), f.owner, f.workspace, f.repository, f.owner, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	late := ociDigest([]byte("late layer"))
	if response := f.do(http.MethodPut, image+"/blobs/uploads/"+session+"?digest="+late, f.write, "", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("upload completed after publisher revocation: %d", response.Code)
	}
	if response := f.do(http.MethodPut, image+"/manifests/after-revocation", f.write, oci.MediaTypeOCIManifest, manifest); response.Code != http.StatusUnauthorized {
		t.Fatalf("manifest committed after publisher revocation: %d", response.Code)
	}
	if response := f.do(http.MethodGet, image+"/manifests/after-revocation", f.read, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("tag exists after revoked push: %d", response.Code)
	}
	if response := f.do(http.MethodHead, image+"/blobs/"+late, f.read, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("blob recorded after revoked push: %d", response.Code)
	}
	// Reads continue with the reader grant, then stop when it is revoked.
	if response := f.do(http.MethodGet, image+"/manifests/v1", f.read, "", nil); response.Code != http.StatusOK {
		t.Fatalf("read after publisher revocation: %d", response.Code)
	}
	if err := f.repositoryService.RevokeRepositoryRole(context.Background(), f.owner, f.workspace, f.repository, f.owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if response := f.do(http.MethodGet, image+"/manifests/v1", f.read, "", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("read after reader revocation: %d", response.Code)
	}
}

func TestOCIPublisherWithoutReaderCannotDownload(t *testing.T) {
	f := newOCIHTTPFixture(t)
	image := f.name(f.repository, "app")
	config := []byte(`{"os":"linux"}`)
	digest := f.pushBlob(t, f.repository, f.write, config)
	if response := f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeOCIManifest, ociImageManifest(config)); response.Code != http.StatusCreated {
		t.Fatalf("manifest push: %d", response.Code)
	}
	if err := f.repositoryService.RevokeRepositoryRole(context.Background(), f.owner, f.workspace, f.repository, f.owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	// Existence probes are what a push needs; content stays unreadable.
	if response := f.do(http.MethodHead, image+"/blobs/"+digest, f.write, "", nil); response.Code != http.StatusOK {
		t.Fatalf("publisher blob existence probe: %d", response.Code)
	}
	for name, response := range map[string]*httptest.ResponseRecorder{
		"blob download":     f.do(http.MethodGet, image+"/blobs/"+digest, f.write, "", nil),
		"manifest download": f.do(http.MethodGet, image+"/manifests/v1", f.write, "", nil),
		"tag list":          f.do(http.MethodGet, image+"/tags/list", f.write, "", nil),
	} {
		if response.Code != http.StatusForbidden {
			t.Errorf("%s by a publisher without reader grant: %d", name, response.Code)
		}
	}
	if response := f.do(http.MethodPost, image+"/blobs/uploads/?digest="+ociDigest([]byte("more")), f.write, "application/octet-stream", []byte("more")); response.Code != http.StatusCreated {
		t.Fatalf("publisher without reader grant could not push: %d", response.Code)
	}
}

func TestOCIRoutesAndRepositoriesRequireOptIn(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	request := httptest.NewRequest(http.MethodGet, "https://registry.example/v2/", nil)
	request.Host = "registry.example"
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("/v2/ exists without OCI opt-in: %d", response.Code)
	}
	var owner string
	if err := fixture.db.QueryRow(`SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(context.Background(), owner, "no-oci", "No OCI")
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []repositories.Format{repositories.FormatOCI, repositories.FormatCargo, repositories.FormatNPM, repositories.FormatPub} {
		if _, err := fixture.repositoryService.CreateWithFormat(context.Background(), owner, workspace.ID, "r-"+string(format), "r", format); err == nil {
			t.Errorf("%s repository created while its adapter is disabled", format)
		}
	}
}

func TestOCIManagementRequiresWorkspaceManager(t *testing.T) {
	f := newOCIHTTPFixture(t)
	image := f.name(f.repository, "team/app")
	configBlob := []byte(`{"os":"linux"}`)
	f.pushBlob(t, f.repository, f.write, configBlob)
	manifest := ociImageManifest(configBlob)
	digest := ociDigest(manifest)
	if response := f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeOCIManifest, manifest); response.Code != http.StatusCreated {
		t.Fatalf("manifest push: %d", response.Code)
	}
	base := "/api/v1/workspaces/" + f.workspace + "/repositories/" + f.repository
	admin := muiraAdminMFACookies(t, f.handler)
	manage := func(cookies map[string]*http.Cookie, method, path, body string) *httptest.ResponseRecorder {
		csrf := ""
		if cookies[csrfCookieName] != nil {
			csrf = cookies[csrfCookieName].Value
		}
		return authHTTPRequestWithCookies(f.handler, method, path, body, authTestOrigin, "registry.example", cookies, csrf)
	}

	// A member with publisher and reader grants cannot manage the repository.
	memberID := seedHTTPUser(t, f.authHTTPFixture, "oci.publisher")
	if err := f.workspaceService.SetMembershipRole(context.Background(), f.owner, f.workspace, memberID, "member"); err != nil {
		t.Fatal(err)
	}
	f.tokens(t, memberID, f.repository)
	login := authHTTPRequest(f.handler, http.MethodPost, "/api/v1/auth/login", `{"login_name":"oci.publisher","password":"synthetic-http-member-password"}`, authTestOrigin, "registry.example")
	member := assertSessionCookies(t, login)
	for name, response := range map[string]*httptest.ResponseRecorder{
		"read policy":     manage(member, http.MethodGet, base+"/oci-policy", ""),
		"delete tag":      manage(member, http.MethodDelete, base+"/oci-tags/v1?image=team/app", ""),
		"delete manifest": manage(member, http.MethodDelete, base+"/oci-manifests/"+digest, ""),
	} {
		if response.Code != http.StatusForbidden {
			t.Errorf("publisher %s: %d %s", name, response.Code, response.Body.String())
		}
	}
	if response := authHTTPRequestWithCookies(f.handler, http.MethodPut, base+"/oci-policy", `{"immutable_tags":true,"expected_revision":0}`, authTestOrigin, "registry.example", admin, ""); response.Code != http.StatusForbidden {
		t.Fatalf("policy change without CSRF: %d", response.Code)
	}
	if response := manage(admin, http.MethodPut, base+"/oci-policy", `{"immutable_tags":true}`); response.Code != http.StatusBadRequest {
		t.Fatalf("policy change without revision: %d", response.Code)
	}
	if response := manage(admin, http.MethodPut, base+"/oci-policy", `{"immutable_tags":true,"expected_revision":0}`); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"revision":1`) {
		t.Fatalf("enable immutable tags: %d %s", response.Code, response.Body.String())
	}
	if response := manage(admin, http.MethodPut, base+"/oci-policy", `{"immutable_tags":false,"expected_revision":0}`); response.Code != http.StatusConflict {
		t.Fatalf("stale policy change: %d", response.Code)
	}

	// Through the protocol, the immutable tag cannot move.
	f.pushBlob(t, f.repository, f.write, []byte(`{"os":"windows"}`))
	moved := ociImageManifest([]byte(`{"os":"windows"}`))
	if response := f.do(http.MethodPut, image+"/manifests/v1", f.write, oci.MediaTypeOCIManifest, moved); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "immutable") {
		t.Fatalf("immutable tag moved through the protocol: %d %s", response.Code, response.Body.String())
	}

	// Retiring the tag is an explicit management action.
	if response := manage(admin, http.MethodDelete, base+"/oci-tags/v1?image=team/app", ""); response.Code != http.StatusNoContent {
		t.Fatalf("delete tag: %d %s", response.Code, response.Body.String())
	}
	if response := f.do(http.MethodGet, image+"/manifests/v1", f.read, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("deleted tag still resolves: %d", response.Code)
	}
	if response := manage(admin, http.MethodDelete, base+"/oci-manifests/"+digest, ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"removed_tags":0`) {
		t.Fatalf("delete manifest: %d %s", response.Code, response.Body.String())
	}
	if response := f.do(http.MethodGet, image+"/manifests/"+digest, f.read, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("deleted manifest still resolves: %d", response.Code)
	}
	if response := manage(admin, http.MethodDelete, base+"/oci-manifests/sha256:nothex", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid digest: %d", response.Code)
	}
	// Protocol DELETE stays unsupported: tokens never remove content.
	if response := f.do(http.MethodDelete, image+"/manifests/"+digest, f.write, "", nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("protocol delete: %d", response.Code)
	}
}

func TestOCIProtocolReportsQuota(t *testing.T) {
	f := newOCIHTTPFixture(t)
	limit := int64(64)
	if _, err := f.repositoryService.SetLogicalQuotaPolicy(context.Background(), f.owner, f.workspace, f.repository, 0, &limit); err != nil {
		t.Fatal(err)
	}
	image := f.name(f.repository, "app")
	content := bytes.Repeat([]byte("q"), 128)
	response := f.do(http.MethodPost, image+"/blobs/uploads/?digest="+ociDigest(content), f.write, "application/octet-stream", content)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "quota") {
		t.Fatalf("over-quota blob: %d %s", response.Code, response.Body.String())
	}
	if response := f.do(http.MethodHead, image+"/blobs/"+ociDigest(content), f.read, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("over-quota blob visible: %d", response.Code)
	}
}

// OCI bytes count against the workspace quota shared with every format.
func TestOCIUsageCountsAgainstTheWorkspaceQuota(t *testing.T) {
	f := newOCIHTTPFixture(t)
	ctx := context.Background()
	limit := int64(300)
	if _, err := f.repositoryService.SetLogicalQuotaPolicy(ctx, f.owner, f.workspace, "", 0, &limit); err != nil {
		t.Fatal(err)
	}
	f.pushBlob(t, f.repository, f.write, bytes.Repeat([]byte("o"), 200))
	generic, err := f.repositoryService.Create(ctx, f.owner, f.workspace, "files", "Files")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.repositoryService.GrantRepositoryRole(ctx, f.owner, f.workspace, generic.ID, f.owner, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	upload := func(size int64) error {
		content := bytes.Repeat([]byte("g"), int(size))
		_, err := f.artifactService.StartUpload(ctx, f.owner, f.workspace, generic.ID, artifacts.StartUploadRequest{Collection: "tools", Version: fmt.Sprintf("1.0.%d", size), Path: "tool.bin", ContentType: "application/octet-stream", Size: size, SHA256: strings.TrimPrefix(ociDigest(content), "sha256:")})
		return err
	}
	if err := upload(150); !errors.Is(err, artifacts.ErrLogicalQuotaExceeded) {
		t.Fatalf("generic upload ignored OCI usage: %v", err)
	}
	if err := upload(50); err != nil {
		t.Fatalf("generic upload within the remaining quota: %v", err)
	}
	// And the reverse: generic reservations count against OCI pushes.
	response := f.do(http.MethodPost, f.name(f.repository, "app")+"/blobs/uploads/?digest="+ociDigest(bytes.Repeat([]byte("p"), 100)), f.write, "application/octet-stream", bytes.Repeat([]byte("p"), 100))
	if response.Code != http.StatusForbidden {
		t.Fatalf("OCI push ignored generic usage: %d", response.Code)
	}
}
