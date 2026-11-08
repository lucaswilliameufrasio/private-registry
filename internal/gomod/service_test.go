package gomod

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/artifacts"
	"private-registry/internal/backup"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/sqlitebackup"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

type countedStore struct {
	storage.Driver
	opens atomic.Int64
}

type recoveryStage struct{ *os.File }

func (s recoveryStage) Close() error {
	return errors.Join(s.File.Close(), os.Remove(s.Name()))
}

type revokeReader struct {
	reader io.Reader
	revoke func() error
	done   bool
}

type observedReader struct {
	reads int
}

type pausedReader struct {
	reader  io.Reader
	started chan struct{}
	release chan struct{}
	paused  bool
}

func (r *pausedReader) Read(p []byte) (int, error) {
	if !r.paused {
		r.paused = true
		close(r.started)
		<-r.release
	}
	return r.reader.Read(p)
}

func (r *observedReader) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

func (r *revokeReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		if err := r.revoke(); err != nil {
			return 0, err
		}
	}
	return r.reader.Read(p)
}

func (s *countedStore) Open(ctx context.Context, key storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	s.opens.Add(1)
	return s.Driver.Open(ctx, key)
}

type corruptReadback struct{ storage.Driver }

type revokeOnOpen struct {
	storage.Driver
	once   sync.Once
	revoke func() error
	err    error
}

func (s *revokeOnOpen) Open(ctx context.Context, key storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	s.once.Do(func() { s.err = s.revoke() })
	if s.err != nil {
		return nil, storage.ObjectInfo{}, s.err
	}
	return s.Driver.Open(ctx, key)
}

func (s corruptReadback) Open(ctx context.Context, key storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	reader, info, err := s.Driver.Open(ctx, key)
	if err != nil {
		return nil, storage.ObjectInfo{}, err
	}
	if err := reader.Close(); err != nil {
		return nil, storage.ObjectInfo{}, err
	}
	return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, int(info.Size)))), info, nil
}

func TestSQLiteModulePublicationAndAuthorization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	cfg := config.Config{DataDir: filepath.Join(root, "data"), DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(root, "data", "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseModulePublication(t, ctx, db, cfg.DatabaseDriver, root, nil)
	exerciseGoQuotaCountsCargoReceipt(t, ctx, db, cfg.DatabaseDriver, root)
}

func exerciseModulePublication(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver, root string, remote storage.Driver) {
	t.Helper()
	bind := func(n int) string {
		if driver == config.Postgres {
			return []string{"", "$1", "$2", "$3", "$4", "$5"}[n]
		}
		return "?"
	}
	users := make([]string, 4)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := range users {
		users[i] = uuid.NewString()
		query := `INSERT INTO registry_users (user_id, display_name, email, email_verified, status, created_at, updated_at) VALUES (` + bind(1) + `, 'synthetic', NULL, FALSE, 'active', ` + bind(2) + `, ` + bind(3) + `)`
		if _, err := db.ExecContext(ctx, query, users[i], now, now); err != nil {
			t.Fatal(err)
		}
	}
	owner, publisher, reader, member := users[0], users[1], users[2], users[3]
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_instance_admins (user_id, granted_by, granted_at) VALUES (`+bind(1)+`, NULL, `+bind(2)+`)`, owner, now); err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "go-synthetic", "Go fixture")
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{publisher, reader, member} {
		if err := workspaceService.SetMembershipRole(ctx, owner, workspace.ID, user, workspaces.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	repoService, err := repositories.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := repoService.CreateWithFormat(ctx, owner, workspace.ID, "modules", "Modules", repositories.FormatGo)
	if err != nil {
		t.Fatal(err)
	}
	genericRepo, err := repoService.Create(ctx, owner, workspace.ID, "assets", "Generic assets")
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct {
		user string
		role repositories.GrantRole
	}{{publisher, repositories.GrantPublisher}, {reader, repositories.GrantReader}} {
		if _, err := repoService.GrantRepositoryRole(ctx, owner, workspace.ID, repo.ID, grant.user, grant.role); err != nil {
			t.Fatal(err)
		}
		if _, err := repoService.GrantRepositoryRole(ctx, owner, workspace.ID, genericRepo.ID, grant.user, grant.role); err != nil {
			t.Fatal(err)
		}
	}
	filesystem, err := storage.NewFileSystem(filepath.Join(root, "go-storage"))
	if err != nil {
		t.Fatal(err)
	}
	store := &countedStore{Driver: filesystem}
	artifactService, err := artifacts.New(db, driver, repoService, filesystem, artifacts.Options{MaxUploadBytes: 1 << 20, MaxConcurrentUploads: 1})
	if err != nil {
		t.Fatal(err)
	}
	genericData := []byte("synthetic generic artifact next to Go modules")
	genericHash := sha256.Sum256(genericData)
	upload, err := artifactService.StartUpload(ctx, publisher, workspace.ID, genericRepo.ID, artifacts.StartUploadRequest{Collection: "recovery-test", Version: "v1", Path: "fixture.bin", ContentType: "application/octet-stream", Size: int64(len(genericData)), SHA256: hex.EncodeToString(genericHash[:])})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifactService.ReceiveUpload(ctx, publisher, workspace.ID, genericRepo.ID, upload.ID, bytes.NewReader(genericData)); err != nil {
		t.Fatal(err)
	}
	genericVersion, err := artifactService.Publish(ctx, publisher, workspace.ID, genericRepo.ID, upload.ArtifactVersionID)
	if err != nil || len(genericVersion.Files) != 1 {
		t.Fatalf("publish generic recovery fixture: %v", err)
	}
	staging := filepath.Join(root, "go-staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(db, driver, repoService, store, Options{StagingDirectory: staging, MaxZipBytes: 1 << 20, MaxFiles: 100, MaxConcurrent: 4})
	if err != nil {
		t.Fatal(err)
	}
	raceRepo, err := repoService.CreateWithFormat(ctx, owner, workspace.ID, "namespace-race", "Namespace race", repositories.FormatGo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repoService.GrantRepositoryRole(ctx, owner, workspace.ID, raceRepo.ID, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	type namespaceRaceResult struct {
		reservation Reservation
		err         error
	}
	reservationRace := make(chan namespaceRaceResult, 1)
	policyRace := make(chan error, 1)
	go func() {
		reservation, err := service.ReservePublication(ctx, publisher, workspace.ID, raceRepo.ID, ReservationRequest{ModulePath: "example.net/private/module", Version: "v1.0.0", SourceTime: time.Now().UTC(), ModBytes: []byte("module example.net/private/module\n"), ZipSize: 1, ZipSHA256: strings.Repeat("a", 64)})
		reservationRace <- namespaceRaceResult{reservation: reservation, err: err}
	}()
	go func() {
		_, err := repoService.SetGoNamespacePolicy(ctx, owner, workspace.ID, raceRepo.ID, 0, "private_prefixes", []string{"example.com/private"}, true)
		policyRace <- err
	}()
	namespaceResult, policyErr := <-reservationRace, <-policyRace
	if !((namespaceResult.err == nil && errors.Is(policyErr, repositories.ErrGoNamespaceInUse)) || (errors.Is(namespaceResult.err, repositories.ErrGoNamespaceOutside) && policyErr == nil)) {
		t.Fatalf("namespace change and incompatible reservation both succeeded or failed unexpectedly: reservation=%v policy=%v", namespaceResult.err, policyErr)
	}
	if namespaceResult.err == nil {
		if err := service.CancelReservation(ctx, publisher, workspace.ID, raceRepo.ID, namespaceResult.reservation.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := artifactService.StartUpload(ctx, publisher, workspace.ID, repo.ID, artifacts.StartUploadRequest{Collection: "wrong-format", Version: "v1", Path: "file", ContentType: "application/octet-stream", Size: int64(len(genericData)), SHA256: hex.EncodeToString(genericHash[:])}); !errors.Is(err, repositories.ErrFormatMismatch) {
		t.Fatalf("generic upload accepted by Go repository: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET format = `+bind(1)+` WHERE repository_id = `+bind(2), "generic", repo.ID); err == nil {
		t.Fatal("database allowed repository format mutation")
	}
	if err := repoService.SetVisibilityPolicy(ctx, owner, repositories.PolicyAll); err != nil {
		t.Fatal(err)
	}
	if err := repoService.SetVisibility(ctx, owner, workspace.ID, repo.ID, repositories.VisibilityListed, true); !errors.Is(err, repositories.ErrVisibilityNotAllowed) {
		t.Fatalf("unsupported public Go serving was enabled: %v", err)
	}
	modulePath := "example.com/private/parent/v2"
	mod := []byte("module example.com/private/parent/v2\n\ngo 1.24\n")
	archiveFor := func(version string) []byte {
		t.Helper()
		prefix := modulePath + "@" + version + "/"
		path := writeArchive(t, []zipEntry{{name: prefix + "go.mod", data: string(mod)}, {name: prefix + "parent.go", data: "package parent\n"}})
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	data := archiveFor("v2.0.0")
	zero := int64(0)
	for _, target := range []string{"", repo.ID} {
		if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, target, 0, &zero); err != nil {
			t.Fatal(err)
		}
		body := &observedReader{}
		if err := service.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, "v2.0.0", time.Now(), mod, body); !errors.Is(err, ErrQuotaUnavailable) || body.reads != 0 {
			t.Fatalf("configured quota did not stop Go publication before body read: reads=%d err=%v", body.reads, err)
		}
		if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, target, 1, nil); err != nil {
			t.Fatal(err)
		}
	}
	quotaChanged := &revokeReader{reader: bytes.NewReader(data), revoke: func() error {
		_, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", 2, &zero)
		return err
	}}
	if err := service.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, "v2.0.0", time.Now(), mod, quotaChanged); !errors.Is(err, ErrQuotaUnavailable) {
		t.Fatalf("quota enabled during upload did not stop commit: %v", err)
	}
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", 3, nil); err != nil {
		t.Fatal(err)
	}
	repositoryQuotaChanged := &revokeReader{reader: bytes.NewReader(data), revoke: func() error {
		_, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, repo.ID, 2, &zero)
		return err
	}}
	if err := service.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, "v2.0.0", time.Now(), mod, repositoryQuotaChanged); !errors.Is(err, ErrQuotaUnavailable) {
		t.Fatalf("repository quota enabled during upload did not stop commit: %v", err)
	}
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, repo.ID, 3, nil); err != nil {
		t.Fatal(err)
	}
	wrongFormatBody := &observedReader{}
	if err := service.Publish(ctx, publisher, workspace.ID, genericRepo.ID, modulePath, "v2.0.0", time.Now(), mod, wrongFormatBody); !errors.Is(err, repositories.ErrFormatMismatch) || wrongFormatBody.reads != 0 {
		t.Fatalf("Go publication accepted by generic repository: reads=%d err=%v", wrongFormatBody.reads, err)
	}
	if _, err := service.ListVersions(ctx, reader, workspace.ID, genericRepo.ID, modulePath); !errors.Is(err, repositories.ErrFormatMismatch) {
		t.Fatalf("Go read accepted by generic repository: %v", err)
	}
	unauthorizedBody := &observedReader{}
	if err := service.Publish(ctx, member, workspace.ID, repo.ID, modulePath, "v2.0.0", time.Now(), mod, unauthorizedBody); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted publisher = %v", err)
	}
	if unauthorizedBody.reads != 0 {
		t.Fatal("ungranted publisher's request body was consumed")
	}
	otherPath := writeArchive(t, []zipEntry{{name: modulePath + "@v2.0.0/go.mod", data: string(mod)}, {name: modulePath + "@v2.0.0/parent.go", data: "package parent\nconst Different = true\n"}})
	otherData, err := os.ReadFile(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	type publicationResult struct {
		data []byte
		err  error
	}
	results := make(chan publicationResult, 2)
	sourceTime := time.Now().UTC().Truncate(time.Millisecond)
	for _, candidate := range [][]byte{data, otherData} {
		go func() {
			results <- publicationResult{data: candidate, err: service.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, "v2.0.0", sourceTime, mod, bytes.NewReader(candidate))}
		}()
	}
	var success, conflicts int
	for range 2 {
		result := <-results
		if result.err == nil {
			success++
			data = result.data
		} else if errors.Is(result.err, ErrVersionExists) {
			conflicts++
		} else {
			t.Fatalf("publish error: %v", result.err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("duplicate publish success=%d conflicts=%d", success, conflicts)
	}
	mixedQuota := int64(len(genericData)*2 + len(data) + len(mod) - 1)
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", 4, &mixedQuota); err != nil {
		t.Fatal(err)
	}
	mixedRequest := artifacts.StartUploadRequest{Collection: "mixed-quota", Version: "v1", Path: "fixture.bin", ContentType: "application/octet-stream", Size: int64(len(genericData)), SHA256: hex.EncodeToString(genericHash[:])}
	if _, err := artifactService.StartUpload(ctx, publisher, workspace.ID, genericRepo.ID, mixedRequest); !errors.Is(err, artifacts.ErrLogicalQuotaExceeded) {
		t.Fatalf("mixed-format workspace quota did not count Go objects: %v", err)
	}
	mixedQuota++
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", 5, &mixedQuota); err != nil {
		t.Fatal(err)
	}
	type mixedResult struct {
		upload artifacts.UploadSession
		err    error
	}
	mixedResults := make(chan mixedResult, 2)
	for _, collection := range []string{"mixed-quota-a", "mixed-quota-b"} {
		go func() {
			request := mixedRequest
			request.Collection = collection
			upload, err := artifactService.StartUpload(ctx, publisher, workspace.ID, genericRepo.ID, request)
			mixedResults <- mixedResult{upload: upload, err: err}
		}()
	}
	var mixedUpload artifacts.UploadSession
	var reserved, exceeded int
	for range 2 {
		result := <-mixedResults
		if result.err == nil {
			mixedUpload = result.upload
			reserved++
		} else if errors.Is(result.err, artifacts.ErrLogicalQuotaExceeded) {
			exceeded++
		} else {
			t.Fatalf("mixed-format reservation failed unexpectedly: %v", result.err)
		}
	}
	if reserved != 1 || exceeded != 1 {
		t.Fatalf("mixed-format quota admitted %d reservations and rejected %d", reserved, exceeded)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_generic_upload_sessions SET status = 'expired' WHERE upload_session_id = `+bind(1), mixedUpload.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", 6, nil); err != nil {
		t.Fatal(err)
	}
	copyGo := `INSERT INTO registry_go_module_versions (module_version_id, workspace_id, repository_id, module_path, version, mod_bytes, zip_sha256, zip_size, source_time, created_by, created_at) SELECT ` + bind(1) + `, workspace_id, ` + bind(2) + `, module_path, version, mod_bytes, zip_sha256, zip_size, source_time, created_by, created_at FROM registry_go_module_versions WHERE module_path = ` + bind(3)
	if _, err := db.ExecContext(ctx, copyGo, uuid.NewString(), genericRepo.ID, modulePath); err == nil || !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Fatalf("Go format foreign key did not reject cross-format insertion: %v", err)
	}
	copyGeneric := `INSERT INTO registry_generic_artifact_versions (artifact_version_id, workspace_id, repository_id, collection_name, version_label, status, created_by, created_at, published_at) SELECT ` + bind(1) + `, workspace_id, ` + bind(2) + `, collection_name, version_label, status, created_by, created_at, published_at FROM registry_generic_artifact_versions WHERE artifact_version_id = ` + bind(3)
	if _, err := db.ExecContext(ctx, copyGeneric, uuid.NewString(), repo.ID, genericVersion.ID); err == nil || !strings.Contains(err.Error(), "generic artifacts require a generic repository") {
		t.Fatalf("generic format guard did not reject cross-format insertion: %v", err)
	}
	moveGeneric := `UPDATE registry_generic_artifact_versions SET repository_id = ` + bind(1) + ` WHERE artifact_version_id = ` + bind(2)
	if _, err := db.ExecContext(ctx, moveGeneric, repo.ID, genericVersion.ID); err == nil || !strings.Contains(err.Error(), "generic artifacts require a generic repository") {
		t.Fatalf("generic format guard did not reject cross-format update: %v", err)
	}
	if err := service.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, "v2.0.0", sourceTime, mod, bytes.NewReader(data)); err != nil {
		t.Fatalf("identical retry was not idempotent: %v", err)
	}
	if err := service.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, "v2.0.0", sourceTime.Add(time.Second), mod, bytes.NewReader(data)); !errors.Is(err, ErrVersionExists) {
		t.Fatalf("retry with changed metadata was accepted: %v", err)
	}
	corruptFS, err := storage.NewFileSystem(filepath.Join(root, "corrupt-go-storage"))
	if err != nil {
		t.Fatal(err)
	}
	corruptService, err := NewService(db, driver, repoService, corruptReadback{Driver: corruptFS}, Options{StagingDirectory: staging, MaxZipBytes: 1 << 20, MaxFiles: 100, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := corruptService.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, "v2.3.0", time.Now(), mod, bytes.NewReader(archiveFor("v2.3.0"))); err == nil {
		t.Fatal("publication accepted corrupt storage readback")
	}
	var corruptCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_go_module_versions WHERE version = `+bind(1), "v2.3.0").Scan(&corruptCount); err != nil || corruptCount != 0 {
		t.Fatalf("corrupt publication count=%d err=%v", corruptCount, err)
	}
	pseudo := "v2.0.1-0.20260102150405-0123456789ab"
	for _, item := range []struct {
		version string
		time    time.Time
	}{
		{"v2.1.0-rc.1", time.Now()},
		{pseudo, time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)},
	} {
		if err := service.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, item.version, item.time, mod, bytes.NewReader(archiveFor(item.version))); err != nil {
			t.Fatalf("publish version %s: %v", item.version, err)
		}
	}
	if _, err := service.ListVersions(ctx, member, workspace.ID, repo.ID, modulePath); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("member listed private modules: %v", err)
	}
	before := store.opens.Load()
	if _, _, err := service.OpenZip(ctx, member, workspace.ID, repo.ID, modulePath, "v2.0.0"); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("member read private module: %v", err)
	}
	if store.opens.Load() != before {
		t.Fatal("unauthorized read touched object storage")
	}
	versions, err := service.ListVersions(ctx, reader, workspace.ID, repo.ID, modulePath)
	if err != nil || len(versions) != 2 || versions[0] != "v2.0.0" || versions[1] != "v2.1.0-rc.1" {
		t.Fatalf("versions=%v err=%v", versions, err)
	}
	latest, err := service.Latest(ctx, reader, workspace.ID, repo.ID, modulePath)
	if err != nil || latest.Version != "v2.0.0" {
		t.Fatalf("latest=%+v err=%v", latest, err)
	}
	resolved, err := service.GetVersion(ctx, reader, workspace.ID, repo.ID, modulePath, "v2.0.0")
	if err != nil || !bytes.Equal(resolved.Mod, mod) {
		t.Fatalf("resolve version error=%v", err)
	}
	stream, _, err := service.OpenZip(ctx, reader, workspace.ID, repo.ID, modulePath, "v2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	restored, readErr := io.ReadAll(stream)
	closeErr := stream.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(restored, data) {
		t.Fatalf("stored zip read=%v close=%v", readErr, closeErr)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_go_module_versions SET version = `+bind(1)+` WHERE module_path = `+bind(2), "v2.9.0", modulePath); err == nil {
		t.Fatal("database allowed mutation of a Go module version")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_go_module_versions WHERE module_path = `+bind(1), modulePath); err == nil || !strings.Contains(err.Error(), "Go module versions are immutable") {
		t.Fatalf("database did not preserve published Go identity: %v", err)
	}
	reservedArchive := archiveFor("v2.9.0")
	reservedDigest := sha256.Sum256(reservedArchive)
	request := ReservationRequest{ModulePath: modulePath, Version: "v2.9.0", SourceTime: time.Now().UTC(), ModBytes: mod, ZipSize: int64(len(reservedArchive)), ZipSHA256: hex.EncodeToString(reservedDigest[:])}
	if _, err := service.ReservePublication(ctx, member, workspace.ID, repo.ID, request); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted Go reservation accepted: %v", err)
	}
	type reservationResult struct {
		reservation Reservation
		err         error
	}
	reservationResults := make(chan reservationResult, 2)
	for range 2 {
		go func() {
			reservation, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, request)
			reservationResults <- reservationResult{reservation: reservation, err: err}
		}()
	}
	var reservation Reservation
	for range 2 {
		result := <-reservationResults
		if result.err != nil {
			t.Fatalf("Go reservation failed: %v", result.err)
		}
		if reservation.ID != "" && (reservation.ID != result.reservation.ID || !reservation.ExpiresAt.Equal(result.reservation.ExpiresAt)) {
			t.Fatal("identical concurrent Go reservations returned different receipts")
		}
		reservation = result.reservation
	}
	if reservation.ID == "" {
		t.Fatal("Go reservation did not return an identity")
	}
	status, err := service.GetReservation(ctx, publisher, workspace.ID, repo.ID, reservation.ID)
	if err != nil || status.Status != "receiving" || status.ID != reservation.ID || status.Version != request.Version {
		t.Fatalf("Go reservation status could not be reconciled: %+v err=%v", status, err)
	}
	if _, err := repoService.GrantRepositoryRole(ctx, owner, workspace.ID, repo.ID, member, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetReservation(ctx, member, workspace.ID, repo.ID, reservation.ID); !errors.Is(err, ErrReservationUnavailable) {
		t.Fatalf("publisher accessed another publisher's reservation: %v", err)
	}
	if err := repoService.RevokeRepositoryRole(ctx, owner, workspace.ID, repo.ID, member, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	changedRequest := request
	changedRequest.ZipSHA256 = strings.Repeat("b", 64)
	if _, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, changedRequest); !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("changed Go reservation was treated as an identical retry: %v", err)
	}
	if err := service.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, request.Version, request.SourceTime, mod, bytes.NewReader(reservedArchive)); !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("direct publication bypassed a Go reservation: %v", err)
	}
	unauthorizedReceive := &observedReader{}
	if err := service.ReceiveReservation(ctx, member, workspace.ID, repo.ID, reservation.ID, unauthorizedReceive); !errors.Is(err, repositories.ErrForbidden) || unauthorizedReceive.reads != 0 {
		t.Fatalf("ungranted Go upload consumed body: reads=%d err=%v", unauthorizedReceive.reads, err)
	}
	if err := service.ReceiveReservation(ctx, publisher, workspace.ID, repo.ID, reservation.ID, bytes.NewReader([]byte("invalid"))); !errors.Is(err, ErrInvalidPublication) {
		t.Fatalf("incorrect Go upload accepted: %v", err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_go_receipt_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'go.upload.received' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := service.ReceiveReservation(ctx, publisher, workspace.ID, repo.ID, reservation.ID, bytes.NewReader(reservedArchive)); err == nil {
			t.Fatal("Go upload receipt succeeded despite failed audit")
		}
		var status string
		var verified int
		if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_go_upload_sessions WHERE upload_session_id = ?`, reservation.ID).Scan(&status, &verified); err != nil || status != "receiving" || verified != 0 {
			t.Fatalf("failed Go receipt audit changed reservation: status=%q verified=%d err=%v", status, verified, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_go_receipt_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	paused := &pausedReader{reader: bytes.NewReader(reservedArchive), started: make(chan struct{}), release: make(chan struct{})}
	receiveResult := make(chan error, 1)
	go func() {
		receiveResult <- service.ReceiveReservation(ctx, publisher, workspace.ID, repo.ID, reservation.ID, paused)
	}()
	select {
	case <-paused.started:
	case <-ctx.Done():
		close(paused.release)
		t.Fatal("Go upload did not begin")
	}
	competingBody := &observedReader{}
	competingErr := service.ReceiveReservation(ctx, publisher, workspace.ID, repo.ID, reservation.ID, competingBody)
	close(paused.release)
	firstErr := <-receiveResult
	if !errors.Is(competingErr, ErrReservationUnavailable) || competingBody.reads != 0 {
		t.Fatalf("competing Go upload consumed body: reads=%d err=%v", competingBody.reads, competingErr)
	}
	if firstErr != nil {
		t.Fatalf("receive valid Go upload after retry: %v", firstErr)
	}
	status, err = service.GetReservation(ctx, publisher, workspace.ID, repo.ID, reservation.ID)
	if err != nil || status.Status != "uploaded" {
		t.Fatalf("received Go reservation status=%+v err=%v", status, err)
	}
	var receiptAudits int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_audit_events WHERE action = 'go.upload.received' AND target_id = `+bind(1), reservation.ID).Scan(&receiptAudits); err != nil || receiptAudits != 1 {
		t.Fatalf("Go receipt audit count=%d err=%v", receiptAudits, err)
	}
	if _, err := service.GetVersion(ctx, reader, workspace.ID, repo.ID, modulePath, request.Version); !errors.Is(err, ErrModuleUnavailable) {
		t.Fatalf("received Go upload became visible before publication: %v", err)
	}
	var publishedUsage int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(zip_size + LENGTH(mod_bytes)), 0) FROM registry_go_module_versions WHERE workspace_id = `+bind(1), workspace.ID).Scan(&publishedUsage); err != nil {
		t.Fatal(err)
	}
	policy, err := repoService.LogicalQuotaPolicy(ctx, owner, workspace.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	limit := publishedUsage + int64(len(genericData)) + request.ZipSize + int64(len(mod)) + int64(len(genericData)) - 1
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", policy.Revision, &limit); err != nil {
		t.Fatal(err)
	}
	if _, err := artifactService.StartUpload(ctx, publisher, workspace.ID, genericRepo.ID, artifacts.StartUploadRequest{Collection: "go-reservation-quota", Version: "v1", Path: "fixture.bin", ContentType: "application/octet-stream", Size: int64(len(genericData)), SHA256: hex.EncodeToString(genericHash[:])}); !errors.Is(err, artifacts.ErrLogicalQuotaExceeded) {
		t.Fatalf("generic reservation ignored pending Go bytes: %v", err)
	}
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", policy.Revision+1, nil); err != nil {
		t.Fatal(err)
	}
	otherArchive := archiveFor("v2.10.0")
	otherDigest := sha256.Sum256(otherArchive)
	otherRequest := ReservationRequest{ModulePath: modulePath, Version: "v2.10.0", SourceTime: time.Now().UTC(), ModBytes: mod, ZipSize: int64(len(otherArchive)), ZipSHA256: hex.EncodeToString(otherDigest[:])}
	repositoryPolicy, err := repoService.LogicalQuotaPolicy(ctx, owner, workspace.ID, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	repositoryLimit := publishedUsage + request.ZipSize + int64(len(mod)) + otherRequest.ZipSize + int64(len(mod)) - 1
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, repo.ID, repositoryPolicy.Revision, &repositoryLimit); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, otherRequest); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Go reservation ignored repository quota: %v", err)
	}
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, repo.ID, repositoryPolicy.Revision+1, nil); err != nil {
		t.Fatal(err)
	}
	cargoRepo := uuid.NewString()
	created := time.Now().UTC().Format(time.RFC3339Nano)
	query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + bind(1) + `, ` + bind(2) + `, 'cargo-quota', 'Cargo quota', ` + bind(3) + `, ` + bind(4) + `, ` + bind(5) + `, 'cargo')`
	if _, err := db.ExecContext(ctx, query, cargoRepo, workspace.ID, owner, created, created); err != nil {
		t.Fatal(err)
	}
	if _, err := repoService.GrantRepositoryRole(ctx, owner, workspace.ID, cargoRepo, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	cargoToken, err := repoService.IssueCargoWriteToken(ctx, publisher, workspace.ID, cargoRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cargoReservations, err := cargo.NewReservationService(db, repoService, driver)
	if err != nil {
		t.Fatal(err)
	}
	cargoFrame := cargo.PublishFrame{Metadata: []byte(`{"name":"quota_fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: 10, SHA256: strings.Repeat("a", 64)}
	cargoReservation, err := cargoReservations.Reserve(ctx, cargoToken.Bearer, workspace.ID, cargoRepo, cargoFrame)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = repoService.LogicalQuotaPolicy(ctx, owner, workspace.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	limit = publishedUsage + int64(len(genericData)) + request.ZipSize + int64(len(mod)) + cargoFrame.Size + otherRequest.ZipSize + int64(len(mod)) - 1
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", policy.Revision, &limit); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, otherRequest); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Go reservation ignored Cargo reservation bytes: %v", err)
	}
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", policy.Revision+1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'expired' WHERE reservation_id = `+bind(1), cargoReservation.ID); err != nil {
		t.Fatal(err)
	}
	policy, err = repoService.LogicalQuotaPolicy(ctx, owner, workspace.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	goBytes := otherRequest.ZipSize + int64(len(mod))
	allocation := int64(len(genericData))
	if goBytes > allocation {
		allocation = goBytes
	}
	limit = publishedUsage + int64(len(genericData)) + request.ZipSize + int64(len(mod)) + allocation
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", policy.Revision, &limit); err != nil {
		t.Fatal(err)
	}
	type crossFormatResult struct {
		goReservation Reservation
		genericUpload artifacts.UploadSession
		err           error
	}
	crossResults := make(chan crossFormatResult, 2)
	go func() {
		item, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, otherRequest)
		crossResults <- crossFormatResult{goReservation: item, err: err}
	}()
	go func() {
		item, err := artifactService.StartUpload(ctx, publisher, workspace.ID, genericRepo.ID, artifacts.StartUploadRequest{Collection: "cross-format-race", Version: "v1", Path: "fixture.bin", ContentType: "application/octet-stream", Size: int64(len(genericData)), SHA256: hex.EncodeToString(genericHash[:])})
		crossResults <- crossFormatResult{genericUpload: item, err: err}
	}()
	var admitted, denied int
	var admittedGoID, admittedGenericID string
	for range 2 {
		result := <-crossResults
		if result.err == nil {
			admitted++
			if result.goReservation.ID != "" {
				admittedGoID = result.goReservation.ID
			} else if result.genericUpload.ID != "" {
				admittedGenericID = result.genericUpload.ID
			} else {
				t.Fatal("successful cross-format reservation has no identity")
			}
		} else if errors.Is(result.err, ErrQuotaExceeded) || errors.Is(result.err, artifacts.ErrLogicalQuotaExceeded) {
			denied++
		} else {
			t.Fatalf("cross-format quota race failed unexpectedly: %v", result.err)
		}
	}
	if admitted != 1 || denied != 1 {
		t.Fatalf("cross-format quota admitted=%d denied=%d", admitted, denied)
	}
	if admittedGoID != "" {
		if _, err := db.ExecContext(ctx, `UPDATE registry_go_upload_sessions SET status = 'expired' WHERE upload_session_id = `+bind(1), admittedGoID); err != nil {
			t.Fatal(err)
		}
	}
	if admittedGenericID != "" {
		if _, err := db.ExecContext(ctx, `UPDATE registry_generic_upload_sessions SET status = 'expired' WHERE upload_session_id = `+bind(1), admittedGenericID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", policy.Revision+1, nil); err != nil {
		t.Fatal(err)
	}
	if driver == config.SQLite {
		assertSQLiteGoRecovery(t, ctx, db, root, workspace.ID, repo.ID, genericRepo.ID, reader, member, modulePath, data, genericVersion.Files[0].ID, genericData, reservation.ID, remote)
	}
	if err := service.CancelReservation(ctx, member, workspace.ID, repo.ID, reservation.ID); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted cancellation succeeded: %v", err)
	}
	if err := service.CancelReservation(ctx, publisher, workspace.ID, repo.ID, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.CancelReservation(ctx, publisher, workspace.ID, repo.ID, reservation.ID); err != nil {
		t.Fatalf("repeated cancellation was not idempotent: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_go_upload_sessions SET status = 'receiving' WHERE upload_session_id = `+bind(1), reservation.ID); err == nil || !strings.Contains(err.Error(), "Go upload identity and verified object are immutable") {
		t.Fatalf("database allowed a cancelled Go receipt to be reactivated: %v", err)
	}
	var cancellationAudits, retainedObject int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_audit_events WHERE action = 'go.upload.cancelled' AND target_id = `+bind(1), reservation.ID).Scan(&cancellationAudits); err != nil || cancellationAudits != 1 {
		t.Fatalf("Go cancellation audit count=%d err=%v", cancellationAudits, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT object_verified FROM registry_go_upload_sessions WHERE upload_session_id = `+bind(1), reservation.ID).Scan(&retainedObject); err != nil || retainedObject != 1 {
		t.Fatalf("cancelled Go object reference lost: verified=%d err=%v", retainedObject, err)
	}
	inventoryTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	inventory, inventoryErr := backup.InventoryGo(ctx, inventoryTx, 10, 10)
	rollbackErr := inventoryTx.Rollback()
	if inventoryErr != nil || rollbackErr != nil || len(inventory) != 4 {
		t.Fatalf("cancelled Go object missing from inventory: count=%d inventory=%v rollback=%v", len(inventory), inventoryErr, rollbackErr)
	}
	replacement, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, request)
	if err != nil || replacement.ID == "" || replacement.ID == reservation.ID {
		t.Fatalf("cancelled identity not released: replacement=%+v err=%v", replacement, err)
	}
	if err := service.CancelReservation(ctx, publisher, workspace.ID, repo.ID, replacement.ID); err != nil {
		t.Fatal(err)
	}
	publicationArchive := archiveFor("v2.14.0")
	publicationDigest := sha256.Sum256(publicationArchive)
	publicationRequest := ReservationRequest{ModulePath: modulePath, Version: "v2.14.0", SourceTime: time.Now().UTC(), ModBytes: mod, ZipSize: int64(len(publicationArchive)), ZipSHA256: hex.EncodeToString(publicationDigest[:])}
	publication, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, publicationRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ReceiveReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID, bytes.NewReader(publicationArchive)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_go_upload_sessions SET mod_bytes = `+bind(1)+` WHERE upload_session_id = `+bind(2), []byte("module example.com/private/changed\n"), publication.ID); err == nil || !strings.Contains(err.Error(), "Go upload identity and verified object are immutable") {
		t.Fatalf("database allowed Go upload metadata mutation: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_go_upload_sessions SET object_verified = 0 WHERE upload_session_id = `+bind(1), publication.ID); err == nil || !strings.Contains(err.Error(), "Go upload identity and verified object are immutable") {
		t.Fatalf("database allowed verified Go object reference removal: %v", err)
	}
	if _, err := repoService.SetGoReviewPolicy(ctx, member, workspace.ID, repo.ID, 0, true); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("member changed review policy: %v", err)
	}
	if _, err := repoService.SetGoReviewPolicy(ctx, owner, workspace.ID, repo.ID, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := service.PublishReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("Go publication bypassed required review: %v", err)
	}
	if _, err := service.GetVersion(ctx, reader, workspace.ID, repo.ID, modulePath, publicationRequest.Version); !errors.Is(err, ErrModuleUnavailable) {
		t.Fatalf("Go publication requiring review became visible: %v", err)
	}
	if _, err := repoService.GrantGoReviewer(ctx, member, workspace.ID, repo.ID, member); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("member granted reviewer capability: %v", err)
	}
	if _, err := repoService.GrantGoReviewer(ctx, owner, workspace.ID, repo.ID, publisher); err != nil {
		t.Fatal(err)
	}
	if err := service.ApproveReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("publisher approved their own upload: %v", err)
	}
	if err := service.ApproveReservation(ctx, member, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted reviewer approved upload: %v", err)
	}
	memberGrant, err := repoService.GrantGoReviewer(ctx, owner, workspace.ID, repo.ID, member)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ApproveReservation(ctx, member, workspace.ID, repo.ID, publication.ID); err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.RemoveMembership(ctx, owner, workspace.ID, member); err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, owner, workspace.ID, member, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	newMemberGrant, err := repoService.GrantGoReviewer(ctx, owner, workspace.ID, repo.ID, member)
	if err != nil || newMemberGrant == memberGrant {
		t.Fatalf("readmitted reviewer retained old grant: %v", err)
	}
	if err := service.PublishReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("readmission revived prior review: %v", err)
	}
	beforeReviewOpen := store.opens.Load()
	if _, _, err := service.OpenReviewZip(ctx, reader, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrForbidden) || store.opens.Load() != beforeReviewOpen {
		t.Fatalf("ungranted review accessed object storage: %v", err)
	}
	if _, _, err := service.ListReviewCandidates(ctx, reader, workspace.ID, genericRepo.ID, "", 10); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("review list exposed another repository: %v", err)
	}
	firstReviewerGrant, err := repoService.GrantGoReviewer(ctx, owner, workspace.ID, repo.ID, reader)
	if err != nil {
		t.Fatal(err)
	}
	candidates, more, err := service.ListReviewCandidates(ctx, reader, workspace.ID, repo.ID, "", 1)
	if err != nil || more || len(candidates) != 1 || candidates[0].ID != publication.ID {
		t.Fatalf("review candidates=%+v more=%t err=%v", candidates, more, err)
	}
	candidate, err := service.GetReviewCandidate(ctx, reader, workspace.ID, repo.ID, publication.ID)
	if err != nil || candidate.PublisherID != publisher || !bytes.Equal(candidate.Mod, mod) {
		t.Fatalf("review candidate metadata unavailable: %v", err)
	}
	reviewZip, _, err := service.OpenReviewZip(ctx, reader, workspace.ID, repo.ID, publication.ID)
	if err != nil {
		t.Fatal(err)
	}
	reviewBytes, reviewReadErr := io.ReadAll(reviewZip)
	reviewCloseErr := reviewZip.Close()
	if reviewReadErr != nil || reviewCloseErr != nil || !bytes.Equal(reviewBytes, publicationArchive) {
		t.Fatalf("review archive differs: read=%v close=%v", reviewReadErr, reviewCloseErr)
	}
	rejectedArchive := archiveFor("v2.15.0")
	rejectedDigest := sha256.Sum256(rejectedArchive)
	rejectedRequest := ReservationRequest{ModulePath: modulePath, Version: "v2.15.0", SourceTime: time.Now().UTC(), ModBytes: mod, ZipSize: int64(len(rejectedArchive)), ZipSHA256: hex.EncodeToString(rejectedDigest[:])}
	rejected, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, rejectedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ReceiveReservation(ctx, publisher, workspace.ID, repo.ID, rejected.ID, bytes.NewReader(rejectedArchive)); err != nil {
		t.Fatal(err)
	}
	if err := service.RejectReservation(ctx, reader, workspace.ID, repo.ID, rejected.ID, " "); !errors.Is(err, ErrInvalidPublication) {
		t.Fatalf("reasonless Go review rejection accepted: %v", err)
	}
	if err := service.RejectReservation(ctx, publisher, workspace.ID, repo.ID, rejected.ID, "synthetic reason"); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("publisher rejected their own upload as reviewer: %v", err)
	}
	for range 2 {
		if err := service.RejectReservation(ctx, reader, workspace.ID, repo.ID, rejected.ID, "synthetic reason"); err != nil {
			t.Fatalf("Go review rejection or retry failed: %v", err)
		}
	}
	var rejectedStatus, rejectedReason string
	var rejectedVerified int
	if err := db.QueryRowContext(ctx, `SELECT u.status, u.object_verified, d.reason FROM registry_go_upload_sessions u JOIN registry_go_review_decisions d ON d.upload_session_id = u.upload_session_id WHERE u.upload_session_id = `+bind(1)+` AND d.decision = 'rejected'`, rejected.ID).Scan(&rejectedStatus, &rejectedVerified, &rejectedReason); err != nil || rejectedStatus != "rejected" || rejectedVerified != 1 || rejectedReason != "synthetic reason" {
		t.Fatalf("Go rejection state=%q verified=%d err=%v", rejectedStatus, rejectedVerified, err)
	}
	rejectedReplacement, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, rejectedRequest)
	if err != nil || rejectedReplacement.ID == rejected.ID {
		t.Fatalf("Go review rejection did not release identity: %v", err)
	}
	if err := service.CancelReservation(ctx, publisher, workspace.ID, repo.ID, rejectedReplacement.ID); err != nil {
		t.Fatal(err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_go_review_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'go.upload.approved' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := service.ApproveReservation(ctx, reader, workspace.ID, repo.ID, publication.ID); err == nil {
			t.Fatal("Go review succeeded without audit")
		}
		var reviewer string
		if err := db.QueryRowContext(ctx, `SELECT reviewed_by FROM registry_go_upload_sessions WHERE upload_session_id = ?`, publication.ID).Scan(&reviewer); err != nil || reviewer != member {
			t.Fatalf("failed review audit changed reviewer: %q err=%v", reviewer, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_go_review_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.ApproveReservation(ctx, reader, workspace.ID, repo.ID, publication.ID); err != nil {
		t.Fatal(err)
	}
	revokingStore := &revokeOnOpen{Driver: store, revoke: func() error {
		return repoService.RevokeGoReviewer(ctx, owner, workspace.ID, repo.ID, reader)
	}}
	revokingService, err := NewService(db, driver, repoService, revokingStore, Options{StagingDirectory: staging, MaxZipBytes: 1 << 20, MaxFiles: 100, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := revokingService.PublishReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("reviewer revoked during publication readback was accepted: %v", err)
	}
	if _, err := repoService.GrantGoReviewer(ctx, owner, workspace.ID, repo.ID, reader); err != nil {
		t.Fatal(err)
	}
	if err := service.ApproveReservation(ctx, reader, workspace.ID, repo.ID, publication.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.ApproveReservation(ctx, reader, workspace.ID, repo.ID, publication.ID); err != nil {
		t.Fatalf("repeated review was not idempotent: %v", err)
	}
	if err := repoService.RevokeGoReviewer(ctx, owner, workspace.ID, repo.ID, reader); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_go_reviewer_grants SET revoked_at = NULL WHERE grant_id = `+bind(1), firstReviewerGrant); err == nil || !strings.Contains(err.Error(), "Go reviewer grant identity and revocation are immutable") {
		t.Fatalf("database allowed revoked reviewer capability to be revived: %v", err)
	}
	if err := service.PublishReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("revoked reviewer approval remained valid: %v", err)
	}
	secondReviewerGrant, err := repoService.GrantGoReviewer(ctx, owner, workspace.ID, repo.ID, reader)
	if err != nil || secondReviewerGrant == firstReviewerGrant {
		t.Fatalf("reviewer regrant did not create a new capability: %v", err)
	}
	if err := service.PublishReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("regrant revived an old approval: %v", err)
	}
	if err := service.ApproveReservation(ctx, reader, workspace.ID, repo.ID, publication.ID); err != nil {
		t.Fatal(err)
	}
	var decisionID string
	if err := db.QueryRowContext(ctx, `SELECT decision_id FROM registry_go_review_decisions WHERE upload_session_id = `+bind(1)+` AND decision = 'approved' ORDER BY decision_id LIMIT 1`, publication.ID).Scan(&decisionID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_go_review_decisions WHERE decision_id = `+bind(1), decisionID); err == nil || !strings.Contains(err.Error(), "Go review decisions are immutable") {
		t.Fatalf("database allowed Go review history deletion: %v", err)
	}
	if err := repoService.RevokeRepositoryRole(ctx, owner, workspace.ID, repo.ID, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if err := service.ApproveReservation(ctx, reader, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("review accepted while publisher grant was revoked: %v", err)
	}
	if _, err := repoService.GrantRepositoryRole(ctx, owner, workspace.ID, repo.ID, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if err := service.PublishReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("publisher regrant revived an old approval: %v", err)
	}
	if err := service.ApproveReservation(ctx, reader, workspace.ID, repo.ID, publication.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repoService.SetGoReviewPolicy(ctx, owner, workspace.ID, repo.ID, 0, false); !errors.Is(err, repositories.ErrReviewPolicyRevision) {
		t.Fatalf("stale review policy update accepted: %v", err)
	}
	if _, err := repoService.SetGoReviewPolicy(ctx, owner, workspace.ID, repo.ID, 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_go_upload_sessions SET review_hold = 0 WHERE upload_session_id = `+bind(1), publication.ID); err == nil || !strings.Contains(err.Error(), "Go upload identity and verified object are immutable") {
		t.Fatalf("database allowed a pending review hold to be cleared: %v", err)
	}
	if err := service.PublishReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("disabling review released an existing held upload: %v", err)
	}
	if err := service.ApproveReservation(ctx, reader, workspace.ID, repo.ID, publication.ID); err != nil {
		t.Fatal(err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_go_publication_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'go.module.published' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := service.PublishReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID); err == nil {
			t.Fatal("Go publication succeeded without audit")
		}
		if _, err := service.GetVersion(ctx, reader, workspace.ID, repo.ID, modulePath, publicationRequest.Version); !errors.Is(err, ErrModuleUnavailable) {
			t.Fatalf("failed audit left Go publication visible: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_go_publication_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	publicationResults := make(chan error, 2)
	for range 2 {
		go func() {
			publicationResults <- service.PublishReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID)
		}()
	}
	for range 2 {
		if err := <-publicationResults; err != nil {
			t.Fatalf("Go publication or identical retry failed: %v", err)
		}
	}
	published, err := service.GetVersion(ctx, reader, workspace.ID, repo.ID, modulePath, publicationRequest.Version)
	if err != nil || published.ZipKey.SHA256 != publicationRequest.ZipSHA256 {
		t.Fatalf("Go published receipt not visible: %v", err)
	}
	var publishedStatus string
	if err := db.QueryRowContext(ctx, `SELECT status FROM registry_go_upload_sessions WHERE upload_session_id = `+bind(1), publication.ID).Scan(&publishedStatus); err != nil || publishedStatus != "published" {
		t.Fatalf("Go publication receipt status=%q err=%v", publishedStatus, err)
	}
	status, err = service.GetReservation(ctx, publisher, workspace.ID, repo.ID, publication.ID)
	if err != nil || status.Status != "published" {
		t.Fatalf("published Go reservation status=%+v err=%v", status, err)
	}
	policy, err = repoService.LogicalQuotaPolicy(ctx, owner, workspace.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	transferredLimit := publishedUsage + publicationRequest.ZipSize + int64(len(mod)) + int64(len(genericData)*2)
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", policy.Revision, &transferredLimit); err != nil {
		t.Fatal(err)
	}
	transferUpload, err := artifactService.StartUpload(ctx, publisher, workspace.ID, genericRepo.ID, artifacts.StartUploadRequest{Collection: "quota-transfer", Version: "v1", Path: "fixture.bin", ContentType: "application/octet-stream", Size: int64(len(genericData)), SHA256: hex.EncodeToString(genericHash[:])})
	if err != nil {
		t.Fatalf("published Go reservation was double-counted: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_generic_upload_sessions SET status = 'expired' WHERE upload_session_id = `+bind(1), transferUpload.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repoService.SetLogicalQuotaPolicy(ctx, owner, workspace.ID, "", policy.Revision+1, nil); err != nil {
		t.Fatal(err)
	}
	expiringArchive := archiveFor("v2.13.0")
	expiringDigest := sha256.Sum256(expiringArchive)
	expiringRequest := ReservationRequest{ModulePath: modulePath, Version: "v2.13.0", SourceTime: time.Now().UTC(), ModBytes: mod, ZipSize: int64(len(expiringArchive)), ZipSHA256: hex.EncodeToString(expiringDigest[:])}
	expiring, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, expiringRequest)
	if err != nil {
		t.Fatal(err)
	}
	stalled := &pausedReader{reader: bytes.NewReader(expiringArchive), started: make(chan struct{}), release: make(chan struct{})}
	stalledResult := make(chan error, 1)
	go func() {
		stalledResult <- service.ReceiveReservation(ctx, publisher, workspace.ID, repo.ID, expiring.ID, stalled)
	}()
	select {
	case <-stalled.started:
	case <-ctx.Done():
		close(stalled.release)
		t.Fatal("expiring Go upload did not begin")
	}
	expired, expireErr := service.ExpireUploadBatch(ctx, expiring.ExpiresAt.Add(time.Second), 1)
	close(stalled.release)
	stalledErr := <-stalledResult
	if expireErr != nil || expired != 1 || !errors.Is(stalledErr, ErrReservationUnavailable) {
		t.Fatalf("expired Go claim was not fenced: expired=%d expiry=%v receive=%v", expired, expireErr, stalledErr)
	}
	var expiredStatus string
	var expiredClaim sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT status, upload_claim_id FROM registry_go_upload_sessions WHERE upload_session_id = `+bind(1), expiring.ID).Scan(&expiredStatus, &expiredClaim); err != nil || expiredStatus != "expired" || expiredClaim.Valid {
		t.Fatalf("expired Go upload status=%q claim=%t err=%v", expiredStatus, expiredClaim.Valid, err)
	}
	expiryRetry, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, expiringRequest)
	if err != nil || expiryRetry.ID == expiring.ID {
		t.Fatalf("expired Go identity was not released: %+v err=%v", expiryRetry, err)
	}
	if err := service.CancelReservation(ctx, publisher, workspace.ID, repo.ID, expiryRetry.ID); err != nil {
		t.Fatal(err)
	}
	if err := repoService.RevokeRepositoryRole(ctx, owner, workspace.ID, repo.ID, reader, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetVersion(ctx, reader, workspace.ID, repo.ID, modulePath, "v2.0.0"); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("revoked reader could read module: %v", err)
	}
	revokedArchive := archiveFor("v2.12.0")
	revokedDigest := sha256.Sum256(revokedArchive)
	revokedReservation, err := service.ReservePublication(ctx, publisher, workspace.ID, repo.ID, ReservationRequest{ModulePath: modulePath, Version: "v2.12.0", SourceTime: time.Now().UTC(), ModBytes: mod, ZipSize: int64(len(revokedArchive)), ZipSHA256: hex.EncodeToString(revokedDigest[:])})
	if err != nil {
		t.Fatal(err)
	}
	revokedReceive := &revokeReader{reader: bytes.NewReader(revokedArchive), revoke: func() error {
		return repoService.RevokeRepositoryRole(ctx, owner, workspace.ID, repo.ID, publisher, repositories.GrantPublisher)
	}}
	if err := service.ReceiveReservation(ctx, publisher, workspace.ID, repo.ID, revokedReservation.ID, revokedReceive); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("revoked publisher completed Go receipt: %v", err)
	}
	var revokedStatus string
	if err := db.QueryRowContext(ctx, `SELECT status FROM registry_go_upload_sessions WHERE upload_session_id = `+bind(1), revokedReservation.ID).Scan(&revokedStatus); err != nil || revokedStatus != "receiving" {
		t.Fatalf("revoked Go receipt state=%q err=%v", revokedStatus, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_go_upload_sessions SET status = 'expired' WHERE upload_session_id = `+bind(1), revokedReservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repoService.GrantRepositoryRole(ctx, owner, workspace.ID, repo.ID, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	revokedUpload := &revokeReader{reader: bytes.NewReader(archiveFor("v2.2.0")), revoke: func() error {
		return repoService.RevokeRepositoryRole(ctx, owner, workspace.ID, repo.ID, publisher, repositories.GrantPublisher)
	}}
	if err := service.Publish(ctx, publisher, workspace.ID, repo.ID, modulePath, "v2.2.0", time.Now(), mod, revokedUpload); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("publisher revoked during upload could commit: %v", err)
	}
	var revokedCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_go_module_versions WHERE version = `+bind(1), "v2.2.0").Scan(&revokedCount); err != nil || revokedCount != 0 {
		t.Fatalf("revoked publication count=%d err=%v", revokedCount, err)
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatalf("Go module staging not cleaned: entries=%d err=%v", len(entries), err)
	}
	var audit int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_audit_events WHERE action = 'go.module.published'`).Scan(&audit); err != nil || audit != 4 {
		t.Fatalf("Go module publication audit=%d err=%v", audit, err)
	}
	if _, err := service.GetVersion(ctx, publisher, workspace.ID, repo.ID, modulePath, strings.Repeat("x", 300)); err == nil {
		t.Fatal("invalid version accepted")
	}
}

func assertSQLiteGoRecovery(t *testing.T, ctx context.Context, db *sql.DB, root, workspaceID, repositoryID, genericRepositoryID, readerID, memberID, modulePath string, expectedZip []byte, genericFileID string, genericData []byte, goReservationID string, remote storage.Driver) {
	t.Helper()
	snapshot := filepath.Join(root, "go-snapshot.sqlite")
	if _, err := sqlitebackup.Snapshot(ctx, db, snapshot, sqlitebackup.Options{PagesPerStep: 16}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var installationID string
	if err := db.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installationID); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	trusted := backup.GenericSetRecovery{Signer: public, InstallationID: installationID, BackupID: uuid.NewString(), SnapshotSHA256: hex.EncodeToString(digest[:])}
	parent := filepath.Join(root, "isolated-recovery")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	uri := url.URL{Scheme: "file", Path: snapshot}
	query := uri.Query()
	query.Set("mode", "ro")
	uri.RawQuery = query.Encode()
	snapshotDB, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshotDB.Close() })
	tx, err := snapshotDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	genericInventory, inventoryErr := backup.InventoryGeneric(ctx, tx, 10, 10)
	var goInventory []backup.GenericObject
	if inventoryErr == nil {
		goInventory, inventoryErr = backup.InventoryGo(ctx, tx, 10, 10)
	}
	rollbackErr := tx.Rollback()
	if inventoryErr != nil || rollbackErr != nil || len(goInventory) != 4 || len(genericInventory) != 1 {
		t.Fatalf("snapshot inventory Go=%d generic=%d inventory=%v rollback=%v", len(goInventory), len(genericInventory), inventoryErr, rollbackErr)
	}
	trusted.Inventory = goInventory
	genericTrust := trusted
	genericTrust.Inventory = genericInventory
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	source, err := storage.NewFileSystem(filepath.Join(root, "go-storage"))
	if err != nil {
		t.Fatal(err)
	}
	if remote == nil {
		remote, err = storage.NewFileSystem(filepath.Join(root, "encrypted-backup"))
		if err != nil {
			t.Fatal(err)
		}
	}
	stageDir := filepath.Join(root, "backup-staging")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	newStage := func() (backup.RecoveryStage, error) {
		file, err := os.CreateTemp(stageDir, "owned-*")
		if err != nil {
			return nil, err
		}
		return recoveryStage{File: file}, nil
	}
	genericCaptured, err := backup.CaptureGenericSet(ctx, genericTrust, source, remote, identity.Recipient(), private, 1<<20, newStage)
	if err != nil || len(genericCaptured.Receipts) != len(genericInventory) {
		t.Fatalf("capture generic objects receipts=%d err=%v", len(genericCaptured.Receipts), err)
	}
	set := genericCaptured.Set
	if _, err := backup.PrepareSQLiteRecovery(ctx, bytes.NewReader(data), 64<<20, 10, 10, set, genericTrust, parent, "prepared"); err == nil || !strings.Contains(err.Error(), "generic-only") {
		t.Fatalf("generic-only recovery did not reject Go catalog: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "prepared", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("failed recovery did not retain its marker:", err)
	}
	captured, err := backup.CaptureGoSet(ctx, trusted, source, remote, identity.Recipient(), private, 1<<20, newStage)
	if err != nil || len(captured.Receipts) != len(goInventory) {
		t.Fatalf("capture Go objects receipts=%d err=%v", len(captured.Receipts), err)
	}
	var encrypted bytes.Buffer
	if _, err := backup.EncryptSnapshot(ctx, bytes.NewReader(data), &encrypted, 64<<20, 65<<20, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	snapshotObject, err := remote.Put(ctx, workspaceID, bytes.NewReader(encrypted.Bytes()), int64(encrypted.Len()))
	if err != nil {
		t.Fatal("store encrypted snapshot:", err)
	}
	makeSources := func(receipts []backup.ObjectReceiptEnvelope) []backup.RecoveryObjectSource {
		t.Helper()
		sources := make([]backup.RecoveryObjectSource, 0, len(receipts))
		for _, envelope := range receipts {
			receipt, err := backup.VerifyObjectReceipt(envelope, public, trusted.InstallationID, trusted.BackupID)
			if err != nil {
				t.Fatal(err)
			}
			key := storage.ObjectKey{WorkspaceID: receipt.WorkspaceID, SHA256: receipt.CipherSHA256}
			sources = append(sources, backup.RecoveryObjectSource{Receipt: envelope, Open: func(ctx context.Context) (io.ReadCloser, error) {
				reader, _, err := remote.Open(ctx, key)
				return reader, err
			}})
		}
		return sources
	}
	genericSources, goSources := makeSources(genericCaptured.Receipts), makeSources(captured.Receipts)
	snapshotReader, _, err := remote.Open(ctx, snapshotObject.Key)
	if err != nil {
		t.Fatal("read encrypted snapshot from backup destination:", err)
	}
	prepared, prepareErr := backup.PrepareEncryptedSQLiteGoRecovery(ctx, snapshotReader, 65<<20, 64<<20, 10, 10, set, genericTrust, captured.Set, trusted, parent, "go-prepared", genericSources, goSources, identity, newStage)
	snapshotCloseErr := snapshotReader.Close()
	err = errors.Join(prepareErr, snapshotCloseErr)
	if err != nil || prepared.GoObjects != 4 || prepared.GenericObjects != 1 || prepared.InvalidatedUploads != 1 {
		t.Fatalf("prepare Go recovery=%+v err=%v", prepared, err)
	}
	dir := filepath.Dir(prepared.DatabasePath)
	if _, err := os.Stat(filepath.Join(dir, "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("Go recovery marker missing:", err)
	}
	recoveryCfg := config.Config{DataDir: dir, DatabaseDriver: config.SQLite, DatabaseDSN: prepared.DatabasePath, DatabaseMaxOpenConns: 2}
	recoveredDB, err := database.Open(ctx, recoveryCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recoveredDB.Close() })
	var recoveredReservationStatus string
	var invalidated int
	if err := recoveredDB.QueryRowContext(ctx, `SELECT status, recovery_invalidated FROM registry_go_upload_sessions WHERE upload_session_id = ?`, goReservationID).Scan(&recoveredReservationStatus, &invalidated); err != nil || recoveredReservationStatus != "uploaded" || invalidated != 1 {
		t.Fatalf("recovered Go reservation status=%q invalidated=%d err=%v", recoveredReservationStatus, invalidated, err)
	}
	if _, err := recoveredDB.ExecContext(ctx, `UPDATE registry_go_upload_sessions SET recovery_invalidated = 0 WHERE upload_session_id = ?`, goReservationID); err == nil || !strings.Contains(err.Error(), "Go upload identity and verified object are immutable") {
		t.Fatalf("database allowed recovered Go upload invalidation to be cleared: %v", err)
	}
	repositoriesService, err := repositories.New(recoveredDB, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	recoveredStore, err := storage.NewFileSystem(filepath.Join(dir, "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	recoveredService, err := NewService(recoveredDB, config.SQLite, repositoriesService, recoveredStore, Options{StagingDirectory: stageDir, MaxZipBytes: 1 << 20, MaxFiles: 100, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := recoveredService.OpenZip(ctx, memberID, workspaceID, repositoryID, modulePath, "v2.0.0"); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted recovered Go read: %v", err)
	}
	stream, _, err := recoveredService.OpenZip(ctx, readerID, workspaceID, repositoryID, modulePath, "v2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	restored, readErr := io.ReadAll(stream)
	closeErr := stream.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(restored, expectedZip) {
		t.Fatalf("restored Go ZIP read=%v close=%v", readErr, closeErr)
	}
	recoveredArtifacts, err := artifacts.New(recoveredDB, config.SQLite, repositoriesService, recoveredStore, artifacts.Options{MaxUploadBytes: 1 << 20, MaxConcurrentUploads: 1})
	if err != nil {
		t.Fatal(err)
	}
	genericStream, err := recoveredArtifacts.OpenFile(ctx, readerID, workspaceID, genericRepositoryID, genericFileID, 0, int64(len(genericData)))
	if err != nil {
		t.Fatal("open recovered generic object:", err)
	}
	gotGeneric, genericReadErr := io.ReadAll(genericStream.Reader)
	genericCloseErr := genericStream.Reader.Close()
	if genericReadErr != nil || genericCloseErr != nil || !bytes.Equal(gotGeneric, genericData) {
		t.Fatalf("recovered generic object read=%v close=%v", genericReadErr, genericCloseErr)
	}
	missingSnapshotReader, _, err := remote.Open(ctx, snapshotObject.Key)
	if err != nil {
		t.Fatal(err)
	}
	missingSources := append([]backup.RecoveryObjectSource(nil), goSources...)
	missingSources[len(missingSources)-1].Open = func(ctx context.Context) (io.ReadCloser, error) {
		reader, _, err := remote.Open(ctx, storage.ObjectKey{WorkspaceID: workspaceID, SHA256: strings.Repeat("0", 64)})
		return reader, err
	}
	missingResult, missingErr := backup.PrepareEncryptedSQLiteGoRecovery(ctx, missingSnapshotReader, 65<<20, 64<<20, 10, 10, set, genericTrust, captured.Set, trusted, parent, "missing-go-object", genericSources, missingSources, identity, newStage)
	missingCloseErr := missingSnapshotReader.Close()
	if missingErr == nil || missingResult.DatabasePath != "" || missingCloseErr != nil {
		t.Fatalf("missing Go object accepted result=%+v err=%v close=%v", missingResult, missingErr, missingCloseErr)
	}
	if _, err := os.Stat(filepath.Join(parent, "missing-go-object", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("failed Go recovery marker missing:", err)
	}
	sourceStream, _, err := source.Open(ctx, storage.ObjectKey{WorkspaceID: workspaceID, SHA256: hex.EncodeToString(sha256Sum(expectedZip))})
	if err != nil {
		t.Fatal("source object changed during recovery:", err)
	}
	sourceBytes, sourceReadErr := io.ReadAll(sourceStream)
	sourceCloseErr := sourceStream.Close()
	if sourceReadErr != nil || sourceCloseErr != nil || !bytes.Equal(sourceBytes, expectedZip) {
		t.Fatalf("source object changed read=%v close=%v", sourceReadErr, sourceCloseErr)
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("Go recovery staging retained entries=%d err=%v", len(entries), err)
	}
}

func sha256Sum(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}
