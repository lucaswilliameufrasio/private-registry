// Package objectmaint holds offline maintenance of stored package objects:
// copying them between drivers and deleting objects nothing references. Both
// require that no registry process is serving, because the object store does
// not take part in database transactions.
package objectmaint

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/storage"
)

// KnownSchemaVersion is the newest schema whose object references this
// package knows. A newer schema may reference objects from tables listed
// nowhere here, so collection refuses to run against it.
const KnownSchemaVersion = 44

// referenceQueries list every column that can name a stored object. Rows are
// counted whatever their state: an object referenced by an expired upload or a
// rejected review is kept, which wastes space but never loses data.
var referenceQueries = []string{
	`SELECT workspace_id, sha256 FROM registry_generic_artifact_files`,
	`SELECT workspace_id, object_sha256 FROM registry_generic_upload_sessions WHERE object_sha256 IS NOT NULL`,
	`SELECT workspace_id, expected_sha256 FROM registry_generic_upload_sessions`,
	`SELECT workspace_id, zip_sha256 FROM registry_go_module_versions`,
	`SELECT workspace_id, zip_sha256 FROM registry_go_upload_sessions`,
	`SELECT workspace_id, archive_sha256 FROM registry_cargo_versions`,
	`SELECT workspace_id, archive_sha256 FROM registry_cargo_reservations`,
	`SELECT workspace_id, metadata_sha256 FROM registry_cargo_reservations`,
	`SELECT workspace_id, tarball_sha256 FROM registry_npm_versions`,
	`SELECT workspace_id, tarball_sha256 FROM registry_npm_reservations`,
	`SELECT workspace_id, metadata_sha256 FROM registry_npm_reservations`,
	`SELECT workspace_id, tarball_sha256 FROM registry_pub_versions`,
	`SELECT workspace_id, tarball_sha256 FROM registry_pub_reservations`,
	`SELECT workspace_id, metadata_sha256 FROM registry_pub_reservations`,
	`SELECT workspace_id, SUBSTR(digest, 8) FROM registry_oci_blobs`,
	// Manifests live in the database; their references are recorded too.
	`SELECT m.workspace_id, SUBSTR(r.referenced_digest, 8) FROM registry_oci_manifest_references r JOIN registry_oci_manifests m ON m.repository_id = r.repository_id AND m.digest = r.manifest_digest`,
}

// requiredQueries list the references that must have a stored object: what
// is published, and uploads whose object the registry already verified. This
// is what a backup has to contain.
var requiredQueries = []string{
	`SELECT workspace_id, sha256 FROM registry_generic_artifact_files`,
	`SELECT workspace_id, object_sha256 FROM registry_generic_upload_sessions WHERE object_sha256 IS NOT NULL AND status IN ('uploaded', 'published')`,
	`SELECT workspace_id, zip_sha256 FROM registry_go_module_versions`,
	`SELECT workspace_id, zip_sha256 FROM registry_go_upload_sessions WHERE object_verified = 1`,
	`SELECT workspace_id, archive_sha256 FROM registry_cargo_versions`,
	`SELECT workspace_id, archive_sha256 FROM registry_cargo_reservations WHERE object_verified = 1`,
	`SELECT workspace_id, tarball_sha256 FROM registry_npm_versions`,
	`SELECT workspace_id, tarball_sha256 FROM registry_npm_reservations WHERE object_verified = 1`,
	`SELECT workspace_id, tarball_sha256 FROM registry_pub_versions`,
	`SELECT workspace_id, tarball_sha256 FROM registry_pub_reservations WHERE object_verified = 1`,
	`SELECT workspace_id, SUBSTR(digest, 8) FROM registry_oci_blobs`,
}

// RequiredObjectsTx returns the objects that must exist for the database in
// tx to be served, inside the caller's transaction.
func RequiredObjectsTx(ctx context.Context, tx *sql.Tx) (map[storage.ObjectKey]struct{}, error) {
	return collectReferences(ctx, tx, requiredQueries)
}

// ReferencedObjects reads every object reference in one read transaction.
func ReferencedObjects(ctx context.Context, db *sql.DB, driver config.DatabaseDriver) (map[storage.ObjectKey]struct{}, error) {
	if db == nil || ctx == nil {
		return nil, errors.New("object reference parameters are invalid")
	}
	options := &sql.TxOptions{ReadOnly: true}
	if driver == config.Postgres {
		options.Isolation = sql.LevelRepeatableRead
	}
	tx, err := db.BeginTx(ctx, options)
	if err != nil {
		return nil, errors.New("object references could not be read")
	}
	defer func() { _ = tx.Rollback() }()
	return ReferencedObjectsTx(ctx, tx)
}

// ReferencedObjectsTx reads every object reference inside the caller's
// transaction, for callers that need the references consistent with another
// read of the same snapshot.
func ReferencedObjectsTx(ctx context.Context, tx *sql.Tx) (map[storage.ObjectKey]struct{}, error) {
	if tx == nil || ctx == nil {
		return nil, errors.New("object reference parameters are invalid")
	}
	return collectReferences(ctx, tx, referenceQueries)
}

func collectReferences(ctx context.Context, tx *sql.Tx, queries []string) (map[storage.ObjectKey]struct{}, error) {
	if err := requireKnownSchema(ctx, tx); err != nil {
		return nil, err
	}
	referenced := make(map[storage.ObjectKey]struct{})
	for _, query := range queries {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return nil, errors.New("object references could not be read")
		}
		for rows.Next() {
			var workspace, digest string
			if err := rows.Scan(&workspace, &digest); err != nil {
				_ = rows.Close()
				return nil, errors.New("object reference could not be read")
			}
			key, err := storage.NewObjectKey(workspace, digest)
			if err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("object reference %s/%s is malformed; refusing to continue", workspace, digest)
			}
			referenced[key] = struct{}{}
		}
		if err := rows.Close(); err != nil {
			return nil, errors.New("object references could not be read")
		}
		if err := rows.Err(); err != nil {
			return nil, errors.New("object references could not be read")
		}
	}
	return referenced, nil
}

type CollectionReport struct {
	Scanned       int
	Referenced    int
	TooRecent     int
	Unreferenced  int
	Deleted       int
	DeletedBytes  int64
	UnrefBytes    int64
	FirstFailures []string
}

// Collect deletes stored objects that no table references and that are older
// than grace. With apply false it only reports. The grace period covers clock
// skew and objects written just before serve stopped.
func Collect(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, store storage.Driver, now time.Time, grace time.Duration, apply bool) (CollectionReport, error) {
	if grace < time.Hour {
		return CollectionReport{}, errors.New("object collection grace must be at least one hour")
	}
	walker, ok := store.(storage.Walker)
	if !ok {
		return CollectionReport{}, errors.New("object storage cannot be listed")
	}
	referenced, err := ReferencedObjects(ctx, db, driver)
	if err != nil {
		return CollectionReport{}, err
	}
	var report CollectionReport
	cutoff := now.Add(-grace)
	err = walker.Walk(ctx, func(object storage.ListedObject) error {
		report.Scanned++
		if _, keep := referenced[object.Key]; keep {
			report.Referenced++
			return nil
		}
		if object.Modified.IsZero() || object.Modified.After(cutoff) {
			report.TooRecent++
			return nil
		}
		report.Unreferenced++
		report.UnrefBytes += object.Size
		if !apply {
			return nil
		}
		if err := store.Delete(ctx, object.Key); err != nil {
			if len(report.FirstFailures) < 10 {
				report.FirstFailures = append(report.FirstFailures, object.Key.WorkspaceID+"/"+object.Key.SHA256)
			}
			return nil
		}
		report.Deleted++
		report.DeletedBytes += object.Size
		return nil
	})
	if err != nil {
		return report, err
	}
	if len(report.FirstFailures) > 0 {
		return report, fmt.Errorf("%d objects could not be deleted", report.Unreferenced-report.Deleted)
	}
	return report, nil
}

type CopyReport struct {
	Copied int
	Bytes  int64
}

// Copy writes every object of source into destination, verifying the digest
// on both sides. It never deletes from source and can be repeated: objects
// already present are verified and skipped by the destination driver.
func Copy(ctx context.Context, source, destination storage.Driver, maxObjectBytes int64, progress func(CopyReport)) (CopyReport, error) {
	walker, ok := source.(storage.Walker)
	if !ok {
		return CopyReport{}, errors.New("source object storage cannot be listed")
	}
	var report CopyReport
	err := walker.Walk(ctx, func(object storage.ListedObject) error {
		reader, info, err := source.Open(ctx, object.Key)
		if err != nil {
			return fmt.Errorf("source object %s/%s could not be read or failed verification: %w", object.Key.WorkspaceID, object.Key.SHA256, err)
		}
		written, putErr := destination.Put(ctx, object.Key.WorkspaceID, io.LimitReader(reader, info.Size+1), maxObjectBytes)
		closeErr := reader.Close()
		if putErr != nil || closeErr != nil {
			return fmt.Errorf("object %s/%s could not be copied: %w", object.Key.WorkspaceID, object.Key.SHA256, errors.Join(putErr, closeErr))
		}
		if written.Key != object.Key || written.Size != info.Size {
			return fmt.Errorf("object %s/%s changed while being copied", object.Key.WorkspaceID, object.Key.SHA256)
		}
		report.Copied++
		report.Bytes += info.Size
		if progress != nil && report.Copied%100 == 0 {
			progress(report)
		}
		return nil
	})
	return report, err
}

func requireKnownSchema(ctx context.Context, tx *sql.Tx) error {
	var count, minimum, maximum int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MIN(version_id), 0), COALESCE(MAX(version_id), 0) FROM registry_migration_checksums`).Scan(&count, &minimum, &maximum); err != nil || count != KnownSchemaVersion || minimum != 1 || maximum != KnownSchemaVersion {
		return fmt.Errorf("database schema is not version %d; object maintenance does not know its references", KnownSchemaVersion)
	}
	return nil
}
