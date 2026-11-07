// Package backup contains building blocks for future complete recovery sets.
// Inventory alone is not a backup and does not coordinate publication or GC.
package backup

import (
	"context"
	"database/sql"
	"errors"

	"private-registry/internal/storage"
)

// GenericObject is an object referenced by the generic catalog or an upload
// receipt. Identical objects in different workspaces remain distinct.
type GenericObject struct {
	Key  storage.ObjectKey
	Size int64
}

// InventoryGeneric reads a caller-provided consistent database snapshot. The
// caller must ensure objects remain available while copying: this function does
// not establish a snapshot, pin objects, or coordinate with garbage collection.
// Distinct objects and scanned references have separate bounds; exceeding
// either rejects the result rather than silently truncating it. The caller must
// provide a deadline and bound database resources, including the SQL sort.
func InventoryGeneric(ctx context.Context, snapshot *sql.Tx, maxObjects, maxReferences int) ([]GenericObject, error) {
	if ctx == nil || snapshot == nil || maxObjects < 1 || maxObjects > 1000000 || maxReferences < 1 || maxReferences > 10000000 {
		return nil, errors.New("generic backup inventory requires a snapshot and bounded object limit")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("generic backup inventory requires a context deadline")
	}
	rows, err := snapshot.QueryContext(ctx, `SELECT workspace_id, sha256, size_bytes FROM registry_generic_artifact_files
		UNION ALL
		SELECT workspace_id, object_sha256, object_size FROM registry_generic_upload_sessions WHERE object_sha256 IS NOT NULL
		ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, errors.New("generic backup inventory could not be read")
	}
	defer rows.Close()
	objects := make([]GenericObject, 0)
	references := 0
	for rows.Next() {
		references++
		if references > maxReferences {
			return nil, errors.New("generic backup reference inventory exceeds its limit")
		}
		var workspace, digest string
		var size int64
		if err := rows.Scan(&workspace, &digest, &size); err != nil {
			return nil, errors.New("generic backup object reference is invalid")
		}
		key, err := storage.NewObjectKey(workspace, digest)
		if err != nil || key.WorkspaceID != workspace || key.SHA256 != digest || size < 0 || size > 1<<30 {
			return nil, errors.New("generic backup object reference is invalid")
		}
		if len(objects) > 0 && objects[len(objects)-1].Key == key {
			if objects[len(objects)-1].Size != size {
				return nil, errors.New("generic backup object references have conflicting sizes")
			}
			continue
		}
		if len(objects) == maxObjects {
			return nil, errors.New("generic backup object inventory exceeds its limit")
		}
		objects = append(objects, GenericObject{Key: key, Size: size})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("generic backup inventory could not be iterated")
	}
	return objects, nil
}
