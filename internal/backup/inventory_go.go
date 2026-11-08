package backup

import (
	"context"
	"database/sql"
	"errors"

	"private-registry/internal/storage"
)

// InventoryGo enumerates ZIP objects referenced by a consistent snapshot.
// go.mod bytes are in the database snapshot. The caller must protect source
// objects from GC, impose SQL/resource limits and authenticate the snapshot;
// this inventory is not a complete installation backup or a GC pin.
func InventoryGo(ctx context.Context, snapshot *sql.Tx, maxObjects, maxReferences int) ([]GenericObject, error) {
	if ctx == nil || snapshot == nil || maxObjects < 1 || maxObjects > 1000000 || maxReferences < 1 || maxReferences > 10000000 {
		return nil, errors.New("Go backup inventory requires a snapshot and bounded object limit")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("Go backup inventory requires a deadline")
	}
	rows, err := snapshot.QueryContext(ctx, `SELECT workspace_id, zip_sha256, zip_size FROM registry_go_module_versions UNION ALL SELECT workspace_id, zip_sha256, zip_size FROM registry_go_upload_sessions WHERE object_verified = 1 ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, errors.New("Go backup inventory could not be read")
	}
	defer rows.Close()
	objects := make([]GenericObject, 0)
	references := 0
	for rows.Next() {
		references++
		if references > maxReferences {
			return nil, errors.New("Go backup reference inventory exceeds its limit")
		}
		var workspace, digest string
		var size int64
		if err := rows.Scan(&workspace, &digest, &size); err != nil {
			return nil, errors.New("Go backup object reference is invalid")
		}
		key, err := storage.NewObjectKey(workspace, digest)
		if err != nil || key.WorkspaceID != workspace || key.SHA256 != digest || size < 1 || size > 500<<20 {
			return nil, errors.New("Go backup object reference is invalid")
		}
		if len(objects) > 0 && objects[len(objects)-1].Key == key {
			if objects[len(objects)-1].Size != size {
				return nil, errors.New("Go backup object references have conflicting sizes")
			}
			continue
		}
		if len(objects) == maxObjects {
			return nil, errors.New("Go backup object inventory exceeds its limit")
		}
		objects = append(objects, GenericObject{Key: key, Size: size})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("Go backup inventory could not be iterated")
	}
	return objects, nil
}
