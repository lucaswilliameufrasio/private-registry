package backup

import (
	"context"
	"database/sql"
	"errors"

	"private-registry/internal/storage"
)

// InventoryPub enumerates verified receipts and published archive references
// from one caller-owned consistent snapshot. Identical workspace-scoped bytes
// are deduplicated, while conflicting sizes fail closed. This is neither a GC
// pin nor a complete signed manifest or proof of object availability.
func InventoryPub(ctx context.Context, snapshot *sql.Tx, maxObjects, maxReferences int) ([]GenericObject, error) {
	if ctx == nil || snapshot == nil || maxObjects < 1 || maxObjects > 1000000 || maxReferences < 1 || maxReferences > 10000000 {
		return nil, errors.New("Pub backup inventory requires a snapshot and bounded limits")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("Pub backup inventory requires a deadline")
	}
	rows, err := snapshot.QueryContext(ctx, `SELECT workspace_id, tarball_sha256, tarball_size FROM registry_pub_versions UNION ALL SELECT workspace_id, tarball_sha256, tarball_size FROM registry_pub_reservations WHERE object_verified = 1 ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, errors.New("Pub backup inventory could not be read")
	}
	defer rows.Close()
	objects := make([]GenericObject, 0)
	references := 0
	for rows.Next() {
		references++
		if references > maxReferences {
			return nil, errors.New("Pub backup reference inventory exceeds its limit")
		}
		var workspace, digest string
		var size int64
		if err := rows.Scan(&workspace, &digest, &size); err != nil {
			return nil, errors.New("Pub backup object reference is invalid")
		}
		key, err := storage.NewObjectKey(workspace, digest)
		if err != nil || key.WorkspaceID != workspace || key.SHA256 != digest || size < 1 || size > 64<<20 {
			return nil, errors.New("Pub backup object reference is invalid")
		}
		if len(objects) > 0 && objects[len(objects)-1].Key == key {
			if objects[len(objects)-1].Size != size {
				return nil, errors.New("Pub backup object references have conflicting sizes")
			}
			continue
		}
		if len(objects) == maxObjects {
			return nil, errors.New("Pub backup object inventory exceeds its limit")
		}
		objects = append(objects, GenericObject{Key: key, Size: size})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("Pub backup inventory could not be iterated")
	}
	return objects, nil
}
