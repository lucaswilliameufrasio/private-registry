package backup

import (
	"context"
	"errors"
	"io"

	"filippo.io/age"
	"private-registry/internal/storage"
)

// RestoreGenericObject authenticates the entire encrypted object into empty,
// caller-owned private staging before writing to the destination. The caller
// must independently authenticate the inventory, choose an isolated recovery
// destination, provide exclusively owned private staging, bound its resources
// and discard staging after every call.
// A destination write can leave an orphan after an ambiguous failure; callers
// must not promote a recovery set until they have reconciled and verified it.
func RestoreGenericObject(ctx context.Context, ciphertext io.Reader, maxCiphertext int64, object GenericObject, identity age.Identity, staging io.ReadWriteSeeker, destination storage.Driver) error {
	if ctx == nil || ciphertext == nil || identity == nil || staging == nil || destination == nil {
		return errors.New("generic object recovery parameters are invalid")
	}
	end, err := staging.Seek(0, io.SeekEnd)
	if err != nil || end != 0 {
		return errors.New("generic object recovery requires empty staging")
	}
	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		return errors.New("generic object recovery staging cannot be rewound")
	}
	if err := DecryptGenericObject(ctx, ciphertext, maxCiphertext, object, staging, identity); err != nil {
		return err
	}
	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		return errors.New("generic object recovery staging cannot be rewound")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := destination.Put(ctx, object.Key.WorkspaceID, staging, object.Size)
	if err != nil {
		return errors.New("generic object recovery destination write failed")
	}
	if info.Key != object.Key || info.Size != object.Size {
		return errors.New("generic object recovery destination did not match inventory")
	}
	return nil
}
