package backup

import (
	"context"
	"errors"
	"io"

	"filippo.io/age"
	"private-registry/internal/storage"
)

// EncryptGenericObject encrypts an inventoried object for an explicitly
// supplied recovery recipient while verifying its digest and size. Callers
// must discard all destination bytes on any error; successful encryption alone
// does not authenticate the backup manifest or prove recoverability.
func EncryptGenericObject(ctx context.Context, source storage.Driver, object GenericObject, destination io.Writer, recipient age.Recipient) error {
	if ctx == nil || source == nil || destination == nil || recipient == nil {
		return errors.New("generic backup encryption parameters are invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encrypted, err := age.Encrypt(destination, recipient)
	if err != nil {
		return errors.New("generic backup encryption could not begin")
	}
	copyErr := CopyGenericObject(ctx, source, object, encrypted)
	closeErr := encrypted.Close()
	if copyErr != nil || closeErr != nil {
		return errors.New("generic backup encryption or verification failed; discard output")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
