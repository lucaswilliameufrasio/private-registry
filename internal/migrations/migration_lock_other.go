//go:build !linux

package migrations

import (
	"context"
	"database/sql"
	"errors"

	"private-registry/internal/config"
)

func acquireMigrationLock(
	_ context.Context,
	_ *sql.DB,
	_ config.DatabaseDriver,
	_ string,
) (func() error, error) {
	return nil, errors.New("database migrations are supported only on Linux")
}
