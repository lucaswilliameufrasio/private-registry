// Package storage provides bounded, immutable object storage primitives.
// Callers remain responsible for authorizing a repository before opening an
// object and for coordinating object references with their catalog.
package storage

import (
	"context"
	"io"
)

type ObjectKey struct {
	WorkspaceID string
	SHA256      string
}

type ObjectInfo struct {
	Key  ObjectKey
	Size int64
}

type Driver interface {
	Put(ctx context.Context, workspaceID string, source io.Reader, maxBytes int64) (ObjectInfo, error)
	Open(ctx context.Context, key ObjectKey) (io.ReadCloser, ObjectInfo, error)
	OpenRange(ctx context.Context, key ObjectKey, offset int64, length int64) (io.ReadCloser, ObjectInfo, error)
	Delete(ctx context.Context, key ObjectKey) error
}
