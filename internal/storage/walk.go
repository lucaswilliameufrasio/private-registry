package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ListedObject is one stored object found by Walk.
type ListedObject struct {
	Key      ObjectKey
	Size     int64
	Modified time.Time
}

// Walker enumerates stored objects. It is meant for offline maintenance:
// objects written while a walk runs may or may not be reported.
type Walker interface {
	Walk(ctx context.Context, visit func(ListedObject) error) error
}

// Walk reports every object below objects/workspaces. Entries that do not
// match the layout this driver writes are skipped, never deleted.
func (s *FileSystem) Walk(ctx context.Context, visit func(ListedObject) error) error {
	if s == nil || ctx == nil || visit == nil {
		return errors.New("filesystem walk parameters are invalid")
	}
	root := filepath.Join(s.root, "objects", "workspaces")
	workspaces, err := os.ReadDir(root)
	if err != nil {
		return errors.New("object workspaces could not be listed")
	}
	for _, workspace := range workspaces {
		if !workspace.IsDir() {
			continue
		}
		prefixes, err := os.ReadDir(filepath.Join(root, workspace.Name()))
		if err != nil {
			return errors.New("object prefixes could not be listed")
		}
		for _, prefix := range prefixes {
			if !prefix.IsDir() || len(prefix.Name()) != 2 {
				continue
			}
			entries, err := os.ReadDir(filepath.Join(root, workspace.Name(), prefix.Name()))
			if err != nil {
				return errors.New("objects could not be listed")
			}
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					return err
				}
				key, err := NewObjectKey(workspace.Name(), entry.Name())
				if err != nil || key.WorkspaceID != workspace.Name() || key.SHA256 != entry.Name() || !strings.HasPrefix(entry.Name(), prefix.Name()) || !entry.Type().IsRegular() {
					continue
				}
				info, err := entry.Info()
				if err != nil {
					return errors.New("object could not be inspected")
				}
				if err := visit(ListedObject{Key: key, Size: info.Size(), Modified: info.ModTime()}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Walk lists the objects under the driver's prefix. Keys outside the layout
// written by Put are skipped.
func (s *S3) Walk(ctx context.Context, visit func(ListedObject) error) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if visit == nil {
		return errors.New("S3 walk callback is required")
	}
	root := "workspaces/"
	if s.prefix != "" {
		root = s.prefix + "/" + root
	}
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(root)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("S3 objects could not be listed")
		}
		for _, object := range page.Contents {
			if object.Key == nil || object.Size == nil {
				continue
			}
			workspace, rest, found := strings.Cut(strings.TrimPrefix(*object.Key, root), "/sha256/")
			if !found {
				continue
			}
			key, err := NewObjectKey(workspace, rest)
			if err != nil || key.WorkspaceID != workspace || key.SHA256 != rest {
				continue
			}
			listed := ListedObject{Key: key, Size: *object.Size}
			if object.LastModified != nil {
				listed.Modified = *object.LastModified
			}
			if err := visit(listed); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *BoundedDriver) Walk(ctx context.Context, visit func(ListedObject) error) error {
	walker, ok := s.driver.(Walker)
	if !ok {
		return errors.New("object storage cannot be listed")
	}
	return walker.Walk(ctx, visit)
}

func (s *DeadlineDriver) Walk(ctx context.Context, visit func(ListedObject) error) error {
	walker, ok := s.driver.(Walker)
	if !ok {
		return errors.New("object storage cannot be listed")
	}
	return walker.Walk(ctx, visit)
}
