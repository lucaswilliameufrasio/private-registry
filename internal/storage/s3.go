package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3 is an unwired, initial S3-compatible driver. It assumes a separately
// qualified backend with atomic conditional puts and private staging storage.
type S3 struct {
	client    *s3.Client
	bucket    string
	prefix    string
	staging   string
	maxObject int64
}

func NewS3(client *s3.Client, bucket, prefix, staging string, maxObjectBytes int64) (*S3, error) {
	if client == nil || strings.TrimSpace(bucket) != bucket || bucket == "" || strings.TrimSpace(staging) == "" || maxObjectBytes < 1 || maxObjectBytes == int64(^uint64(0)>>1) {
		return nil, errors.New("S3 client, bucket, private staging and bounded object size are required")
	}
	if strings.Trim(prefix, "/") != prefix || strings.ContainsAny(prefix, "\\\x00") {
		return nil, errors.New("S3 object prefix is invalid")
	}
	for _, part := range strings.Split(prefix, "/") {
		if part == "." || part == ".." || (part == "" && prefix != "") {
			return nil, errors.New("S3 object prefix is invalid")
		}
	}
	staging, err := filepath.Abs(staging)
	if err != nil {
		return nil, errors.New("S3 staging path is invalid")
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return nil, errors.New("S3 staging directory could not be created")
	}
	if err := requirePrivateDirectory(staging); err != nil {
		return nil, errors.New("S3 staging directory is unsafe")
	}
	return &S3{client: client, bucket: bucket, prefix: prefix, staging: staging, maxObject: maxObjectBytes}, nil
}

func (s *S3) objectName(key ObjectKey) (string, ObjectKey, error) {
	canonical, err := NewObjectKey(key.WorkspaceID, key.SHA256)
	if err != nil {
		return "", ObjectKey{}, err
	}
	name := "workspaces/" + canonical.WorkspaceID + "/sha256/" + canonical.SHA256
	if s.prefix != "" {
		name = s.prefix + "/" + name
	}
	return name, canonical, nil
}

func (s *S3) validate(ctx context.Context) error {
	if s == nil || s.client == nil || ctx == nil {
		return errors.New("S3 storage and context are required")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("S3 storage operation requires a context deadline")
	}
	return ctx.Err()
}

func (s *S3) Put(ctx context.Context, workspaceID string, source io.Reader, maxBytes int64) (info ObjectInfo, retErr error) {
	if err := s.validate(ctx); err != nil {
		return ObjectInfo{}, err
	}
	if source == nil || maxBytes < 0 || maxBytes > s.maxObject {
		return ObjectInfo{}, errors.New("S3 source and bounded upload size are required")
	}
	if _, err := NewObjectKey(workspaceID, strings.Repeat("0", 64)); err != nil {
		return ObjectInfo{}, err
	}
	file, err := s.createStaging()
	if err != nil {
		return ObjectInfo{}, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			info = ObjectInfo{}
			retErr = errors.Join(retErr, err)
		}
	}()
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hasher), &io.LimitedReader{R: contextReader{ctx: ctx, reader: source}, N: maxBytes + 1})
	if err != nil {
		if ctx.Err() != nil {
			return ObjectInfo{}, ctx.Err()
		}
		return ObjectInfo{}, errors.New("S3 object could not be staged")
	}
	if size > maxBytes {
		return ObjectInfo{}, ErrObjectTooLarge
	}
	if err := ctx.Err(); err != nil {
		return ObjectInfo{}, err
	}
	key, err := NewObjectKey(workspaceID, hex.EncodeToString(hasher.Sum(nil)))
	if err != nil {
		return ObjectInfo{}, err
	}
	name, key, err := s.objectName(key)
	if err != nil {
		return ObjectInfo{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ObjectInfo{}, errors.New("S3 staging file could not be rewound")
	}
	_, putErr := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(name), Body: file.File,
		ContentLength: aws.Int64(size), IfNoneMatch: aws.String("*"),
	})
	if err := ctx.Err(); err != nil {
		return ObjectInfo{}, err
	}
	// Verify even on success: remote checksums and ETags are not proof that the
	// object at this key has the intended bytes. On an ambiguous failure this
	// also safely recognizes a prior completed write or matching existing object.
	verified, info, verifyErr := s.openVerified(ctx, key)
	if verifyErr != nil {
		if putErr != nil {
			return ObjectInfo{}, errors.New("conditional S3 object write failed or its result is unknown")
		}
		return ObjectInfo{}, errors.New("written S3 object could not be verified")
	}
	if err := verified.Close(); err != nil || info.Size != size {
		return ObjectInfo{}, ErrObjectIntegrity
	}
	return info, nil
}

func (s *S3) Open(ctx context.Context, key ObjectKey) (io.ReadCloser, ObjectInfo, error) {
	file, info, err := s.openVerified(ctx, key)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	return file, info, nil
}

func (s *S3) OpenRange(ctx context.Context, key ObjectKey, offset, length int64) (io.ReadCloser, ObjectInfo, error) {
	file, info, err := s.openVerified(ctx, key)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	if offset < 0 || length < 0 || offset > info.Size || length > info.Size-offset {
		_ = file.Close()
		return nil, ObjectInfo{}, ErrInvalidObjectKey
	}
	return &sectionReadCloser{SectionReader: io.NewSectionReader(file.File, offset, length), closer: file}, info, nil
}

func (s *S3) Delete(ctx context.Context, key ObjectKey) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	name, _, err := s.objectName(key)
	if err != nil {
		return err
	}
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(name)}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("S3 object could not be deleted")
	}
	return nil
}

func (s *S3) openVerified(ctx context.Context, key ObjectKey) (*s3StagedFile, ObjectInfo, error) {
	if err := s.validate(ctx); err != nil {
		return nil, ObjectInfo{}, err
	}
	name, key, err := s.objectName(key)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(name)})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ObjectInfo{}, ctx.Err()
		}
		return nil, ObjectInfo{}, errors.New("S3 object could not be read")
	}
	if result.Body == nil {
		return nil, ObjectInfo{}, ErrObjectIntegrity
	}
	defer result.Body.Close()
	if result.ContentLength == nil || *result.ContentLength < 0 || *result.ContentLength > s.maxObject {
		return nil, ObjectInfo{}, ErrObjectIntegrity
	}
	file, err := s.createStaging()
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hasher), &io.LimitedReader{R: contextReader{ctx: ctx, reader: result.Body}, N: s.maxObject + 1})
	if ctx.Err() != nil {
		_ = file.Close()
		return nil, ObjectInfo{}, ctx.Err()
	}
	if err != nil || size != *result.ContentLength || size > s.maxObject || hex.EncodeToString(hasher.Sum(nil)) != key.SHA256 {
		_ = file.Close()
		return nil, ObjectInfo{}, ErrObjectIntegrity
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, ObjectInfo{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, ObjectInfo{}, errors.New("verified S3 object could not be rewound")
	}
	return file, ObjectInfo{Key: key, Size: size}, nil
}

func (s *S3) createStaging() (*s3StagedFile, error) {
	if err := requirePrivateDirectory(s.staging); err != nil {
		return nil, errors.New("S3 staging directory is unsafe")
	}
	file, err := os.CreateTemp(s.staging, "s3-object-*")
	if err != nil {
		return nil, errors.New("S3 staging file could not be created")
	}
	return &s3StagedFile{File: file, path: file.Name()}, nil
}

type s3StagedFile struct {
	*os.File
	path string
}

func (f *s3StagedFile) Close() error {
	closeErr := f.File.Close()
	removeErr := os.Remove(f.path)
	if closeErr != nil || removeErr != nil {
		return errors.New("S3 staging file cleanup failed")
	}
	return nil
}
