package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrInvalidObjectKey  = errors.New("object key is invalid")
	ErrObjectTooLarge    = errors.New("object exceeds the configured size limit")
	ErrObjectIntegrity   = errors.New("stored object failed integrity verification")
	ErrObjectPermissions = errors.New("object storage permissions are not private")
)

type FileSystem struct {
	root string
}

func NewFileSystem(root string) (*FileSystem, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("filesystem storage root is required")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("filesystem storage root must be a valid path")
	}
	absoluteRoot = filepath.Clean(absoluteRoot)
	if err := os.MkdirAll(absoluteRoot, 0o700); err != nil {
		return nil, errors.New("filesystem storage root could not be created")
	}
	if err := requirePrivateDirectory(absoluteRoot); err != nil {
		return nil, errors.Join(errors.New("filesystem storage root is unsafe"), err)
	}
	for _, directory := range []string{"staging", "objects", filepath.Join("objects", "workspaces")} {
		if err := ensurePrivateDirectory(filepath.Join(absoluteRoot, directory)); err != nil {
			return nil, errors.Join(errors.New("filesystem storage directories could not be initialized"), err)
		}
	}
	return &FileSystem{root: absoluteRoot}, nil
}

func NewObjectKey(workspaceID string, digest string) (ObjectKey, error) {
	workspaceUUID, err := uuid.Parse(workspaceID)
	if err != nil {
		return ObjectKey{}, ErrInvalidObjectKey
	}
	digest = strings.ToLower(digest)
	if len(digest) != sha256.Size*2 {
		return ObjectKey{}, ErrInvalidObjectKey
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return ObjectKey{}, ErrInvalidObjectKey
	}
	return ObjectKey{WorkspaceID: workspaceUUID.String(), SHA256: digest}, nil
}

func (s *FileSystem) Put(
	ctx context.Context,
	workspaceID string,
	source io.Reader,
	maxBytes int64,
) (ObjectInfo, error) {
	if s == nil || ctx == nil || source == nil {
		return ObjectInfo{}, errors.New("filesystem storage, context, and source are required")
	}
	if err := ctx.Err(); err != nil {
		return ObjectInfo{}, err
	}
	workspaceUUID, err := uuid.Parse(workspaceID)
	if err != nil {
		return ObjectInfo{}, ErrInvalidObjectKey
	}
	if maxBytes < 0 || maxBytes == int64(^uint64(0)>>1) {
		return ObjectInfo{}, errors.New("object size limit must be non-negative and bounded")
	}

	stagingDirectory := filepath.Join(s.root, "staging")
	if err := requirePrivateDirectory(stagingDirectory); err != nil {
		return ObjectInfo{}, errors.New("object staging directory is unsafe")
	}
	temporary, err := os.CreateTemp(stagingDirectory, "object-*")
	if err != nil {
		return ObjectInfo{}, errors.New("object staging file could not be created")
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryPath)
	}()

	digest := sha256.New()
	limited := &io.LimitedReader{R: contextReader{ctx: ctx, reader: source}, N: maxBytes + 1}
	size, copyErr := io.Copy(io.MultiWriter(temporary, digest), limited)
	if copyErr != nil {
		_ = temporary.Close()
		return ObjectInfo{}, errors.Join(errors.New("object stream could not be staged"), copyErr)
	}
	if size > maxBytes {
		_ = temporary.Close()
		return ObjectInfo{}, ErrObjectTooLarge
	}
	if err := ctx.Err(); err != nil {
		_ = temporary.Close()
		return ObjectInfo{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return ObjectInfo{}, errors.New("staged object could not be synchronized")
	}
	if err := temporary.Close(); err != nil {
		return ObjectInfo{}, errors.New("staged object could not be closed")
	}

	key, err := NewObjectKey(workspaceUUID.String(), hex.EncodeToString(digest.Sum(nil)))
	if err != nil {
		return ObjectInfo{}, err
	}
	destination, err := s.objectPath(key, true)
	if err != nil {
		return ObjectInfo{}, err
	}
	if err := os.Link(temporaryPath, destination); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return ObjectInfo{}, errors.New("immutable object could not be finalized")
		}
		existingFile, existingInfo, verifyErr := s.openVerified(ctx, key)
		if verifyErr != nil {
			return ObjectInfo{}, errors.Join(errors.New("existing object is not a valid immutable object"), verifyErr)
		}
		if closeErr := existingFile.Close(); closeErr != nil {
			return ObjectInfo{}, errors.New("existing object could not be closed after verification")
		}
		if existingInfo.Size != size {
			return ObjectInfo{}, ErrObjectIntegrity
		}
		return existingInfo, nil
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return ObjectInfo{}, errors.New("finalized object directory could not be synchronized")
	}
	return ObjectInfo{Key: key, Size: size}, nil
}

func (s *FileSystem) Open(ctx context.Context, key ObjectKey) (io.ReadCloser, ObjectInfo, error) {
	return s.openVerified(ctx, key)
}

func (s *FileSystem) OpenRange(
	ctx context.Context,
	key ObjectKey,
	offset int64,
	length int64,
) (io.ReadCloser, ObjectInfo, error) {
	file, info, err := s.openVerified(ctx, key)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	if offset < 0 || length < 0 || offset > info.Size || length > info.Size-offset {
		_ = file.Close()
		return nil, ObjectInfo{}, ErrInvalidObjectKey
	}
	return &sectionReadCloser{
		SectionReader: io.NewSectionReader(file, offset, length),
		closer:        file,
	}, info, nil
}

func (s *FileSystem) Delete(ctx context.Context, key ObjectKey) error {
	if s == nil || ctx == nil {
		return errors.New("filesystem storage and context are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.objectPath(key, false)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("object availability could not be checked")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return ErrObjectPermissions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.New("object could not be deleted")
	}
	return syncDirectory(filepath.Dir(path))
}

func (s *FileSystem) openVerified(ctx context.Context, key ObjectKey) (*os.File, ObjectInfo, error) {
	if s == nil || ctx == nil {
		return nil, ObjectInfo{}, errors.New("filesystem storage and context are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, ObjectInfo{}, err
	}
	canonicalKey, err := NewObjectKey(key.WorkspaceID, key.SHA256)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	path, err := s.objectPath(canonicalKey, false)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ObjectInfo{}, fs.ErrNotExist
		}
		return nil, ObjectInfo{}, errors.New("object metadata could not be read")
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o077 != 0 {
		return nil, ObjectInfo{}, ErrObjectPermissions
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ObjectInfo{}, errors.New("object could not be opened")
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, ObjectInfo{}, errors.New("opened object metadata could not be read")
	}
	if !fileInfo.Mode().IsRegular() || !os.SameFile(pathInfo, fileInfo) || fileInfo.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, ObjectInfo{}, ErrObjectPermissions
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, contextReader{ctx: ctx, reader: file}); err != nil {
		_ = file.Close()
		return nil, ObjectInfo{}, errors.Join(errors.New("object could not be verified"), err)
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, ObjectInfo{}, err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != canonicalKey.SHA256 {
		_ = file.Close()
		return nil, ObjectInfo{}, ErrObjectIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, ObjectInfo{}, errors.New("verified object could not be rewound")
	}
	return file, ObjectInfo{Key: canonicalKey, Size: fileInfo.Size()}, nil
}

func (s *FileSystem) objectPath(key ObjectKey, createDirectories bool) (string, error) {
	if s == nil {
		return "", errors.New("filesystem storage is unavailable")
	}
	canonicalKey, err := NewObjectKey(key.WorkspaceID, key.SHA256)
	if err != nil {
		return "", err
	}
	directories := []string{
		s.root,
		filepath.Join(s.root, "objects"),
		filepath.Join(s.root, "objects", "workspaces"),
		filepath.Join(s.root, "objects", "workspaces", canonicalKey.WorkspaceID),
		filepath.Join(s.root, "objects", "workspaces", canonicalKey.WorkspaceID, canonicalKey.SHA256[:2]),
	}
	for _, directory := range directories {
		if createDirectories {
			if err := ensurePrivateDirectory(directory); err != nil {
				return "", errors.New("object directory is unsafe")
			}
			continue
		}
		if err := requirePrivateDirectory(directory); err != nil {
			return "", errors.Join(errors.New("object directory is unsafe"), err)
		}
	}
	return filepath.Join(directories[len(directories)-1], canonicalKey.SHA256), nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return requirePrivateDirectory(path)
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: path is not a real directory", ErrObjectPermissions)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ErrObjectPermissions
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

type sectionReadCloser struct {
	*io.SectionReader
	closer io.Closer
}

func (r *sectionReadCloser) Close() error {
	return r.closer.Close()
}

var _ Driver = (*FileSystem)(nil)
