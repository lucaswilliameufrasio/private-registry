package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestFileSystemPutOpenAndOpenRange(t *testing.T) {
	store := newTestFileSystem(t)
	workspaceID := uuid.NewString()
	payload := []byte("private generic artifact bytes")

	object, err := store.Put(context.Background(), workspaceID, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal("put object:", err)
	}
	wantDigest := sha256.Sum256(payload)
	if object.Size != int64(len(payload)) || object.Key.SHA256 != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("object metadata = %+v; want size %d and SHA-256 %x", object, len(payload), wantDigest)
	}

	reader, opened, err := store.Open(context.Background(), object.Key)
	if err != nil {
		t.Fatal("open verified object:", err)
	}
	openedBytes, err := io.ReadAll(reader)
	if closeErr := reader.Close(); closeErr != nil {
		t.Fatal("close object:", closeErr)
	}
	if err != nil {
		t.Fatal("read object:", err)
	}
	if !bytes.Equal(openedBytes, payload) || opened != object {
		t.Fatalf("opened object = %q / %+v; want %q / %+v", openedBytes, opened, payload, object)
	}

	rangeReader, rangeInfo, err := store.OpenRange(context.Background(), object.Key, 8, 9)
	if err != nil {
		t.Fatal("open object range:", err)
	}
	rangeBytes, err := io.ReadAll(rangeReader)
	if closeErr := rangeReader.Close(); closeErr != nil {
		t.Fatal("close object range:", closeErr)
	}
	if err != nil {
		t.Fatal("read object range:", err)
	}
	if !bytes.Equal(rangeBytes, payload[8:17]) || rangeInfo != object {
		t.Fatalf("range = %q / %+v; want %q / %+v", rangeBytes, rangeInfo, payload[8:17], object)
	}
}

func TestFileSystemPutDeduplicatesOnlyWithinWorkspace(t *testing.T) {
	store := newTestFileSystem(t)
	workspaceOne := uuid.NewString()
	workspaceTwo := uuid.NewString()
	payload := []byte("same bytes, separate security scopes")

	first, err := store.Put(context.Background(), workspaceOne, bytes.NewReader(payload), 128)
	if err != nil {
		t.Fatal("put first object:", err)
	}
	duplicate, err := store.Put(context.Background(), workspaceOne, bytes.NewReader(payload), 128)
	if err != nil {
		t.Fatal("put duplicate object:", err)
	}
	otherWorkspace, err := store.Put(context.Background(), workspaceTwo, bytes.NewReader(payload), 128)
	if err != nil {
		t.Fatal("put object in second workspace:", err)
	}
	if duplicate.Key != first.Key || otherWorkspace.Key == first.Key {
		t.Fatalf("deduplication keys: first=%+v duplicate=%+v second workspace=%+v", first, duplicate, otherWorkspace)
	}
}

func TestFileSystemStoresZeroByteObjects(t *testing.T) {
	store := newTestFileSystem(t)
	object, err := store.Put(context.Background(), uuid.NewString(), bytes.NewReader(nil), 0)
	if err != nil {
		t.Fatal("put zero-byte object:", err)
	}
	if object.Size != 0 {
		t.Fatalf("zero-byte object size = %d; want 0", object.Size)
	}
	reader, info, err := store.Open(context.Background(), object.Key)
	if err != nil {
		t.Fatal("open zero-byte object:", err)
	}
	content, err := io.ReadAll(reader)
	if closeErr := reader.Close(); closeErr != nil {
		t.Fatal("close zero-byte object:", closeErr)
	}
	if err != nil || len(content) != 0 || info.Size != 0 {
		t.Fatalf("zero-byte object read = %q info=%+v err=%v", content, info, err)
	}
}

func TestFileSystemPutRejectsOversizeAndRemovesStagingFile(t *testing.T) {
	store := newTestFileSystem(t)
	_, err := store.Put(context.Background(), uuid.NewString(), bytes.NewReader([]byte("12345")), 4)
	if !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("oversized put error = %v; want ErrObjectTooLarge", err)
	}
	entries, err := os.ReadDir(filepath.Join(store.root, "staging"))
	if err != nil {
		t.Fatal("read staging directory:", err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging files after rejected put = %d; want 0", len(entries))
	}
	workspaceEntries, err := os.ReadDir(filepath.Join(store.root, "objects", "workspaces"))
	if err != nil {
		t.Fatal("read workspace object directory:", err)
	}
	if len(workspaceEntries) != 0 {
		t.Fatalf("published workspace directories after rejected put = %d; want 0", len(workspaceEntries))
	}
}

func TestFileSystemPutHonorsCanceledContext(t *testing.T) {
	store := newTestFileSystem(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := store.Put(ctx, uuid.NewString(), bytes.NewReader([]byte("not accepted")), 128)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled put error = %v; want context.Canceled", err)
	}
}

func TestFileSystemOpenRejectsCorruptedObject(t *testing.T) {
	store := newTestFileSystem(t)
	payload := []byte("integrity protected")
	object, err := store.Put(context.Background(), uuid.NewString(), bytes.NewReader(payload), 128)
	if err != nil {
		t.Fatal("put object:", err)
	}
	path, err := store.objectPath(object.Key, false)
	if err != nil {
		t.Fatal("resolve object path:", err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal("tamper test object:", err)
	}
	reader, _, err := store.Open(context.Background(), object.Key)
	if reader != nil {
		_ = reader.Close()
	}
	if !errors.Is(err, ErrObjectIntegrity) {
		t.Fatalf("corrupt object open error = %v; want ErrObjectIntegrity", err)
	}
}

func TestFileSystemDeleteIsIdempotentAndDoesNotAcceptInvalidKeys(t *testing.T) {
	store := newTestFileSystem(t)
	object, err := store.Put(context.Background(), uuid.NewString(), bytes.NewReader([]byte("delete me")), 128)
	if err != nil {
		t.Fatal("put object:", err)
	}
	if err := store.Delete(context.Background(), object.Key); err != nil {
		t.Fatal("delete object:", err)
	}
	if err := store.Delete(context.Background(), object.Key); err != nil {
		t.Fatal("repeat object delete:", err)
	}
	_, _, err = store.Open(context.Background(), object.Key)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open deleted object error = %v; want os.ErrNotExist", err)
	}
	if err := store.Delete(context.Background(), ObjectKey{WorkspaceID: "../../outside", SHA256: strings.Repeat("0", 64)}); !errors.Is(err, ErrInvalidObjectKey) {
		t.Fatalf("invalid key delete error = %v; want ErrInvalidObjectKey", err)
	}
}

func TestFileSystemConcurrentPutFinalizesOneImmutableObject(t *testing.T) {
	store := newTestFileSystem(t)
	workspaceID := uuid.NewString()
	payload := bytes.Repeat([]byte("concurrent object data "), 2048)
	const writers = 12
	results := make(chan ObjectInfo, writers)
	errorsFound := make(chan error, writers)
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			object, err := store.Put(context.Background(), workspaceID, bytes.NewReader(payload), int64(len(payload)))
			if err != nil {
				errorsFound <- err
				return
			}
			results <- object
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent put failed: %v", err)
	}
	var first ObjectInfo
	count := 0
	for result := range results {
		if count == 0 {
			first = result
		} else if result != first {
			t.Errorf("concurrent put result = %+v; want %+v", result, first)
		}
		count++
	}
	if count != writers {
		t.Fatalf("successful concurrent writes = %d; want %d", count, writers)
	}
}

func TestFileSystemRejectsUnsafeRootAndObjectPermissions(t *testing.T) {
	root := t.TempDir()
	unsafeRoot := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafeRoot, 0o755); err != nil {
		t.Fatal("create unsafe root:", err)
	}
	if _, err := NewFileSystem(unsafeRoot); !errors.Is(err, ErrObjectPermissions) {
		t.Fatalf("unsafe root error = %v; want ErrObjectPermissions", err)
	}

	store := newTestFileSystem(t)
	object, err := store.Put(context.Background(), uuid.NewString(), bytes.NewReader([]byte("private")), 128)
	if err != nil {
		t.Fatal("put object:", err)
	}
	path, err := store.objectPath(object.Key, false)
	if err != nil {
		t.Fatal("resolve object path:", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal("make object permissions unsafe:", err)
	}
	if _, _, err := store.Open(context.Background(), object.Key); !errors.Is(err, ErrObjectPermissions) {
		t.Fatalf("unsafe object error = %v; want ErrObjectPermissions", err)
	}
}

func TestFileSystemRejectsSymlinkedObjectDirectory(t *testing.T) {
	store := newTestFileSystem(t)
	object, err := store.Put(context.Background(), uuid.NewString(), bytes.NewReader([]byte("private bytes")), 128)
	if err != nil {
		t.Fatal("put object:", err)
	}
	path, err := store.objectPath(object.Key, false)
	if err != nil {
		t.Fatal("resolve object path:", err)
	}
	prefixDirectory := filepath.Dir(path)
	if err := os.Remove(path); err != nil {
		t.Fatal("remove original object:", err)
	}
	if err := os.Remove(prefixDirectory); err != nil {
		t.Fatal("remove original prefix directory:", err)
	}
	externalDirectory := filepath.Join(t.TempDir(), "external")
	if err := os.Mkdir(externalDirectory, 0o700); err != nil {
		t.Fatal("create external directory:", err)
	}
	externalObject := filepath.Join(externalDirectory, object.Key.SHA256)
	if err := os.WriteFile(externalObject, []byte("private bytes"), 0o600); err != nil {
		t.Fatal("create external object:", err)
	}
	if err := os.Symlink(externalDirectory, prefixDirectory); err != nil {
		t.Fatal("replace prefix with symlink:", err)
	}

	if _, _, err := store.Open(context.Background(), object.Key); !errors.Is(err, ErrObjectPermissions) {
		t.Fatalf("open through symlink error = %v; want ErrObjectPermissions", err)
	}
	if err := store.Delete(context.Background(), object.Key); !errors.Is(err, ErrObjectPermissions) {
		t.Fatalf("delete through symlink error = %v; want ErrObjectPermissions", err)
	}
	if _, err := os.Stat(externalObject); err != nil {
		t.Fatalf("external object was unexpectedly affected: %v", err)
	}
}

func newTestFileSystem(t *testing.T) *FileSystem {
	t.Helper()
	store, err := NewFileSystem(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal("create filesystem store:", err)
	}
	return store
}
