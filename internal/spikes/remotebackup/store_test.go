package remotebackup

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestFixtureEndpointRestrictions(t *testing.T) {
	for _, endpoint := range []string{
		"https://s3.amazonaws.com", "http://192.168.1.10:9000", "http://localhost:9000",
		"http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:99999",
		"http://user:secret@127.0.0.1:9000", "http://127.0.0.1:9000/bucket",
		"http://127.0.0.1:9000?secret=no", "http://127.0.0.1:9000#fragment", "%broken",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := NewClient(endpoint, "test", "test-secret"); err == nil {
				t.Fatal("non-fixture endpoint accepted")
			}
		})
	}
	if _, err := NewClient("http://127.0.0.1:9000", "", ""); err == nil {
		t.Fatal("implicit credentials accepted")
	}
	if _, err := NewClient("http://127.0.0.1:9000/", "test", "test-secret"); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteValidationBeforeNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	store := Store{}
	if _, err := store.Upload(ctx, "missing", "", nil, nil); err == nil {
		t.Fatal("invalid upload accepted")
	}
	if err := store.Restore(ctx, "", filepath.Join(t.TempDir(), "unused"), nil, "", 0); err == nil {
		t.Fatal("invalid restore accepted")
	}
	client, err := NewClient("http://127.0.0.1:1", "test", "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	store = Store{Client: client, Bucket: "fixture"}
	if _, err := store.Upload(context.Background(), "missing", "key", nil, nil); err == nil {
		t.Fatal("unbounded context accepted")
	}
	if err := store.Restore(ctx, "key", "unused", nil, "bad-digest", 1); err == nil {
		t.Fatal("invalid recovery policy accepted")
	}
}
