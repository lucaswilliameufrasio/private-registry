package artifacts

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestExpireUploadBatchIsBoundedAndIdempotent(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
	actor := fixture.userIDs["publisher"]
	first := startFixtureUpload(t, fixture, actor, "expire", "v1", "a", []byte("a"))
	second := startFixtureUpload(t, fixture, actor, "expire", "v1", "b", []byte("b"))
	active := startFixtureUpload(t, fixture, actor, "expire", "v1", "c", []byte("c"))
	now := time.Now().UTC()
	old := now.Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_generic_upload_sessions SET expires_at = ? WHERE upload_session_id = ?`, old, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_generic_upload_sessions SET expires_at = ?, status = 'uploading', upload_claim_id = ? WHERE upload_session_id = ?`, old, uuid.NewString(), second.ID); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{1, 1, 0} {
		got, err := fixture.service.ExpireUploadBatch(ctx, now, 1)
		if err != nil || got != want {
			t.Fatalf("expiration count = %d, error = %v; want %d", got, err, want)
		}
	}
	for _, id := range []string{first.ID, second.ID} {
		var status string
		var claim sql.NullString
		if err := fixture.db.QueryRowContext(ctx, `SELECT status, upload_claim_id FROM registry_generic_upload_sessions WHERE upload_session_id = ?`, id).Scan(&status, &claim); err != nil {
			t.Fatal(err)
		}
		if status != "expired" || claim.Valid {
			t.Fatalf("expired session has status %q and claim %v", status, claim)
		}
	}
	var status string
	if err := fixture.db.QueryRowContext(ctx, `SELECT status FROM registry_generic_upload_sessions WHERE upload_session_id = ?`, active.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "receiving" {
		t.Fatalf("unexpired session status = %q; want receiving", status)
	}
	if _, err := fixture.service.ExpireUploadBatch(ctx, now, maxExpirationBatch+1); err == nil {
		t.Fatal("unbounded expiration batch was accepted")
	}
}
