package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestVerifySQLiteIntegrityRejectsCorruptDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-corrupt.sqlite")
	if err := os.WriteFile(path, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := VerifySQLiteIntegrity(ctx, db); err == nil {
		t.Fatal("corrupt SQLite database was accepted")
	}
	if err := VerifySQLiteIntegrity(context.Background(), db); err == nil {
		t.Fatal("integrity check without a deadline was accepted")
	}
}
