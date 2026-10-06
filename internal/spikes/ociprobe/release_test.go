//go:build integration

package ociprobe

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

var errReleaseIneligible = errors.New("fixture release not verified or no longer eligible")

// Experimental SQL boundary only, not product schema or a complete coordinator.
// Publication state and qualified routes commit together with a current policy
// check. A remote 201 never adds a route on its own.
func releaseVerified(ctx context.Context, db *sql.DB, attempt string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE attempts SET phase='published'
		WHERE id=? AND phase='verified' AND EXISTS(SELECT 1 FROM policy WHERE publisher_allowed=1)`, attempt)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errReleaseIneligible
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO visible(path,attempt)
		SELECT path,attempt FROM candidate_routes WHERE attempt=?`, attempt); err != nil {
		return err
	}
	return tx.Commit()
}

func TestOCIDurableReleaseReconcilesRemoteCommitWithoutPrematureVisibility(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	directory, err := os.MkdirTemp("/tmp/opencode", "oci-release-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil { // Owned synthetic fixture only.
			t.Error(err)
		}
	})
	backend := startStorageRegistry(t, ctx, directory, filepath.Join(directory, "storage"), false)
	seed := filepath.Join(directory, "seed")
	root := imageLayout(t, seed)
	if count, err := verifyGraph(seed, root); err != nil || count != 6 {
		t.Fatal("invalid seed graph:", count, err)
	}
	indexBytes, err := os.ReadFile(filepath.Join(seed, "blobs", "sha256", strings.TrimPrefix(root.Digest, "sha256:")))
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Manifests []ociDescriptor `json:"manifests"`
	}
	if err := json.Unmarshal(indexBytes, &index); err != nil || len(index.Manifests) != 2 {
		t.Fatal("invalid fixture index")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(seed, "blobs", "sha256", strings.TrimPrefix(index.Manifests[0].Digest, "sha256:")))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Layers []ociDescriptor `json:"layers"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil || len(manifest.Layers) != 1 {
		t.Fatal("invalid fixture layer")
	}
	layerDigest := manifest.Layers[0].Digest
	dbPath := filepath.Join(directory, "release.db")
	var db *sql.DB
	open := func() {
		t.Helper()
		uri := &url.URL{Scheme: "file", Path: dbPath}
		db, err = sql.Open("sqlite", uri.String()+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		if err := db.PingContext(ctx); err != nil {
			t.Fatal(err)
		}
	}
	open()
	defer func() { _ = db.Close() }()
	execSQL := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	execSQL(`CREATE TABLE policy(publisher_allowed integer NOT NULL CHECK(publisher_allowed IN(0,1)));
		INSERT INTO policy VALUES(1);
		CREATE TABLE attempts(id text PRIMARY KEY, repository text NOT NULL UNIQUE, digest text NOT NULL,
			phase text NOT NULL CHECK(phase IN('prepared','verified','published','rejected')));
		CREATE TABLE candidate_routes(path text PRIMARY KEY, attempt text NOT NULL REFERENCES attempts(id));
		CREATE TABLE visible(path text PRIMARY KEY, attempt text NOT NULL REFERENCES attempts(id));`)
	prepare := func(id string) string {
		t.Helper()
		repo := "fixture/" + id + "/image"
		execSQL("INSERT INTO attempts VALUES(?,?,?,'prepared')", id, repo, root.Digest)
		execSQL("INSERT INTO candidate_routes VALUES(?,?)", "/v2/"+repo+"/manifests/multi", id)
		entries, err := os.ReadDir(filepath.Join(seed, "blobs", "sha256"))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			hash := "sha256:" + entry.Name()
			execSQL("INSERT INTO candidate_routes VALUES(?,?)", "/v2/"+repo+"/blobs/"+hash, id)
			data, err := os.ReadFile(filepath.Join(seed, "blobs", "sha256", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), `"schemaVersion":2`) {
				execSQL("INSERT INTO candidate_routes VALUES(?,?)", "/v2/"+repo+"/manifests/"+hash, id)
			}
		}
		// Internal staging call, not fake native success through the consumer gate.
		reference := strings.TrimPrefix(backend.server.URL, "http://") + "/" + repo
		orasStorage(t, ctx, directory, "cp", "--from-oci-layout", "--to-plain-http", "seed:multi", reference+":multi")
		return repo
	}
	reconcile := func(id, repo, expectedDigest string) error {
		// Re-read actual motor content after losing the remote receipt. Never
		// promote based only on an old 201 or presence of a tag.
		layout := "reconcile-" + id
		reference := strings.TrimPrefix(backend.server.URL, "http://") + "/" + repo
		if actual := orasStorage(t, ctx, directory, "resolve", "--plain-http", reference+":multi"); actual != expectedDigest {
			return errors.New("fixture tag differs from prepared digest")
		}
		orasStorage(t, ctx, directory, "cp", "--from-plain-http", "--to-oci-layout", reference+"@"+expectedDigest, layout+":multi")
		expected := root
		expected.Digest = expectedDigest
		if _, err := verifyGraph(filepath.Join(directory, layout), expected); err != nil {
			return err
		}
		result, err := db.ExecContext(ctx, "UPDATE attempts SET phase='verified' WHERE id=? AND digest=? AND phase='prepared'", id, expectedDigest)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return errReleaseIneligible
		}
		return nil
	}
	startGate := func() *httptest.Server {
		upstream, _ := url.Parse(backend.server.URL)
		proxy := httputil.NewSingleHostReverseProxy(upstream)
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				http.NotFound(w, r)
				return
			}
			var count int
			err := db.QueryRowContext(r.Context(), `SELECT count(*) FROM visible v JOIN attempts a ON a.id=v.attempt
				WHERE v.path=? AND a.phase='published'`, r.URL.Path).Scan(&count)
			if err != nil {
				http.Error(w, "release state unavailable", http.StatusServiceUnavailable)
				return
			}
			if count != 1 {
				http.NotFound(w, r)
				return
			}
			proxy.ServeHTTP(w, r)
		}))
	}
	gate := startGate()
	defer func() { gate.Close() }()
	client := &http.Client{Timeout: 5 * time.Second}
	check := func(method, base, repo, suffix string, want int) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+"/v2/"+repo+suffix, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Accept", indexMedia+", "+manifestMedia)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s %s %s: got %d want %d", method, repo, suffix, response.StatusCode, want)
		}
	}
	baseline := prepare("baseline")
	if err := reconcile("baseline", baseline, root.Digest); err != nil {
		t.Fatal(err)
	}
	if err := releaseVerified(ctx, db, "baseline"); err != nil {
		t.Fatal(err)
	}
	check("GET", gate.URL, baseline, "/manifests/multi", 200)
	revoked := prepare("revoked")
	if err := reconcile("revoked", revoked, root.Digest); err != nil {
		t.Fatal(err)
	}
	execSQL("UPDATE policy SET publisher_allowed=0")
	if err := releaseVerified(ctx, db, "revoked"); !errors.Is(err, errReleaseIneligible) {
		t.Fatal("remote commit ignored current revocation:", err)
	}
	execSQL("UPDATE attempts SET phase='rejected' WHERE id='revoked'")
	interrupted := prepare("interrupted") // Receipt not recorded: remains prepared.
	check("GET", backend.server.URL, interrupted, "/manifests/multi", 200)
	check("GET", backend.server.URL, interrupted, "/blobs/"+layerDigest, 200)
	check("GET", gate.URL, interrupted, "/manifests/multi", 404)
	gate.Close()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	open() // Reopen disk state; not a SIGKILL/power-loss or multi-host experiment.
	gate = startGate()
	for _, repo := range []string{revoked, interrupted} {
		for _, method := range []string{"GET", "HEAD"} {
			check(method, gate.URL, repo, "/manifests/multi", 404)
			check(method, gate.URL, repo, "/manifests/"+root.Digest, 404)
			check(method, gate.URL, repo, "/blobs/"+layerDigest, 404)
		}
	}
	check("GET", gate.URL, baseline, "/manifests/multi", 200)
	execSQL("UPDATE policy SET publisher_allowed=1")
	if err := releaseVerified(ctx, db, "interrupted"); !errors.Is(err, errReleaseIneligible) {
		t.Fatal("unreconciled receipt promoted:", err)
	}
	if err := releaseVerified(ctx, db, "revoked"); !errors.Is(err, errReleaseIneligible) {
		t.Fatal("rejected receipt revived after permission restored:", err)
	}
	if err := reconcile("interrupted", interrupted, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("unexpected engine digest accepted by reconciliation")
	}
	if err := reconcile("interrupted", interrupted, root.Digest); err != nil {
		t.Fatal(err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := releaseVerified(canceled, db, "interrupted"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled release succeeded:", err)
	}
	// Inject a real SQL failure AFTER the phase UPDATE; the transaction must
	// rollback both phase and routes, never expose a partially written graph.
	execSQL(`CREATE TRIGGER fail_release BEFORE INSERT ON visible
		WHEN NEW.attempt='interrupted' AND EXISTS(SELECT 1 FROM visible WHERE attempt='interrupted')
		BEGIN SELECT RAISE(ABORT,'injected second route write failure'); END`)
	if err := releaseVerified(ctx, db, "interrupted"); err == nil {
		t.Fatal("route write failure ignored")
	}
	var phase string
	if err := db.QueryRowContext(ctx, "SELECT phase FROM attempts WHERE id='interrupted'").Scan(&phase); err != nil || phase != "verified" {
		t.Fatal("SQL failure did not rollback phase:", phase, err)
	}
	var routes int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM visible WHERE attempt='interrupted'").Scan(&routes); err != nil || routes != 0 {
		t.Fatal("SQL failure left partial reachable graph:", routes, err)
	}
	check("GET", gate.URL, interrupted, "/manifests/multi", 404)
	execSQL("DROP TRIGGER fail_release")
	if err := releaseVerified(ctx, db, "interrupted"); err != nil {
		t.Fatal(err)
	}
	check("GET", gate.URL, interrupted, "/manifests/multi", 200)
	check("HEAD", gate.URL, interrupted, "/manifests/"+root.Digest, 200)
	// ORAS consumes the graph through the released read-only gate after recovery.
	reference := strings.TrimPrefix(gate.URL, "http://") + "/" + interrupted
	orasStorage(t, ctx, directory, "cp", "--from-plain-http", "--to-oci-layout", reference+":multi", "consumer:multi")
	if count, err := verifyGraph(filepath.Join(directory, "consumer"), root); err != nil || count != 6 {
		t.Fatal("released consumer graph differs:", count, err)
	}
	if err := releaseVerified(ctx, db, "interrupted"); !errors.Is(err, errReleaseIneligible) {
		t.Fatal("published receipt released twice:", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	check("GET", gate.URL, baseline, "/manifests/multi", 503)
	gate.Close()
	open()
	gate = startGate()
	check("GET", gate.URL, baseline, "/manifests/multi", 200)
	check("GET", gate.URL, interrupted, "/blobs/"+layerDigest, 200)
	t.Logf("SQLite durable release: remote commits withheld across reopen, rejected receipt stays rejected, reconciled graph releases atomically; %s", root.Digest)
}
