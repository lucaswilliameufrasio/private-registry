//go:build integration

package postgresbackup

import (
	"bufio"
	"io"
	"strings"
	"testing"
	"time"
)

// SQL-only coordinator probe, not a registry release implementation. PostgreSQL
// permits writes to independent rows that SQLite's global writer lock orders.
func TestPostgresReleaseRevocationRequiresSharedPolicyLock(t *testing.T) {
	for _, scenario := range []string{"predicate_only", "policy_lock_commit", "policy_lock_rollback", "revocation_first"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := operation(t)
			name := database(t, ctx)
			query(t, ctx, name, `CREATE TABLE policy(id integer PRIMARY KEY, publisher_allowed boolean NOT NULL);
				INSERT INTO policy VALUES(1,true);
				CREATE TABLE attempts(id integer PRIMARY KEY, phase text NOT NULL);
				INSERT INTO attempts VALUES(1,'verified');
				CREATE TABLE visible(path text PRIMARY KEY, attempt integer NOT NULL REFERENCES attempts(id));`)
			if isolation := query(t, ctx, name, "SHOW default_transaction_isolation;"); isolation != "read committed" {
				t.Fatal("unexpected isolation for PostgreSQL ordering probe:", isolation)
			}
			releaseSQL := `UPDATE attempts SET phase='published' WHERE id=1 AND phase='verified'
				AND EXISTS(SELECT 1 FROM policy WHERE id=1 AND publisher_allowed);
				INSERT INTO visible SELECT '/v2/fixture/image/manifests/v1', id FROM attempts WHERE id=1 AND phase='published';`
			if scenario == "revocation_first" {
				query(t, ctx, name, "UPDATE policy SET publisher_allowed=false WHERE id=1;")
				query(t, ctx, name, "BEGIN; SELECT id FROM policy WHERE id=1 FOR UPDATE; "+releaseSQL+" COMMIT;")
				if actual := query(t, ctx, name, "SELECT phase||':'||(SELECT count(*) FROM visible) FROM attempts;"); actual != "verified:0" {
					t.Fatal("acknowledged revocation did not prevent release:", actual)
				}
				return
			}
			releaser := fixtureTools.command(ctx, "psql", "--username=postgres", "--no-password", "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--dbname="+name)
			stdin, err := releaser.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := releaser.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var diagnostics cappedBuffer
			releaser.Stderr = &diagnostics
			if err := releaser.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				_ = stdin.Close()
				if !waited {
					_ = releaser.Wait()
				}
			}()
			lockSQL := ""
			if scenario != "predicate_only" {
				lockSQL = "SELECT id FROM policy WHERE id=1 FOR UPDATE;"
			}
			if _, err := io.WriteString(stdin, "BEGIN; "+lockSQL+releaseSQL+" SELECT 'release-held';\n"); err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(stdout)
			held := false
			for scanner.Scan() {
				if strings.TrimSpace(scanner.Text()) == "release-held" {
					held = true
					break
				}
			}
			if !held {
				t.Fatalf("release transaction did not reach controlled boundary: %v %s", scanner.Err(), diagnostics.String())
			}
			if actual := query(t, ctx, name, "SELECT phase||':'||(SELECT count(*) FROM visible) FROM attempts;"); actual != "verified:0" {
				t.Fatal("reader observed uncommitted release:", actual)
			}
			var finished chan error
			if scenario == "predicate_only" {
				// The conditional UPDATE reads policy but does not lock its row.
				// Revocation can commit while the release transaction is still open.
				query(t, ctx, name, "UPDATE policy SET publisher_allowed=false WHERE id=1;")
				if actual := query(t, ctx, name, "SELECT publisher_allowed FROM policy;"); actual != "f" {
					t.Fatal("revocation did not commit before release")
				}
			} else {
				finished = make(chan error, 1)
				revoker := fixtureTools.command(ctx, "psql", "--username=postgres", "--no-password", "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--dbname="+name)
				go func() {
					finished <- run(revoker, io.Discard, strings.NewReader("SET application_name='release-revoker'; UPDATE policy SET publisher_allowed=false WHERE id=1;"))
				}()
				// Observe the actual server wait, not an arbitrary timing delay.
				for query(t, ctx, name, "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name='release-revoker' AND wait_event_type='Lock';") != "1" {
					select {
					case err := <-finished:
						t.Fatalf("revocation completed without waiting for shared policy lock: %v", err)
					case <-ctx.Done():
						t.Fatal("policy lock wait not observed:", ctx.Err())
					case <-time.After(20 * time.Millisecond):
					}
				}
				if actual := query(t, ctx, name, "SELECT publisher_allowed FROM policy;"); actual != "t" {
					t.Fatal("waiting revocation was prematurely acknowledged")
				}
			}
			end := "COMMIT;\n"
			if scenario == "policy_lock_rollback" {
				end = "ROLLBACK;\n"
			}
			if _, err := io.WriteString(stdin, end); err != nil {
				t.Fatal(err)
			}
			_ = stdin.Close()
			err = releaser.Wait()
			waited = true
			if err != nil || diagnostics.String() != "" {
				t.Fatalf("release resolution failed: %v %s", err, diagnostics.String())
			}
			if finished != nil {
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal("revocation failed after lock released:", err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			want := "published:1:false"
			if scenario == "policy_lock_rollback" {
				want = "verified:0:false"
			}
			if actual := query(t, ctx, name, "SELECT phase||':'||(SELECT count(*) FROM visible)||':'||(SELECT publisher_allowed::text FROM policy) FROM attempts;"); actual != want {
				t.Fatal("unexpected committed ordering:", actual)
			}
			query(t, ctx, name, `INSERT INTO attempts VALUES(2,'verified');
				BEGIN; SELECT id FROM policy WHERE id=1 FOR UPDATE;
				UPDATE attempts SET phase='published' WHERE id=2 AND phase='verified'
				AND EXISTS(SELECT 1 FROM policy WHERE id=1 AND publisher_allowed);
				INSERT INTO visible SELECT '/v2/fixture/image/manifests/later',id FROM attempts WHERE id=2 AND phase='published';
				COMMIT;`)
			if actual := query(t, ctx, name, "SELECT phase||':'||(SELECT count(*) FROM visible WHERE attempt=2) FROM attempts WHERE id=2;"); actual != "verified:0" {
				t.Fatal("later release ignored acknowledged revocation:", actual)
			}
			t.Log("scenario:", scenario, "resolved; conditional predicate alone is not a shared-row lock")
		})
	}
}
