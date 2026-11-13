package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"private-registry/internal/replication"
)

type fixedReplicationStatus replication.Status

func (s fixedReplicationStatus) Status() replication.Status { return replication.Status(s) }

func TestReplicationStatusIsForInstanceAdministrators(t *testing.T) {
	now := time.Now().UTC()
	status := fixedReplicationStatus{Generation: "20261112T100000.000000000Z-0a0b0c0d", TXID: 42, LastSyncedAt: now.Add(-10 * time.Second), LastCycleAt: now.Add(-2 * time.Second), StartedAt: now.Add(-time.Hour), Interval: 30 * time.Second, LastError: "endpoint https://secret.example refused"}
	for _, item := range []struct {
		name   string
		source ReplicationStatus
		want   string
	}{
		{"enabled", status, `"health":"current"`},
		{"disabled", nil, `"enabled":false`},
	} {
		t.Run(item.name, func(t *testing.T) {
			fixture := newAuthHTTPFixtureWithConfig(t, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, Replication: item.source})
			if anonymous := authHTTPRequest(fixture.handler, http.MethodGet, "/api/v1/admin/replication", "", "", "registry.example"); anonymous.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous status request: %d", anonymous.Code)
			}
			admin := muiraAdminMFACookies(t, fixture.handler)
			response := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, "/api/v1/admin/replication", "", "", "registry.example", admin, "")
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), item.want) {
				t.Fatalf("administrator status: %d %s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "secret.example") {
				t.Fatal("status exposed error text")
			}
			if item.source != nil {
				var body replicationStatusResponse
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.TXID != 42 || body.Generation == "" || body.LagSeconds > 120 || body.IntervalSeconds != 30 || body.LastCurrentAt == "" {
					t.Fatalf("status body: %+v %v", body, err)
				}
			}
			seedHTTPUser(t, fixture, "plain.member")
			login := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login", `{"login_name":"plain.member","password":"synthetic-http-member-password"}`, authTestOrigin, "registry.example")
			member := assertSessionCookies(t, login)
			if forbidden := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, "/api/v1/admin/replication", "", "", "registry.example", member, ""); forbidden.Code != http.StatusForbidden {
				t.Fatalf("non-administrator status request: %d", forbidden.Code)
			}
		})
	}
}
