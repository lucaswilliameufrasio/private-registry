package server

import (
	"net/http"
	"time"

	"private-registry/internal/replication"
)

// ReplicationStatus is implemented by the SQLite replicator.
type ReplicationStatus interface {
	Status() replication.Status
}

type replicationStatusResponse struct {
	Enabled             bool   `json:"enabled"`
	Health              string `json:"health,omitempty"`
	Generation          string `json:"generation,omitempty"`
	TXID                uint64 `json:"txid,omitempty"`
	LastSyncedAt        string `json:"last_synced_at,omitempty"`
	LastCurrentAt       string `json:"last_current_at,omitempty"`
	LagSeconds          int64  `json:"lag_seconds,omitempty"`
	IntervalSeconds     int64  `json:"interval_seconds,omitempty"`
	ConsecutiveFailures int    `json:"consecutive_failures,omitempty"`
}

// replicationStatus is for installation administrators only. It reports
// positions and timing, never bucket names, keys or error text, which can
// carry endpoint details.
func (h *authHTTP) replicationStatus(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	if err := h.repositories.RequireInstanceAdministrator(request.Context(), session.UserID); err != nil {
		writeRepositoryError(response, err)
		return
	}
	if h.replication == nil {
		writeJSON(response, http.StatusOK, replicationStatusResponse{Enabled: false})
		return
	}
	status := h.replication.Status()
	now := time.Now().UTC()
	health, lag := status.Evaluate(now)
	result := replicationStatusResponse{
		Enabled:             true,
		Health:              string(health),
		Generation:          status.Generation,
		TXID:                status.TXID,
		LagSeconds:          int64(lag / time.Second),
		IntervalSeconds:     int64(status.Interval / time.Second),
		ConsecutiveFailures: status.ConsecutiveFails,
	}
	if !status.LastSyncedAt.IsZero() {
		result.LastSyncedAt = status.LastSyncedAt.Format(time.RFC3339Nano)
	}
	if current := status.LastCurrentAt(); !current.IsZero() {
		result.LastCurrentAt = current.Format(time.RFC3339Nano)
	}
	writeJSON(response, http.StatusOK, result)
}
