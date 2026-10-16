package server

import (
	"context"
	"database/sql"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
)

const readinessTimeout = time.Second

type Health struct {
	database *sql.DB
	draining atomic.Bool
}

func NewHealth(database *sql.DB) *Health {
	return &Health{database: database}
}

func (h *Health) Handler() http.Handler {
	router := chi.NewRouter()
	router.Get("/livez", h.livez)
	router.Get("/readyz", h.readyz)
	return router
}

func (h *Health) MarkDraining() {
	h.draining.Store(true)
}

func (h *Health) livez(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *Health) readyz(w http.ResponseWriter, request *http.Request) {
	if h.draining.Load() || h.database == nil {
		h.notReady(w)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), readinessTimeout)
	defer cancel()
	if err := h.database.PingContext(ctx); err != nil {
		h.notReady(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Health) notReady(w http.ResponseWriter) {
	http.Error(w, "not ready", http.StatusServiceUnavailable)
}
