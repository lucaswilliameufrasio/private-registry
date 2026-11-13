package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

func Serve(
	ctx context.Context,
	listener net.Listener,
	handler http.Handler,
	onDrain func(),
	shutdownTimeout time.Duration,
) error {
	if ctx == nil || listener == nil || handler == nil {
		return errors.New("context, listener, and HTTP handler are required")
	}
	if shutdownTimeout <= 0 {
		return errors.New("shutdown timeout must be positive")
	}

	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- httpServer.Serve(listener)
	}()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		if onDrain != nil {
			onDrain()
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return errors.Join(err, httpServer.Close())
	}

	serveErr := <-serveErrors
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}
