package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/server"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], logger); err != nil {
		logger.Error("registry stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *slog.Logger) (err error) {
	if len(args) != 1 || (args[0] != "serve" && args[0] != "migrate") {
		return errors.New("usage: registry {serve|migrate}")
	}
	if logger == nil {
		return errors.New("logger is required")
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	db, err := database.Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, db.Close())
	}()

	if args[0] == "migrate" {
		report, err := migrations.Migrate(ctx, db, cfg)
		if err != nil {
			return err
		}
		logger.Info("database migrations complete",
			"applied_versions", report.AppliedVersions,
			"current_version", report.CurrentVersion,
			"target_version", report.TargetVersion,
			"installation_id", report.InstallationID,
		)
		return nil
	}

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return errors.Join(errors.New("HTTP listener could not be opened"), err)
	}
	health := server.NewHealth(db)
	logger.Info("registry health server listening", "address", listener.Addr().String(), "database_driver", cfg.DatabaseDriver)
	if err := server.Serve(ctx, listener, health.Handler(), health.MarkDraining, shutdownTimeout); err != nil {
		return errors.Join(errors.New("HTTP server failed"), err)
	}
	logger.Info("registry health server stopped")
	return nil
}
