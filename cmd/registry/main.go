package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"private-registry/internal/artifacts"
	"private-registry/internal/auth"
	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/jobs"
	"private-registry/internal/maintenance"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
	"private-registry/internal/secrets"
	"private-registry/internal/server"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
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
	if len(args) != 1 || (args[0] != "serve" && args[0] != "migrate" && args[0] != "bootstrap-admin" && args[0] != "init-master-key") {
		return errors.New("usage: registry {serve|migrate|bootstrap-admin|init-master-key}")
	}
	if logger == nil {
		return errors.New("logger is required")
	}
	if args[0] == "bootstrap-admin" {
		return runBootstrapAdmin(ctx)
	}
	if args[0] == "init-master-key" {
		return runInitMasterKey(logger)
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
	if cfg.MasterKeyFile == "" {
		return errors.New("REGISTRY_MASTER_KEY_FILE is required by serve")
	}
	if cfg.CanonicalOrigin == "" {
		return errors.New("REGISTRY_CANONICAL_ORIGIN is required by serve")
	}
	if cfg.AssetOrigin == "" {
		return errors.New("REGISTRY_ASSET_ORIGIN is required by serve")
	}
	if len(cfg.TrustedProxies) == 0 {
		return errors.New("REGISTRY_TRUSTED_PROXIES must include the TLS-terminating proxy for serve")
	}
	masterKey, err := secrets.LoadMasterKeyFile(cfg.MasterKeyFile, cfg.DataDir)
	if err != nil {
		return err
	}
	defer masterKey.Destroy()

	authentication, err := auth.New(db, cfg.DatabaseDriver, &masterKey)
	if err != nil {
		return err
	}
	workspaceService, err := workspaces.New(db, cfg.DatabaseDriver)
	if err != nil {
		return err
	}
	repositoryService, err := repositories.New(db, cfg.DatabaseDriver)
	if err != nil {
		return err
	}
	objectStore, err := storage.NewFileSystem(filepath.Join(cfg.DataDir, "object-store"))
	if err != nil {
		return err
	}
	artifactService, err := artifacts.New(db, cfg.DatabaseDriver, repositoryService, objectStore, artifacts.Options{
		MaxUploadBytes:       cfg.MaxUploadBytes,
		MaxConcurrentUploads: cfg.MaxConcurrentUploads,
	})
	if err != nil {
		return err
	}
	jobQueue, err := jobs.New(db, cfg.DatabaseDriver)
	if err != nil {
		return err
	}
	expirationWorker, err := maintenance.NewUploadExpiration(jobQueue, artifactService)
	if err != nil {
		return err
	}
	health := server.NewHealth(db)
	handler, err := server.NewHandler(health, authentication, workspaceService, repositoryService, artifactService, server.AuthHTTPConfig{
		CanonicalOrigin:        cfg.CanonicalOrigin,
		AssetOrigin:            cfg.AssetOrigin,
		PublicAssetCORSOrigins: cfg.PublicAssetCORSOrigins,
		TrustedProxies:         cfg.TrustedProxies,
	})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return errors.Join(errors.New("HTTP listener could not be opened"), err)
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		expirationWorker.Run(workerCtx, logger)
	}()
	logger.Info("registry HTTP server listening", "address", listener.Addr().String(), "database_driver", cfg.DatabaseDriver)
	serveErr := server.Serve(ctx, listener, handler, health.MarkDraining, shutdownTimeout)
	stopWorker()
	select {
	case <-workerDone:
	case <-time.After(shutdownTimeout):
		return errors.Join(serveErr, errors.New("upload expiration worker did not stop before shutdown deadline"))
	}
	if serveErr != nil {
		return errors.Join(errors.New("HTTP server failed"), serveErr)
	}
	logger.Info("registry HTTP server stopped")
	return nil
}

func runInitMasterKey(logger *slog.Logger) error {
	settings, err := config.LoadMasterKeySettings()
	if err != nil {
		return err
	}
	if err := secrets.InitializeMasterKey(settings.MasterKeyFile, settings.DataDir); err != nil {
		return err
	}
	logger.Info("local master key initialized")
	return nil
}

func runBootstrapAdmin(ctx context.Context) (err error) {
	if err := requireInteractiveTerminal(int(os.Stdin.Fd()), int(os.Stdout.Fd())); err != nil {
		return err
	}
	currentUser, err := user.Current()
	if err != nil || currentUser == nil || strings.TrimSpace(currentUser.Username) == "" {
		return errors.New("local operator identity could not be determined")
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
		if closeErr := db.Close(); closeErr != nil {
			err = errors.Join(err, errors.New("database connection could not be closed"))
		}
	}()

	if err := bootstrap.CheckReady(ctx, db, cfg.DatabaseDriver); err != nil {
		return err
	}
	input, err := promptAdministrator(os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	defer clear(input.Password)
	if _, err := bootstrap.CreateFirstAdmin(ctx, db, cfg.DatabaseDriver, bootstrap.AdminInput{
		LoginName:     input.LoginName,
		DisplayName:   input.DisplayName,
		Email:         input.Email,
		Password:      input.Password,
		OperatorLabel: currentUser.Username,
	}); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, "First administrator created."); err != nil {
		return errors.New("bootstrap result could not be written")
	}
	return nil
}

func requireInteractiveTerminal(inputFD, outputFD int) error {
	if !term.IsTerminal(inputFD) || !term.IsTerminal(outputFD) {
		return errors.New("bootstrap-admin requires an interactive terminal; no account data was read")
	}
	return nil
}
