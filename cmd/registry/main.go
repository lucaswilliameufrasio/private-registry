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
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/secrets"
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
