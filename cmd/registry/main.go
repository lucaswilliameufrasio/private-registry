package main

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/term"

	"private-registry/internal/artifacts"
	"private-registry/internal/auth"
	"private-registry/internal/bootstrap"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/egress"
	"private-registry/internal/gomod"
	"private-registry/internal/jobs"
	"private-registry/internal/maintenance"
	"private-registry/internal/migrations"
	"private-registry/internal/npm"
	"private-registry/internal/oci"
	"private-registry/internal/pub"
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
	if args[0] == "serve" {
		if err := rejectIncompleteRecovery(cfg.DataDir); err != nil {
			return err
		}
		if cfg.DatabaseDriver == config.SQLite {
			if err := rejectIncompleteRecovery(filepath.Dir(cfg.DatabaseDSN)); err != nil {
				return err
			}
		}
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
	if err := verifyServeSchema(ctx, db, cfg.DatabaseDriver); err != nil {
		return err
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
	if cfg.Muira.Enabled {
		if err := enableMuira(ctx, authentication, cfg); err != nil {
			return err
		}
	}
	workspaceService, err := workspaces.New(db, cfg.DatabaseDriver)
	if err != nil {
		return err
	}
	repositoryService, err := repositories.New(db, cfg.DatabaseDriver)
	if err != nil {
		return err
	}
	objectStore, err := openObjectStore(cfg)
	if err != nil {
		return err
	}
	goStaging := filepath.Join(cfg.DataDir, "go-staging")
	if err := os.MkdirAll(goStaging, 0o700); err != nil {
		return errors.New("Go module staging directory could not be created")
	}
	goModules, err := gomod.NewService(db, cfg.DatabaseDriver, repositoryService, objectStore, gomod.Options{StagingDirectory: goStaging, MaxZipBytes: 500 << 20, MaxFiles: 10000, MaxConcurrent: 4})
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
	goExpirationWorker, err := maintenance.NewGoUploadExpiration(jobQueue, goModules)
	if err != nil {
		return err
	}
	cargoReservations, err := cargo.NewReservationService(db, repositoryService, cfg.DatabaseDriver)
	if err != nil {
		return err
	}
	cargoExpirationWorker, err := maintenance.NewCargoReservationExpiration(jobQueue, cargoReservations)
	if err != nil {
		return err
	}
	health := server.NewHealth(db)
	httpConfig := server.AuthHTTPConfig{
		CanonicalOrigin:        cfg.CanonicalOrigin,
		AssetOrigin:            cfg.AssetOrigin,
		PublicAssetCORSOrigins: cfg.PublicAssetCORSOrigins,
		TrustedProxies:         cfg.TrustedProxies,
		GoModules:              goModules,
	}
	// A repository of an opt-in format can only be created while its
	// protocol adapter is served by this process.
	var enabledFormats []repositories.Format
	if cfg.ExperimentalCargo {
		enabledFormats = append(enabledFormats, repositories.FormatCargo)
		cargoStaging := filepath.Join(cfg.DataDir, "cargo-staging")
		if err := os.MkdirAll(cargoStaging, 0o700); err != nil {
			return errors.New("Cargo staging directory could not be created")
		}
		maxArchive := cfg.MaxUploadBytes
		if maxArchive > 500<<20 {
			maxArchive = 500 << 20
		}
		concurrent := cfg.MaxConcurrentUploads
		if concurrent > 16 {
			concurrent = 16
		}
		limits := cargo.ArchiveLimits{MaxCompressedBytes: maxArchive, MaxUncompressedBytes: 1 << 30, MaxFiles: 10000, MaxManifestBytes: 1 << 20}
		cargoReceipts, err := cargo.NewReceiptService(db, repositoryService, cfg.DatabaseDriver, objectStore, cargo.ReceiptOptions{StagingDirectory: cargoStaging, Limits: limits, MaxConcurrent: concurrent, IndexOrigin: cfg.CanonicalOrigin, DefaultIndex: "https://github.com/rust-lang/crates.io-index"})
		if err != nil {
			return err
		}
		httpConfig.CargoReservations = cargoReservations
		httpConfig.CargoReceipts = cargoReceipts
		httpConfig.CargoProtocol = &server.CargoProtocolConfig{StagingDirectory: cargoStaging, MaxArchiveBytes: maxArchive, MaxConcurrent: concurrent}
	}
	if cfg.ExperimentalNPM {
		enabledFormats = append(enabledFormats, repositories.FormatNPM)
		npmStaging := filepath.Join(cfg.DataDir, "npm-staging")
		if err := os.MkdirAll(npmStaging, 0o700); err != nil {
			return errors.New("npm staging directory could not be created")
		}
		maxArchive := cfg.MaxUploadBytes
		if maxArchive > 64<<20 {
			maxArchive = 64 << 20
		}
		concurrent := cfg.MaxConcurrentUploads
		if concurrent > 16 {
			concurrent = 16
		}
		limits := npm.ArchiveLimits{MaxCompressedBytes: maxArchive, MaxUncompressedBytes: 512 << 20, MaxEntries: 10000, MaxManifestBytes: 1 << 20}
		npmReservations, err := npm.NewReservationService(db, repositoryService, cfg.DatabaseDriver)
		if err != nil {
			return err
		}
		npmReceipts, err := npm.NewReceiptService(db, repositoryService, cfg.DatabaseDriver, objectStore, npm.ReceiptOptions{StagingDirectory: npmStaging, MaxConcurrent: concurrent, Limits: limits})
		if err != nil {
			return err
		}
		httpConfig.NPMReservations = npmReservations
		httpConfig.NPMReceipts = npmReceipts
		httpConfig.NPMReadProtocol = true
		httpConfig.NPMWriteProtocol = &server.NPMWriteProtocolConfig{StagingDirectory: npmStaging, MaxDocumentBytes: 128 << 20, MaxArchiveBytes: maxArchive, MaxConcurrent: concurrent}
	}
	if cfg.ExperimentalOCI {
		concurrent := cfg.MaxConcurrentUploads * 4
		if concurrent > 64 {
			concurrent = 64
		}
		ociService, err := oci.New(db, cfg.DatabaseDriver, repositoryService, objectStore, oci.Options{StagingDirectory: filepath.Join(cfg.DataDir, "oci-staging"), MaxBlobBytes: cfg.MaxUploadBytes, MaxUploads: concurrent})
		if err != nil {
			return err
		}
		httpConfig.OCI = ociService
		enabledFormats = append(enabledFormats, repositories.FormatOCI)
	}
	if cfg.ExperimentalPub {
		enabledFormats = append(enabledFormats, repositories.FormatPub)
		pubStaging := filepath.Join(cfg.DataDir, "pub-staging")
		if err := os.MkdirAll(pubStaging, 0o700); err != nil {
			return errors.New("Pub staging directory could not be created")
		}
		maxArchive := cfg.MaxUploadBytes
		if maxArchive > 64<<20 {
			maxArchive = 64 << 20
		}
		concurrent := cfg.MaxConcurrentUploads
		if concurrent > 16 {
			concurrent = 16
		}
		limits := pub.ArchiveLimits{MaxCompressedBytes: maxArchive, MaxUncompressedBytes: 512 << 20, MaxEntries: 10000, MaxManifestBytes: 1 << 20}
		pubReservations, err := pub.NewReservationService(db, repositoryService, cfg.DatabaseDriver)
		if err != nil {
			return err
		}
		pubReceipts, err := pub.NewReceiptService(db, repositoryService, cfg.DatabaseDriver, objectStore, pub.ReceiptOptions{StagingDirectory: pubStaging, MaxConcurrent: concurrent, Limits: limits})
		if err != nil {
			return err
		}
		httpConfig.PubReservations = pubReservations
		httpConfig.PubReceipts = pubReceipts
		httpConfig.PubReadProtocol = true
		httpConfig.PubWriteProtocol = &server.PubWriteProtocolConfig{StagingDirectory: pubStaging, MaxArchiveBytes: maxArchive, MaxConcurrent: concurrent, Limits: limits}
	}
	if err := repositoryService.EnableFormatCreation(enabledFormats...); err != nil {
		return err
	}
	handler, err := server.NewHandler(health, authentication, workspaceService, repositoryService, artifactService, httpConfig)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return errors.Join(errors.New("HTTP listener could not be opened"), err)
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	var workers sync.WaitGroup
	for _, worker := range []*maintenance.UploadExpiration{expirationWorker, goExpirationWorker, cargoExpirationWorker} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			worker.Run(workerCtx, logger)
		}()
	}
	go func() {
		defer close(workerDone)
		workers.Wait()
	}()
	logger.Info("registry HTTP server listening", "address", listener.Addr().String(), "database_driver", cfg.DatabaseDriver, "storage_driver", cfg.Storage.Driver)
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

// openObjectStore selects the package object backend. The S3-compatible
// driver only reaches the configured HTTPS endpoint on the configured
// networks, reads its credentials from private files and keeps a bounded
// private staging directory under the data directory.
func openObjectStore(cfg config.Config) (storage.Driver, error) {
	switch cfg.Storage.Driver {
	case config.StorageFileSystem:
		return storage.NewFileSystem(filepath.Join(cfg.DataDir, "object-store"))
	case config.StorageS3:
		accessKeyID, err := secrets.LoadSecretFile(cfg.Storage.S3AccessKeyIDFile)
		if err != nil {
			return nil, errors.New("S3 access key ID file is missing, unsafe or malformed")
		}
		secretAccessKey, err := secrets.LoadSecretFile(cfg.Storage.S3SecretKeyFile)
		if err != nil {
			return nil, errors.New("S3 secret access key file is missing, unsafe or malformed")
		}
		credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey, Source: "registry-secret-files"}, nil
		})
		roots, err := loadCertificatePool(cfg.Storage.S3CAFile)
		if err != nil {
			return nil, errors.New("S3 CA file is missing or contains no certificates")
		}
		return storage.NewRestrictedS3Storage(storage.S3ClientSettings{
			RootCAs:     roots,
			Origin:      cfg.Storage.S3Endpoint,
			Region:      cfg.Storage.S3Region,
			Networks:    cfg.Storage.S3AllowedNetworks,
			DNSServer:   cfg.Storage.S3DNSServer,
			Credentials: credentials,
		}, cfg.Storage.S3Bucket, cfg.Storage.S3Prefix, filepath.Join(cfg.DataDir, "s3-staging"), config.MaxConfiguredUploadBytes, cfg.Storage.S3MaxConcurrent, cfg.Storage.S3OperationTimeout)
	default:
		return nil, errors.New("storage driver is not supported")
	}
}

// enableMuira turns on the optional Muira sign-in. Discovery runs once at
// startup through a client restricted to the issuer origin and the configured
// networks, so a misconfigured or unreachable provider fails the start instead
// of silently leaving only part of the sign-in methods available.
func enableMuira(ctx context.Context, authentication *auth.Service, cfg config.Config) error {
	clientSecret, err := secrets.LoadSecretFile(cfg.Muira.ClientSecretFile)
	if err != nil {
		return errors.New("Muira client secret file is missing, unsafe or malformed")
	}
	roots, err := loadCertificatePool(cfg.Muira.CAFile)
	if err != nil {
		return errors.New("Muira CA file is missing or contains no certificates")
	}
	destinations := []egress.Destination{{Origin: cfg.Muira.Issuer, CIDRs: cfg.Muira.AllowedNetworks}}
	client, err := egress.NewHTTPSClient(destinations, roots)
	if cfg.Muira.DNSServer.IsValid() {
		client, err = egress.NewHTTPSClientWithDNS(destinations, roots, cfg.Muira.DNSServer)
	}
	if err != nil {
		return errors.New("Muira network policy is invalid")
	}
	client.Timeout = 15 * time.Second
	discoveryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return authentication.EnableMuira(discoveryCtx, auth.MuiraOptions{
		Issuer:       cfg.Muira.Issuer,
		ClientID:     cfg.Muira.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  strings.TrimSuffix(cfg.CanonicalOrigin, "/") + "/api/v1/auth/muira/callback",
		HTTPClient:   client,
	})
}

// loadCertificatePool returns nil (system roots) when no bundle is configured.
// A configured bundle replaces the system roots for that single integration.
func loadCertificatePool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	bundle, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(bundle) > 1<<20 {
		return nil, errors.New("certificate bundle is unreadable or too large")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, errors.New("certificate bundle contains no certificates")
	}
	return pool, nil
}

func verifyServeSchema(ctx context.Context, db *sql.DB, driver config.DatabaseDriver) error {
	if ctx == nil || db == nil {
		return errors.New("database schema verification is unavailable")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var installationID string
	if err := db.QueryRowContext(checkCtx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installationID); err != nil {
		return errors.New("database schema is not ready; run migrations explicitly")
	}
	if err := migrations.VerifyCurrent(checkCtx, db, driver, installationID); err != nil {
		return errors.New("database schema verification failed; run or inspect migrations explicitly")
	}
	return nil
}

func rejectIncompleteRecovery(dataDir string) error {
	_, err := os.Lstat(filepath.Join(dataDir, "RECOVERY_INCOMPLETE"))
	if err == nil {
		return errors.New("cannot serve an incomplete recovery directory")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("recovery directory status could not be checked")
	}
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
