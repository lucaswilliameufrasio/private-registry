package main

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"errors"
	"flag"
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

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/lucaswilliameufrasio/sqlite-replication-go/storages3"
	"golang.org/x/term"

	"private-registry/internal/artifacts"
	"private-registry/internal/auth"
	"private-registry/internal/bootstrap"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/egress"
	"private-registry/internal/email"
	"private-registry/internal/fullbackup"
	"private-registry/internal/gomod"
	"private-registry/internal/jobs"
	"private-registry/internal/maintenance"
	"private-registry/internal/migrations"
	"private-registry/internal/npm"
	"private-registry/internal/objectmaint"
	"private-registry/internal/oci"
	"private-registry/internal/pub"
	"private-registry/internal/replication"
	"private-registry/internal/repositories"
	"private-registry/internal/secrets"
	"private-registry/internal/server"
	"private-registry/internal/storage"
	"private-registry/internal/trustedpub"
	"private-registry/internal/workspaces"
)

const (
	shutdownTimeout            = 10 * time.Second
	replicationShutdownTimeout = 45 * time.Second
)

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
	apply := false
	if len(args) == 2 && args[0] == "collect-objects" && args[1] == "--apply" {
		apply, args = true, args[:1]
	}
	if len(args) >= 1 && (args[0] == "backup" || args[0] == "verify-backup" || args[0] == "restore-backup") {
		return runBackupCommand(ctx, args[0], args[1:], logger)
	}
	if len(args) != 1 || (args[0] != "serve" && args[0] != "migrate" && args[0] != "bootstrap-admin" && args[0] != "init-master-key" && args[0] != "recover-admin" && args[0] != "restore-database" && args[0] != "migrate-objects" && args[0] != "collect-objects") {
		return errors.New("usage: registry {serve|migrate|bootstrap-admin|recover-admin|init-master-key|restore-database|migrate-objects|collect-objects [--apply]|backup|verify-backup|restore-backup}")
	}
	if logger == nil {
		return errors.New("logger is required")
	}
	if args[0] == "bootstrap-admin" {
		return runBootstrapAdmin(ctx)
	}
	if args[0] == "recover-admin" {
		return runRecoverAdmin(ctx)
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

	if args[0] == "restore-database" {
		// Must run before anything opens the database: opening creates it.
		return runRestoreDatabase(ctx, cfg, logger)
	}

	db, err := database.Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, db.Close())
	}()

	if args[0] == "migrate-objects" || args[0] == "collect-objects" {
		return runObjectMaintenance(ctx, db, cfg, logger, args[0], apply)
	}
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
	// Offline object maintenance takes the same lock, so it cannot run while
	// this process serves.
	instanceLock, err := objectmaint.AcquireInstanceLock(cfg.DataDir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, instanceLock.Release()) }()
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
	var outbox *email.Outbox
	if cfg.Email.Provider != config.EmailDisabled {
		sender, err := openEmailSender(cfg)
		if err != nil {
			return err
		}
		outbox, err = email.NewOutbox(db, cfg.DatabaseDriver, jobQueue, &masterKey, sender)
		if err != nil {
			return err
		}
		if err := authentication.EnableEmail(outbox, cfg.CanonicalOrigin); err != nil {
			return err
		}
		if err := workspaceService.EnableEmail(outbox, cfg.CanonicalOrigin); err != nil {
			return err
		}
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
	if outbox != nil {
		httpConfig.Email = outbox
	}
	var ociCollector *oci.Service
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
		ociCollector = ociService
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
	if cfg.TrustedPublishing.Enabled {
		roots, err := loadCertificatePool(cfg.TrustedPublishing.CAFile)
		if err != nil {
			return errors.New("trusted publishing CA file is missing or contains no certificates")
		}
		destinations := []egress.Destination{{Origin: cfg.TrustedPublishing.Issuer, CIDRs: cfg.TrustedPublishing.AllowedNetworks}}
		client, err := egress.NewHTTPSClient(destinations, roots)
		if cfg.TrustedPublishing.DNSServer.IsValid() {
			client, err = egress.NewHTTPSClientWithDNS(destinations, roots, cfg.TrustedPublishing.DNSServer)
		}
		if err != nil {
			return errors.New("trusted publishing network policy is invalid")
		}
		client.Timeout = 15 * time.Second
		// The audience is this registry, so a token minted for another
		// service cannot be replayed here.
		trusted, err := trustedpub.New(db, cfg.DatabaseDriver, repositoryService, cfg.TrustedPublishing.Issuer, strings.TrimSuffix(cfg.CanonicalOrigin, "/"), client)
		if err != nil {
			return err
		}
		httpConfig.TrustedPublishing = trusted
	}
	var replicator *replication.Replicator
	if cfg.Replication.Enabled {
		store, err := openReplicationStore(cfg)
		if err != nil {
			return err
		}
		replicator, err = replication.New(replication.Options{
			DatabasePath:        cfg.DatabaseDSN,
			Directory:           filepath.Join(cfg.DataDir, "replication"),
			Store:               store,
			Prefix:              cfg.Replication.Target.Prefix,
			RemoteID:            cfg.Replication.Target.Endpoint + "/" + cfg.Replication.Target.Bucket,
			Interval:            cfg.Replication.Interval,
			RotateAfterCaptures: cfg.Replication.RotateAfterCaptures,
			RetainGenerations:   cfg.Replication.RetainGenerations,
			Logger:              logger,
		})
		if err != nil {
			return err
		}
		httpConfig.Replication = replicator
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
	if outbox != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			outbox.Run(workerCtx, logger)
		}()
	}
	if ociCollector != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runOCICollection(workerCtx, ociCollector, logger)
		}()
	}
	go func() {
		defer close(workerDone)
		workers.Wait()
	}()
	replicationDone := make(chan struct{})
	if replicator != nil {
		go func() {
			defer close(replicationDone)
			replicator.Run(workerCtx)
		}()
	} else {
		close(replicationDone)
	}
	logger.Info("registry HTTP server listening", "address", listener.Addr().String(), "database_driver", cfg.DatabaseDriver, "storage_driver", cfg.Storage.Driver, "sqlite_replication", cfg.Replication.Enabled, "email_provider", string(cfg.Email.Provider))
	serveErr := server.Serve(ctx, listener, handler, health.MarkDraining, shutdownTimeout)
	stopWorker()
	select {
	case <-workerDone:
	case <-time.After(shutdownTimeout):
		return errors.Join(serveErr, errors.New("upload expiration worker did not stop before shutdown deadline"))
	}
	// Replication ships the last transactions after the HTTP server has
	// stopped accepting writes; it bounds that final attempt itself.
	select {
	case <-replicationDone:
	case <-time.After(replicationShutdownTimeout):
		return errors.Join(serveErr, errors.New("SQLite replication did not finish its final upload before the shutdown deadline"))
	}
	if serveErr != nil {
		return errors.Join(errors.New("HTTP server failed"), serveErr)
	}
	logger.Info("registry HTTP server stopped")
	return nil
}

const (
	ociCollectionInterval = time.Hour
	// ociCollectionGrace keeps blobs of a push that has not uploaded its
	// manifest yet. Clients finish pushes in minutes; a day is generous.
	ociCollectionGrace = 24 * time.Hour
)

// runOCICollection drops OCI blob membership no manifest references. It runs
// hourly and once shortly after start.
func runOCICollection(ctx context.Context, service *oci.Service, logger *slog.Logger) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			removed, err := service.CollectUnreferencedBlobs(runCtx, time.Now(), ociCollectionGrace)
			cancel()
			if err != nil {
				logger.Warn("OCI blob collection failed", "error", err)
			} else if removed > 0 {
				logger.Info("OCI blob collection released unreferenced blobs", "blobs", removed)
			}
			timer.Reset(ociCollectionInterval)
		}
	}
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
		settings, err := s3ClientSettings(config.S3Target{Endpoint: cfg.Storage.S3Endpoint, Region: cfg.Storage.S3Region, AccessKeyIDFile: cfg.Storage.S3AccessKeyIDFile, SecretKeyFile: cfg.Storage.S3SecretKeyFile, CAFile: cfg.Storage.S3CAFile, AllowedNetworks: cfg.Storage.S3AllowedNetworks, DNSServer: cfg.Storage.S3DNSServer})
		if err != nil {
			return nil, err
		}
		return storage.NewRestrictedS3Storage(settings, cfg.Storage.S3Bucket, cfg.Storage.S3Prefix, filepath.Join(cfg.DataDir, "s3-staging"), config.MaxConfiguredUploadBytes, cfg.Storage.S3MaxConcurrent, cfg.Storage.S3OperationTimeout)
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

// s3ClientSettings resolves one S3-compatible destination into an explicit
// network policy and credentials read from private files. Nothing is taken
// from the environment's AWS variables or shared configuration.
func s3ClientSettings(target config.S3Target) (storage.S3ClientSettings, error) {
	accessKeyID, err := secrets.LoadSecretFile(target.AccessKeyIDFile)
	if err != nil {
		return storage.S3ClientSettings{}, errors.New("S3 access key ID file is missing, unsafe or malformed")
	}
	secretAccessKey, err := secrets.LoadSecretFile(target.SecretKeyFile)
	if err != nil {
		return storage.S3ClientSettings{}, errors.New("S3 secret access key file is missing, unsafe or malformed")
	}
	roots, err := loadCertificatePool(target.CAFile)
	if err != nil {
		return storage.S3ClientSettings{}, errors.New("S3 CA file is missing or contains no certificates")
	}
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey, Source: "registry-secret-files"}, nil
	})
	return storage.S3ClientSettings{Origin: target.Endpoint, Region: target.Region, Networks: target.AllowedNetworks, DNSServer: target.DNSServer, RootCAs: roots, Credentials: credentials}, nil
}

// openReplicationStore reaches the disaster-recovery bucket, which is
// configured independently of the package object store.
func openReplicationStore(cfg config.Config) (*storages3.Store, error) {
	settings, err := s3ClientSettings(cfg.Replication.Target)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewRestrictedS3Client(settings)
	if err != nil {
		return nil, err
	}
	store, err := storages3.New(client, cfg.Replication.Target.Bucket)
	if err != nil {
		return nil, errors.New("SQLite replication destination is invalid")
	}
	return store, nil
}

// runRestoreDatabase rebuilds the SQLite database from the replication bucket
// on a host where it does not exist. It restores the database only: package
// objects, the master key and configuration must be provided by the operator.
// Tokens and sessions come back exactly as they were at the restored point,
// so anything revoked after that point must be revoked again.
func runRestoreDatabase(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	if cfg.DatabaseDriver != config.SQLite || !cfg.Replication.Enabled {
		return errors.New("restore-database requires the sqlite driver and REGISTRY_REPLICATION_ENABLED=true with its destination")
	}
	if _, err := os.Lstat(cfg.DatabaseDSN); err == nil {
		return errors.New("a database already exists at the configured path; restore-database never overwrites one")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("database path could not be checked")
	}
	directory := filepath.Dir(cfg.DatabaseDSN)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("database directory could not be created")
	}
	if info, err := os.Stat(directory); err != nil || info.Mode().Perm()&0o077 != 0 {
		return errors.New("database directory must be private to its owner")
	}
	store, err := openReplicationStore(cfg)
	if err != nil {
		return err
	}
	restored, err := replication.Restore(ctx, store, cfg.Replication.Target.Prefix, cfg.DatabaseDSN)
	if err != nil {
		return err
	}
	logger.Info("database restored from replication", "generation", restored.Generation, "skipped_generations", restored.Skipped)
	return nil
}

// runObjectMaintenance runs offline object commands while holding the
// instance lock that serve also takes.
func runObjectMaintenance(ctx context.Context, db *sql.DB, cfg config.Config, logger *slog.Logger, command string, apply bool) (err error) {
	if err := verifyServeSchema(ctx, db, cfg.DatabaseDriver); err != nil {
		return err
	}
	lock, err := objectmaint.AcquireInstanceLock(cfg.DataDir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Release()) }()
	if command == "migrate-objects" {
		if cfg.Storage.Driver != config.StorageS3 {
			return errors.New("migrate-objects copies the filesystem object store into S3; configure REGISTRY_STORAGE_DRIVER=s3 and its destination first")
		}
		source, err := storage.NewFileSystem(filepath.Join(cfg.DataDir, "object-store"))
		if err != nil {
			return err
		}
		destination, err := openObjectStore(cfg)
		if err != nil {
			return err
		}
		report, err := objectmaint.Copy(ctx, source, destination, config.MaxConfiguredUploadBytes, func(progress objectmaint.CopyReport) {
			logger.Info("objects copied so far", "objects", progress.Copied, "bytes", progress.Bytes)
		})
		if err != nil {
			return err
		}
		logger.Info("object migration complete; the filesystem copy was kept", "objects", report.Copied, "bytes", report.Bytes)
		return nil
	}
	store, err := openObjectStore(cfg)
	if err != nil {
		return err
	}
	walkCtx, cancel := context.WithTimeout(ctx, 6*time.Hour)
	defer cancel()
	report, err := objectmaint.Collect(walkCtx, db, cfg.DatabaseDriver, store, time.Now(), objectCollectionGrace, apply)
	logger.Info("object collection", "apply", apply, "scanned", report.Scanned, "referenced", report.Referenced, "too_recent", report.TooRecent, "unreferenced", report.Unreferenced, "unreferenced_bytes", report.UnrefBytes, "deleted", report.Deleted, "deleted_bytes", report.DeletedBytes)
	if err != nil {
		return err
	}
	if !apply && report.Unreferenced > 0 {
		logger.Info("nothing was deleted; run collect-objects --apply to delete the unreferenced objects")
	}
	return nil
}

// runBackupCommand runs backup, verify-backup or restore-backup. verify and
// restore take the operator's age identity file; backup never needs it.
func runBackupCommand(ctx context.Context, command string, args []string, logger *slog.Logger) (err error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	identityPath := flags.String("identity", "", "age identity file (verify-backup, restore-backup)")
	backupID := flags.String("id", "", "backup ID; default is the newest complete backup")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || (command == "backup" && (*identityPath != "" || *backupID != "")) || (command != "backup" && *identityPath == "") {
		return errors.New("usage: registry backup | registry verify-backup --identity FILE [--id ID] | registry restore-backup --identity FILE [--id ID]")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if !cfg.Backup.Enabled {
		return errors.New("backups need REGISTRY_BACKUP_S3_* and REGISTRY_BACKUP_AGE_RECIPIENT")
	}
	settings, err := s3ClientSettings(cfg.Backup.Target)
	if err != nil {
		return err
	}
	client, err := storage.NewRestrictedS3Client(settings)
	if err != nil {
		return err
	}
	bucket := fullbackup.Bucket{Client: client, Name: cfg.Backup.Target.Bucket, Prefix: cfg.Backup.Target.Prefix}
	staging := filepath.Join(cfg.DataDir, "backup-staging")
	runCtx, cancel := context.WithTimeout(ctx, 12*time.Hour)
	defer cancel()

	switch command {
	case "backup":
		recipient, err := age.ParseX25519Recipient(cfg.Backup.Recipient)
		if err != nil {
			return errors.New("REGISTRY_BACKUP_AGE_RECIPIENT is not a valid age recipient")
		}
		db, err := database.Open(runCtx, cfg)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, db.Close()) }()
		if err := verifyServeSchema(runCtx, db, cfg.DatabaseDriver); err != nil {
			return err
		}
		store, err := openObjectStore(cfg)
		if err != nil {
			return err
		}
		report, err := fullbackup.Run(runCtx, fullbackup.Options{DB: db, Driver: cfg.DatabaseDriver, DSN: cfg.DatabaseDSN, Store: store, Bucket: bucket, Recipient: recipient, PgDump: cfg.Backup.PgDump, Staging: staging, Retain: cfg.Backup.Retain})
		logger.Info("backup", "id", report.ID, "objects", report.Objects, "objects_uploaded", report.ObjectsUploaded, "bytes_uploaded", report.BytesUploaded, "database_bytes", report.DatabaseBytes, "removed_backups", report.Removed)
		return err
	case "verify-backup":
		identity, err := loadAgeIdentity(*identityPath)
		if err != nil {
			return err
		}
		report, err := fullbackup.Verify(runCtx, bucket, identity, *backupID, staging, cfg.Backup.PgRestore)
		if err != nil {
			return err
		}
		logger.Info("backup verified", "id", report.ID, "objects", report.Objects, "database_bytes", report.DatabaseBytes)
		return nil
	default:
		identity, err := loadAgeIdentity(*identityPath)
		if err != nil {
			return err
		}
		store, err := openObjectStore(cfg)
		if err != nil {
			return err
		}
		options := fullbackup.RestoreOptions{Bucket: bucket, Identity: identity, ID: *backupID, Staging: staging, Driver: cfg.DatabaseDriver, PgRestore: cfg.Backup.PgRestore, Store: store}
		if cfg.DatabaseDriver == config.SQLite {
			options.SQLite = cfg.DatabaseDSN
		} else {
			db, err := database.Open(runCtx, cfg)
			if err != nil {
				return err
			}
			defer func() { err = errors.Join(err, db.Close()) }()
			options.DB, options.DSN = db, cfg.DatabaseDSN
		}
		lock, err := objectmaint.AcquireInstanceLock(cfg.DataDir)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, lock.Release()) }()
		report, err := fullbackup.Restore(runCtx, options)
		if err != nil {
			return err
		}
		logger.Info("backup restored; revoke again any credential revoked after the backup was taken", "id", report.ID, "objects", report.ObjectsRestored)
		return nil
	}
}

// loadAgeIdentity reads the operator's identity from a private file.
func loadAgeIdentity(path string) (age.Identity, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 64<<10 {
		return nil, errors.New("age identity file must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("age identity file could not be read")
	}
	defer file.Close()
	identities, err := age.ParseIdentities(file)
	if err != nil || len(identities) == 0 {
		return nil, errors.New("age identity file holds no valid identity")
	}
	return identities[0], nil
}

// objectCollectionGrace keeps objects written shortly before serve stopped.
const objectCollectionGrace = 24 * time.Hour

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

// runRecoverAdmin lets someone with a shell on the server regain access to an
// installation administrator account: it sets a new password, removes the
// account's second factors and revokes its sessions. The next sign-in
// enrolls TOTP again. It is the way back when no administrator can sign in.
func runRecoverAdmin(ctx context.Context) (err error) {
	if err := requireInteractiveTerminal(int(os.Stdin.Fd()), int(os.Stdout.Fd())); err != nil {
		return errors.New("recover-admin requires an interactive terminal")
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
	defer func() { err = errors.Join(err, db.Close()) }()
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
	loginName, err := readTerminalLine(os.Stdin, os.Stdout, "Administrator login username: ")
	if err != nil {
		return err
	}
	password, err := readTerminalPassword(os.Stdin, os.Stdout, "New password (input hidden): ")
	if err != nil {
		return err
	}
	defer clear(password)
	confirmation, err := readTerminalPassword(os.Stdin, os.Stdout, "Confirm new password (input hidden): ")
	if err != nil {
		return err
	}
	defer clear(confirmation)
	if subtle.ConstantTimeCompare(password, confirmation) != 1 {
		return errors.New("passwords do not match; nothing was changed")
	}
	if err := authentication.RecoverAdministrator(ctx, loginName, password, currentUser.Username); err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, "Administrator recovered: sign in with the new password and enroll TOTP again.")
	return err
}

func requireInteractiveTerminal(inputFD, outputFD int) error {
	if !term.IsTerminal(inputFD) || !term.IsTerminal(outputFD) {
		return errors.New("bootstrap-admin requires an interactive terminal; no account data was read")
	}
	return nil
}
