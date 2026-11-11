package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type DatabaseDriver string

const (
	SQLite                   DatabaseDriver = "sqlite"
	Postgres                 DatabaseDriver = "postgres"
	MaxConfiguredUploadBytes int64          = 1 << 30
)

type Config struct {
	ListenAddress           string
	DataDir                 string
	MasterKeyFile           string
	CanonicalOrigin         string
	AssetOrigin             string
	PublicAssetCORSOrigins  []string
	TrustedProxies          []netip.Prefix
	DatabaseDriver          DatabaseDriver
	DatabaseDSN             string
	DatabaseAllowedNetworks []netip.Prefix
	DatabaseDNSServer       netip.AddrPort
	DatabaseMaxOpenConns    int
	MaxUploadBytes          int64
	MaxConcurrentUploads    int
	ExperimentalPub         bool
	ExperimentalCargo       bool
	ExperimentalNPM         bool
	ExperimentalOCI         bool
	Storage                 StorageConfig
	Muira                   MuiraConfig
}

type StorageDriver string

const (
	StorageFileSystem StorageDriver = "filesystem"
	StorageS3         StorageDriver = "s3"
)

// StorageConfig selects where immutable package objects are kept. S3 settings
// are only populated when the S3-compatible driver is explicitly selected.
// Credentials are referenced by file path and never read from the environment.
type StorageConfig struct {
	Driver             StorageDriver
	S3Endpoint         string
	S3Region           string
	S3Bucket           string
	S3Prefix           string
	S3AccessKeyIDFile  string
	S3SecretKeyFile    string
	S3CAFile           string
	S3AllowedNetworks  []netip.Prefix
	S3DNSServer        netip.AddrPort
	S3MaxConcurrent    int
	S3OperationTimeout time.Duration
}

// MuiraConfig enables the optional Muira OIDC sign-in. Local authentication
// stays available regardless of this configuration.
type MuiraConfig struct {
	Enabled          bool
	Issuer           string
	ClientID         string
	ClientSecretFile string
	CAFile           string
	AllowedNetworks  []netip.Prefix
	DNSServer        netip.AddrPort
}

type MasterKeySettings struct {
	DataDir       string
	MasterKeyFile string
}

type LookupEnv func(string) (string, bool)

func Load() (Config, error) {
	return LoadFrom(lookupEnvironment)
}

func LoadMasterKeySettings() (MasterKeySettings, error) {
	return LoadMasterKeySettingsFrom(lookupEnvironment)
}

func LoadMasterKeySettingsFrom(lookup LookupEnv) (MasterKeySettings, error) {
	if lookup == nil {
		return MasterKeySettings{}, errors.New("environment lookup is required")
	}
	dataDir, err := loadDataDir(lookup)
	if err != nil {
		return MasterKeySettings{}, err
	}
	masterKeyFile, ok := lookup("REGISTRY_MASTER_KEY_FILE")
	if !ok {
		return MasterKeySettings{}, errors.New("REGISTRY_MASTER_KEY_FILE is required")
	}
	masterKeyFile = strings.TrimSpace(masterKeyFile)
	if masterKeyFile == "" {
		return MasterKeySettings{}, errors.New("REGISTRY_MASTER_KEY_FILE must not be empty")
	}
	masterKeyFile, err = filepath.Abs(masterKeyFile)
	if err != nil {
		return MasterKeySettings{}, errors.New("master key file path must be valid")
	}
	return MasterKeySettings{
		DataDir:       dataDir,
		MasterKeyFile: filepath.Clean(masterKeyFile),
	}, nil
}

func LoadFrom(lookup LookupEnv) (Config, error) {
	if lookup == nil {
		return Config{}, errors.New("environment lookup is required")
	}

	listenAddress, err := value(lookup, "REGISTRY_LISTEN_ADDRESS", "127.0.0.1:8080")
	if err != nil {
		return Config{}, err
	}
	if err := validateListenAddress(listenAddress); err != nil {
		return Config{}, err
	}

	dataDir, err := loadDataDir(lookup)
	if err != nil {
		return Config{}, err
	}

	masterKeyFile := ""
	if rawMasterKeyFile, ok := lookup("REGISTRY_MASTER_KEY_FILE"); ok {
		rawMasterKeyFile = strings.TrimSpace(rawMasterKeyFile)
		if rawMasterKeyFile == "" {
			return Config{}, errors.New("REGISTRY_MASTER_KEY_FILE must not be empty")
		}
		masterKeyFile, err = filepath.Abs(rawMasterKeyFile)
		if err != nil {
			return Config{}, errors.New("master key file path must be valid")
		}
		masterKeyFile = filepath.Clean(masterKeyFile)
	}

	canonicalOrigin := ""
	if rawCanonicalOrigin, ok := lookup("REGISTRY_CANONICAL_ORIGIN"); ok {
		canonicalOrigin = strings.TrimSpace(rawCanonicalOrigin)
		if canonicalOrigin == "" {
			return Config{}, errors.New("REGISTRY_CANONICAL_ORIGIN must not be empty")
		}
	}

	assetOrigin := ""
	if rawAssetOrigin, ok := lookup("REGISTRY_ASSET_ORIGIN"); ok {
		assetOrigin = strings.TrimSpace(rawAssetOrigin)
		if assetOrigin == "" {
			return Config{}, errors.New("REGISTRY_ASSET_ORIGIN must not be empty")
		}
	}

	trustedProxies, err := loadTrustedProxies(lookup)
	if err != nil {
		return Config{}, err
	}
	var publicAssetCORSOrigins []string
	if raw, exists := lookup("REGISTRY_PUBLIC_ASSET_CORS_ORIGINS"); exists {
		if len(raw) > 4096 || strings.TrimSpace(raw) == "" {
			return Config{}, errors.New("public asset CORS origins must be a nonempty bounded list")
		}
		for _, part := range strings.Split(raw, ",") {
			origin := strings.TrimSpace(part)
			if origin == "" || len(publicAssetCORSOrigins) >= 32 {
				return Config{}, errors.New("public asset CORS origins must contain at most 32 nonempty entries")
			}
			publicAssetCORSOrigins = append(publicAssetCORSOrigins, origin)
		}
	}

	driverValue, err := value(lookup, "REGISTRY_DATABASE_DRIVER", string(SQLite))
	if err != nil {
		return Config{}, err
	}
	driver := DatabaseDriver(driverValue)
	if driver != SQLite && driver != Postgres {
		return Config{}, errors.New("database driver must be sqlite or postgres")
	}

	defaultDSN := ""
	if driver == SQLite {
		defaultDSN = filepath.Join(dataDir, "registry.sqlite")
	}
	var databaseAllowedNetworks []netip.Prefix
	var databaseDNSServer netip.AddrPort
	if raw, exists := lookup("REGISTRY_DATABASE_DNS_SERVER"); exists {
		var err error
		databaseDNSServer, err = netip.ParseAddrPort(raw)
		address := databaseDNSServer.Addr()
		if err != nil || databaseDNSServer.String() != raw || databaseDNSServer.Port() == 0 || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address == netip.MustParseAddr("255.255.255.255") {
			return Config{}, errors.New("database DNS server must be a canonical unicast IP and port")
		}
	}
	if raw, exists := lookup("REGISTRY_DATABASE_ALLOWED_NETWORKS"); exists {
		if strings.TrimSpace(raw) == "" || len(raw) > 4096 {
			return Config{}, errors.New("database allowed networks must be a bounded CIDR list")
		}
		parts := strings.Split(raw, ",")
		if len(parts) > 128 {
			return Config{}, errors.New("database allowed networks contains too many entries")
		}
		for _, part := range parts {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
			if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
				return Config{}, errors.New("database allowed networks must contain canonical CIDRs")
			}
			databaseAllowedNetworks = append(databaseAllowedNetworks, prefix)
		}
	}
	dsn, err := value(lookup, "REGISTRY_DATABASE_DSN", defaultDSN)
	if err != nil {
		return Config{}, err
	}
	if err := validateDatabaseDSN(driver, dsn); err != nil {
		return Config{}, err
	}
	if driver == SQLite {
		dsn, err = filepath.Abs(dsn)
		if err != nil {
			return Config{}, errors.New("SQLite database path must be a valid local path")
		}
	}

	defaultMaxOpenConns := 10
	if driver == SQLite {
		defaultMaxOpenConns = 4
	}
	maxOpenValue, err := value(lookup, "REGISTRY_DATABASE_MAX_OPEN_CONNS", strconv.Itoa(defaultMaxOpenConns))
	if err != nil {
		return Config{}, err
	}
	maxOpenConns, err := strconv.Atoi(maxOpenValue)
	if err != nil || maxOpenConns < 1 || maxOpenConns > 128 {
		return Config{}, errors.New("database max open connections must be between 1 and 128")
	}

	maxUploadBytesValue, err := value(lookup, "REGISTRY_MAX_UPLOAD_BYTES", strconv.FormatInt(MaxConfiguredUploadBytes, 10))
	if err != nil {
		return Config{}, err
	}
	maxUploadBytes, err := strconv.ParseInt(maxUploadBytesValue, 10, 64)
	if err != nil || maxUploadBytes < 1 || maxUploadBytes > MaxConfiguredUploadBytes {
		return Config{}, errors.New("maximum upload size must be between 1 byte and 1 GiB")
	}

	maxConcurrentUploadsValue, err := value(lookup, "REGISTRY_MAX_CONCURRENT_UPLOADS", "4")
	if err != nil {
		return Config{}, err
	}
	maxConcurrentUploads, err := strconv.Atoi(maxConcurrentUploadsValue)
	if err != nil || maxConcurrentUploads < 1 || maxConcurrentUploads > 128 {
		return Config{}, errors.New("maximum concurrent uploads must be between 1 and 128")
	}
	pubEnabled := false
	if raw, ok := lookup("REGISTRY_EXPERIMENTAL_PUB"); ok {
		switch raw {
		case "true":
			pubEnabled = true
		case "false":
		default:
			return Config{}, errors.New("REGISTRY_EXPERIMENTAL_PUB must be true or false")
		}
	}
	cargoEnabled := false
	if raw, ok := lookup("REGISTRY_EXPERIMENTAL_CARGO"); ok {
		switch raw {
		case "true":
			cargoEnabled = true
		case "false":
		default:
			return Config{}, errors.New("REGISTRY_EXPERIMENTAL_CARGO must be true or false")
		}
	}
	npmEnabled := false
	if raw, ok := lookup("REGISTRY_EXPERIMENTAL_NPM"); ok {
		switch raw {
		case "true":
			npmEnabled = true
		case "false":
		default:
			return Config{}, errors.New("REGISTRY_EXPERIMENTAL_NPM must be true or false")
		}
	}
	ociEnabled := false
	if raw, ok := lookup("REGISTRY_EXPERIMENTAL_OCI"); ok {
		switch raw {
		case "true":
			ociEnabled = true
		case "false":
		default:
			return Config{}, errors.New("REGISTRY_EXPERIMENTAL_OCI must be true or false")
		}
	}
	storageConfig, err := loadStorage(lookup)
	if err != nil {
		return Config{}, err
	}
	muiraConfig, err := loadMuira(lookup)
	if err != nil {
		return Config{}, err
	}

	return Config{
		ListenAddress:           listenAddress,
		DataDir:                 filepath.Clean(dataDir),
		MasterKeyFile:           masterKeyFile,
		CanonicalOrigin:         canonicalOrigin,
		AssetOrigin:             assetOrigin,
		PublicAssetCORSOrigins:  publicAssetCORSOrigins,
		TrustedProxies:          trustedProxies,
		DatabaseDriver:          driver,
		DatabaseDSN:             dsn,
		DatabaseAllowedNetworks: databaseAllowedNetworks,
		DatabaseDNSServer:       databaseDNSServer,
		DatabaseMaxOpenConns:    maxOpenConns,
		MaxUploadBytes:          maxUploadBytes,
		MaxConcurrentUploads:    maxConcurrentUploads,
		ExperimentalPub:         pubEnabled,
		ExperimentalCargo:       cargoEnabled,
		ExperimentalNPM:         npmEnabled,
		ExperimentalOCI:         ociEnabled,
		Storage:                 storageConfig,
		Muira:                   muiraConfig,
	}, nil
}

func loadStorage(lookup LookupEnv) (StorageConfig, error) {
	driverValue, err := value(lookup, "REGISTRY_STORAGE_DRIVER", string(StorageFileSystem))
	if err != nil {
		return StorageConfig{}, err
	}
	s3Keys := []string{"REGISTRY_S3_ENDPOINT", "REGISTRY_S3_REGION", "REGISTRY_S3_BUCKET", "REGISTRY_S3_PREFIX", "REGISTRY_S3_ACCESS_KEY_ID_FILE", "REGISTRY_S3_SECRET_ACCESS_KEY_FILE", "REGISTRY_S3_CA_FILE", "REGISTRY_S3_ALLOWED_NETWORKS", "REGISTRY_S3_DNS_SERVER", "REGISTRY_S3_MAX_CONCURRENT", "REGISTRY_S3_OPERATION_TIMEOUT_SECONDS"}
	switch StorageDriver(driverValue) {
	case StorageFileSystem:
		for _, key := range s3Keys {
			if _, exists := lookup(key); exists {
				return StorageConfig{}, fmt.Errorf("%s requires REGISTRY_STORAGE_DRIVER=s3", key)
			}
		}
		return StorageConfig{Driver: StorageFileSystem}, nil
	case StorageS3:
	default:
		return StorageConfig{}, errors.New("storage driver must be filesystem or s3")
	}
	endpoint, err := requiredHTTPSOrigin(lookup, "REGISTRY_S3_ENDPOINT")
	if err != nil {
		return StorageConfig{}, err
	}
	region, err := required(lookup, "REGISTRY_S3_REGION")
	if err != nil {
		return StorageConfig{}, err
	}
	if len(region) > 128 || strings.ContainsAny(region, "\x00\r\n\t /\\") {
		return StorageConfig{}, errors.New("REGISTRY_S3_REGION is invalid")
	}
	bucket, err := required(lookup, "REGISTRY_S3_BUCKET")
	if err != nil {
		return StorageConfig{}, err
	}
	if len(bucket) < 3 || len(bucket) > 63 {
		return StorageConfig{}, errors.New("REGISTRY_S3_BUCKET is invalid")
	}
	for _, ch := range bucket {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.') {
			return StorageConfig{}, errors.New("REGISTRY_S3_BUCKET is invalid")
		}
	}
	prefix := ""
	if raw, exists := lookup("REGISTRY_S3_PREFIX"); exists {
		prefix = raw
		if prefix == "" || len(prefix) > 256 || strings.Trim(prefix, "/") != prefix || strings.TrimSpace(prefix) != prefix || strings.ContainsAny(prefix, "\\\x00") {
			return StorageConfig{}, errors.New("REGISTRY_S3_PREFIX is invalid")
		}
		for _, part := range strings.Split(prefix, "/") {
			if part == "" || part == "." || part == ".." {
				return StorageConfig{}, errors.New("REGISTRY_S3_PREFIX is invalid")
			}
		}
	}
	accessKeyFile, err := requiredFilePath(lookup, "REGISTRY_S3_ACCESS_KEY_ID_FILE")
	if err != nil {
		return StorageConfig{}, err
	}
	secretKeyFile, err := requiredFilePath(lookup, "REGISTRY_S3_SECRET_ACCESS_KEY_FILE")
	if err != nil {
		return StorageConfig{}, err
	}
	caFile := ""
	if _, exists := lookup("REGISTRY_S3_CA_FILE"); exists {
		caFile, err = requiredFilePath(lookup, "REGISTRY_S3_CA_FILE")
		if err != nil {
			return StorageConfig{}, err
		}
	}
	networks, err := requiredNetworks(lookup, "REGISTRY_S3_ALLOWED_NETWORKS")
	if err != nil {
		return StorageConfig{}, err
	}
	dns, err := optionalDNSServer(lookup, "REGISTRY_S3_DNS_SERVER")
	if err != nil {
		return StorageConfig{}, err
	}
	concurrentValue, err := value(lookup, "REGISTRY_S3_MAX_CONCURRENT", "8")
	if err != nil {
		return StorageConfig{}, err
	}
	concurrent, err := strconv.Atoi(concurrentValue)
	if err != nil || concurrent < 1 || concurrent > 128 {
		return StorageConfig{}, errors.New("REGISTRY_S3_MAX_CONCURRENT must be between 1 and 128")
	}
	timeoutValue, err := value(lookup, "REGISTRY_S3_OPERATION_TIMEOUT_SECONDS", "600")
	if err != nil {
		return StorageConfig{}, err
	}
	timeoutSeconds, err := strconv.Atoi(timeoutValue)
	if err != nil || timeoutSeconds < 1 || timeoutSeconds > 3600 {
		return StorageConfig{}, errors.New("REGISTRY_S3_OPERATION_TIMEOUT_SECONDS must be between 1 and 3600")
	}
	return StorageConfig{
		Driver:             StorageS3,
		S3Endpoint:         endpoint,
		S3Region:           region,
		S3Bucket:           bucket,
		S3Prefix:           prefix,
		S3AccessKeyIDFile:  accessKeyFile,
		S3SecretKeyFile:    secretKeyFile,
		S3CAFile:           caFile,
		S3AllowedNetworks:  networks,
		S3DNSServer:        dns,
		S3MaxConcurrent:    concurrent,
		S3OperationTimeout: time.Duration(timeoutSeconds) * time.Second,
	}, nil
}

func loadMuira(lookup LookupEnv) (MuiraConfig, error) {
	enabled := false
	if raw, ok := lookup("REGISTRY_MUIRA_ENABLED"); ok {
		switch raw {
		case "true":
			enabled = true
		case "false":
		default:
			return MuiraConfig{}, errors.New("REGISTRY_MUIRA_ENABLED must be true or false")
		}
	}
	keys := []string{"REGISTRY_MUIRA_ISSUER", "REGISTRY_MUIRA_CLIENT_ID", "REGISTRY_MUIRA_CLIENT_SECRET_FILE", "REGISTRY_MUIRA_CA_FILE", "REGISTRY_MUIRA_ALLOWED_NETWORKS", "REGISTRY_MUIRA_DNS_SERVER"}
	if !enabled {
		for _, key := range keys {
			if _, exists := lookup(key); exists {
				return MuiraConfig{}, fmt.Errorf("%s requires REGISTRY_MUIRA_ENABLED=true", key)
			}
		}
		return MuiraConfig{}, nil
	}
	issuer, err := requiredHTTPSOrigin(lookup, "REGISTRY_MUIRA_ISSUER")
	if err != nil {
		return MuiraConfig{}, err
	}
	clientID, err := required(lookup, "REGISTRY_MUIRA_CLIENT_ID")
	if err != nil {
		return MuiraConfig{}, err
	}
	if len(clientID) > 256 || strings.ContainsAny(clientID, "\x00\r\n\t ") {
		return MuiraConfig{}, errors.New("REGISTRY_MUIRA_CLIENT_ID is invalid")
	}
	secretFile, err := requiredFilePath(lookup, "REGISTRY_MUIRA_CLIENT_SECRET_FILE")
	if err != nil {
		return MuiraConfig{}, err
	}
	caFile := ""
	if _, exists := lookup("REGISTRY_MUIRA_CA_FILE"); exists {
		caFile, err = requiredFilePath(lookup, "REGISTRY_MUIRA_CA_FILE")
		if err != nil {
			return MuiraConfig{}, err
		}
	}
	networks, err := requiredNetworks(lookup, "REGISTRY_MUIRA_ALLOWED_NETWORKS")
	if err != nil {
		return MuiraConfig{}, err
	}
	dns, err := optionalDNSServer(lookup, "REGISTRY_MUIRA_DNS_SERVER")
	if err != nil {
		return MuiraConfig{}, err
	}
	return MuiraConfig{Enabled: true, Issuer: issuer, ClientID: clientID, ClientSecretFile: secretFile, CAFile: caFile, AllowedNetworks: networks, DNSServer: dns}, nil
}

func required(lookup LookupEnv, key string) (string, error) {
	raw, ok := lookup(key)
	if !ok {
		return "", fmt.Errorf("%s is required", key)
	}
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", fmt.Errorf("%s must be a nonempty value without surrounding whitespace", key)
	}
	return raw, nil
}

// requiredHTTPSOrigin accepts only scheme://host[:port] with HTTPS; the value
// is returned without a trailing slash.
func requiredHTTPSOrigin(lookup LookupEnv, key string) (string, error) {
	raw, err := required(lookup, key)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.Hostname() == "" {
		return "", fmt.Errorf("%s must be an HTTPS origin without path, query or credentials", key)
	}
	return "https://" + strings.ToLower(parsed.Host), nil
}

func requiredFilePath(lookup LookupEnv, key string) (string, error) {
	raw, err := required(lookup, key)
	if err != nil {
		return "", err
	}
	path, err := filepath.Abs(raw)
	if err != nil || strings.ContainsRune(raw, 0) {
		return "", fmt.Errorf("%s must be a valid local path", key)
	}
	return filepath.Clean(path), nil
}

func requiredNetworks(lookup LookupEnv, key string) ([]netip.Prefix, error) {
	raw, ok := lookup(key)
	if !ok {
		return nil, fmt.Errorf("%s is required; outbound access is denied without explicit networks", key)
	}
	if strings.TrimSpace(raw) == "" || len(raw) > 4096 {
		return nil, fmt.Errorf("%s must be a bounded CIDR list", key)
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 128 {
		return nil, fmt.Errorf("%s contains too many entries", key)
	}
	networks := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, fmt.Errorf("%s must contain canonical CIDRs", key)
		}
		networks = append(networks, prefix)
	}
	return networks, nil
}

func optionalDNSServer(lookup LookupEnv, key string) (netip.AddrPort, error) {
	raw, exists := lookup(key)
	if !exists {
		return netip.AddrPort{}, nil
	}
	server, err := netip.ParseAddrPort(raw)
	address := server.Addr()
	if err != nil || server.String() != raw || server.Port() == 0 || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address == netip.MustParseAddr("255.255.255.255") {
		return netip.AddrPort{}, fmt.Errorf("%s must be a canonical unicast IP and port", key)
	}
	return server, nil
}

func loadTrustedProxies(lookup LookupEnv) ([]netip.Prefix, error) {
	raw, exists := lookup("REGISTRY_TRUSTED_PROXIES")
	if !exists {
		return nil, nil
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 4096 {
		return nil, errors.New("REGISTRY_TRUSTED_PROXIES must contain valid IP addresses or CIDRs")
	}

	parts := strings.Split(raw, ",")
	if len(parts) > 128 {
		return nil, errors.New("REGISTRY_TRUSTED_PROXIES contains too many entries")
	}
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			return nil, errors.New("REGISTRY_TRUSTED_PROXIES must contain valid IP addresses or CIDRs")
		}
		prefix, err := parseProxyPrefix(entry)
		if err != nil {
			return nil, errors.New("REGISTRY_TRUSTED_PROXIES must contain valid IP addresses or CIDRs")
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseProxyPrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		address := prefix.Addr()
		if address.Is4In6() {
			if prefix.Bits() < 96 {
				return netip.Prefix{}, errors.New("mapped IPv4 proxy prefix is too broad")
			}
			prefix = netip.PrefixFrom(address.Unmap(), prefix.Bits()-96)
		}
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return netip.Prefix{}, errors.New("proxy address is invalid")
	}
	address = address.Unmap()
	return netip.PrefixFrom(address, address.BitLen()), nil
}

func loadDataDir(lookup LookupEnv) (string, error) {
	dataDir, err := value(lookup, "REGISTRY_DATA_DIR", "./data")
	if err != nil {
		return "", err
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return "", errors.New("data directory must be a valid local path")
	}
	return filepath.Clean(dataDir), nil
}

func lookupEnvironment(key string) (string, bool) {
	return os.LookupEnv(key)
}

func value(lookup LookupEnv, key, defaultValue string) (string, error) {
	value, ok := lookup(key)
	if !ok {
		return defaultValue, nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s must not be empty", key)
	}
	return value, nil
}

func validateListenAddress(address string) error {
	host, portValue, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return errors.New("listen address must include an explicit host and port")
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listen port must be between 1 and 65535")
	}
	return nil
}

func validateDatabaseDSN(driver DatabaseDriver, dsn string) error {
	if dsn == "" {
		return errors.New("database DSN is required")
	}
	if driver == SQLite {
		if dsn == ":memory:" || strings.HasPrefix(dsn, "file:") {
			return errors.New("SQLite database DSN must be a persistent filesystem path")
		}
		return nil
	}
	if driver == Postgres {
		if _, err := pgx.ParseConfig(dsn); err != nil {
			return errors.New("PostgreSQL database DSN is invalid")
		}
		return nil
	}
	return errors.New("unsupported database driver")
}
