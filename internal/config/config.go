package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	}, nil
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
