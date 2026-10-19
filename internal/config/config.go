package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

type DatabaseDriver string

const (
	SQLite   DatabaseDriver = "sqlite"
	Postgres DatabaseDriver = "postgres"
)

type Config struct {
	ListenAddress        string
	DataDir              string
	MasterKeyFile        string
	DatabaseDriver       DatabaseDriver
	DatabaseDSN          string
	DatabaseMaxOpenConns int
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

	return Config{
		ListenAddress:        listenAddress,
		DataDir:              filepath.Clean(dataDir),
		MasterKeyFile:        masterKeyFile,
		DatabaseDriver:       driver,
		DatabaseDSN:          dsn,
		DatabaseMaxOpenConns: maxOpenConns,
	}, nil
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
