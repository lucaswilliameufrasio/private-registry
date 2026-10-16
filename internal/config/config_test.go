package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFromDefaultsToLoopbackAndPersistentSQLite(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	values := map[string]string{"REGISTRY_DATA_DIR": dataDir}

	config, err := LoadFrom(lookupMap(values))
	if err != nil {
		t.Fatal(err)
	}
	if config.ListenAddress != "127.0.0.1:8080" {
		t.Fatalf("unexpected default listen address: %q", config.ListenAddress)
	}
	if config.DatabaseDriver != SQLite {
		t.Fatalf("unexpected default database driver: %q", config.DatabaseDriver)
	}
	if config.DataDir != dataDir {
		t.Fatalf("unexpected data directory: got %q, want %q", config.DataDir, dataDir)
	}
	if config.DatabaseDSN != filepath.Join(dataDir, "registry.sqlite") {
		t.Fatalf("unexpected SQLite path: %q", config.DatabaseDSN)
	}
	if config.DatabaseMaxOpenConns != 4 {
		t.Fatalf("unexpected SQLite pool limit: %d", config.DatabaseMaxOpenConns)
	}
}

func TestLoadFromAcceptsPostgresDSNWithoutConnecting(t *testing.T) {
	values := map[string]string{
		"REGISTRY_DATABASE_DRIVER": "postgres",
		"REGISTRY_DATABASE_DSN":    "postgres://registry@127.0.0.1:5432/registry?sslmode=disable",
	}

	config, err := LoadFrom(lookupMap(values))
	if err != nil {
		t.Fatal(err)
	}
	if config.DatabaseDriver != Postgres {
		t.Fatalf("unexpected database driver: %q", config.DatabaseDriver)
	}
	if config.DatabaseMaxOpenConns != 10 {
		t.Fatalf("unexpected PostgreSQL pool limit: %d", config.DatabaseMaxOpenConns)
	}
}

func TestLoadFromRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
	}{
		{
			name:   "wildcard host without explicit interface",
			values: map[string]string{"REGISTRY_LISTEN_ADDRESS": ":8080"},
		},
		{
			name:   "invalid port",
			values: map[string]string{"REGISTRY_LISTEN_ADDRESS": "127.0.0.1:70000"},
		},
		{
			name:   "unsupported database",
			values: map[string]string{"REGISTRY_DATABASE_DRIVER": "mysql"},
		},
		{
			name:   "in-memory sqlite",
			values: map[string]string{"REGISTRY_DATABASE_DSN": ":memory:"},
		},
		{
			name: "missing postgres dsn",
			values: map[string]string{
				"REGISTRY_DATABASE_DRIVER": "postgres",
			},
		},
		{
			name: "malformed postgres dsn",
			values: map[string]string{
				"REGISTRY_DATABASE_DRIVER": "postgres",
				"REGISTRY_DATABASE_DSN":    "postgres://%",
			},
		},
		{
			name:   "pool size above safety bound",
			values: map[string]string{"REGISTRY_DATABASE_MAX_OPEN_CONNS": "129"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadFrom(lookupMap(test.values))
			if err == nil {
				t.Fatal("expected invalid configuration to fail")
			}
		})
	}
}

func TestLoadFromDoesNotEchoInvalidDSN(t *testing.T) {
	values := map[string]string{
		"REGISTRY_DATABASE_DRIVER": "postgres",
		"REGISTRY_DATABASE_DSN":    "postgres://private-value@%",
	}

	_, err := LoadFrom(lookupMap(values))
	if err == nil {
		t.Fatal("expected malformed DSN to fail")
	}
	if strings.Contains(err.Error(), "private-value") {
		t.Fatalf("configuration error exposed DSN contents: %q", err)
	}
}

func lookupMap(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
