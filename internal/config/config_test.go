package config

import (
	"net/netip"
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
	if config.MaxUploadBytes != MaxConfiguredUploadBytes || config.MaxConcurrentUploads != 4 {
		t.Fatalf("unexpected upload limits: bytes=%d concurrent=%d", config.MaxUploadBytes, config.MaxConcurrentUploads)
	}
	if len(config.PublicAssetCORSOrigins) != 0 {
		t.Fatal("public asset CORS must default to disabled")
	}
}

func TestPublicAssetCORSOriginListIsBounded(t *testing.T) {
	cfg, err := LoadFrom(lookupMap(map[string]string{"REGISTRY_PUBLIC_ASSET_CORS_ORIGINS": " https://app.example,https://docs.example "}))
	if err != nil || len(cfg.PublicAssetCORSOrigins) != 2 || cfg.PublicAssetCORSOrigins[0] != "https://app.example" || cfg.PublicAssetCORSOrigins[1] != "https://docs.example" {
		t.Fatalf("CORS list = %v, %v", cfg.PublicAssetCORSOrigins, err)
	}
	for _, value := range []string{"", "https://app.example,", strings.Repeat("https://a.example,", 33) + "https://b.example"} {
		if _, err := LoadFrom(lookupMap(map[string]string{"REGISTRY_PUBLIC_ASSET_CORS_ORIGINS": value})); err == nil {
			t.Fatalf("invalid CORS list %q was accepted", value)
		}
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

func TestLoadFromResolvesOptionalMasterKeyFilePath(t *testing.T) {
	keyPath := filepath.Join("secrets", "registry-master.key")
	absoluteKeyPath, err := filepath.Abs(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	config, err := LoadFrom(lookupMap(map[string]string{
		"REGISTRY_MASTER_KEY_FILE": keyPath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.MasterKeyFile != absoluteKeyPath {
		t.Fatalf("unexpected master key file path: got %q, want %q", config.MasterKeyFile, absoluteKeyPath)
	}
}

func TestLoadFromAcceptsCanonicalOriginAndTrustedProxyRanges(t *testing.T) {
	config, err := LoadFrom(lookupMap(map[string]string{
		"REGISTRY_CANONICAL_ORIGIN": " https://registry.example ",
		"REGISTRY_ASSET_ORIGIN":     " https://assets.example ",
		"REGISTRY_TRUSTED_PROXIES":  "192.0.2.7, 2001:db8::/32",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.CanonicalOrigin != "https://registry.example" {
		t.Fatalf("unexpected canonical origin: %q", config.CanonicalOrigin)
	}
	if config.AssetOrigin != "https://assets.example" {
		t.Fatalf("unexpected asset origin: %q", config.AssetOrigin)
	}
	wantPrefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.7/32"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if len(config.TrustedProxies) != len(wantPrefixes) {
		t.Fatalf("unexpected trusted proxy count: %d", len(config.TrustedProxies))
	}
	for index, want := range wantPrefixes {
		if config.TrustedProxies[index] != want {
			t.Fatalf("unexpected trusted proxy at index %d: got %s, want %s", index, config.TrustedProxies[index], want)
		}
	}
}

func TestLoadMasterKeySettingsRequiresAndResolvesFilePath(t *testing.T) {
	keyPath := filepath.Join("secrets", "registry-master.key")
	absoluteKeyPath, err := filepath.Abs(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(t.TempDir(), "registry-data")

	settings, err := LoadMasterKeySettingsFrom(lookupMap(map[string]string{
		"REGISTRY_DATA_DIR":        dataDir,
		"REGISTRY_MASTER_KEY_FILE": keyPath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if settings.MasterKeyFile != absoluteKeyPath {
		t.Fatalf("unexpected master key file path: got %q, want %q", settings.MasterKeyFile, absoluteKeyPath)
	}
	if settings.DataDir != dataDir {
		t.Fatalf("unexpected data directory: got %q, want %q", settings.DataDir, dataDir)
	}

	for _, values := range []map[string]string{
		{},
		{"REGISTRY_MASTER_KEY_FILE": "  "},
	} {
		if _, err := LoadMasterKeySettingsFrom(lookupMap(values)); err == nil {
			t.Fatalf("expected missing or empty master key path to fail: %#v", values)
		}
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
		{
			name:   "upload size exceeds storage schema limit",
			values: map[string]string{"REGISTRY_MAX_UPLOAD_BYTES": "1073741825"},
		},
		{
			name:   "zero upload size",
			values: map[string]string{"REGISTRY_MAX_UPLOAD_BYTES": "0"},
		},
		{
			name:   "too many concurrent uploads",
			values: map[string]string{"REGISTRY_MAX_CONCURRENT_UPLOADS": "129"},
		},
		{
			name:   "empty canonical origin",
			values: map[string]string{"REGISTRY_CANONICAL_ORIGIN": "  "},
		},
		{
			name:   "trusted proxy hostname",
			values: map[string]string{"REGISTRY_TRUSTED_PROXIES": "proxy.example"},
		},
		{
			name:   "empty trusted proxy entry",
			values: map[string]string{"REGISTRY_TRUSTED_PROXIES": "192.0.2.1,"},
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
