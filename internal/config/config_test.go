package config

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestExperimentalPubRequiresExplicitBoolean(t *testing.T) {
	for _, item := range []struct {
		value   string
		enabled bool
		valid   bool
	}{{"true", true, true}, {"false", false, true}, {"", false, false}, {"1", false, false}, {"TRUE", false, false}} {
		cfg, err := LoadFrom(lookupMap(map[string]string{"REGISTRY_EXPERIMENTAL_PUB": item.value}))
		if item.valid && (err != nil || cfg.ExperimentalPub != item.enabled) {
			t.Fatalf("Pub setting %q: enabled=%v err=%v", item.value, cfg.ExperimentalPub, err)
		}
		if !item.valid && err == nil {
			t.Fatalf("invalid Pub setting %q was accepted", item.value)
		}
	}
	cfg, err := LoadFrom(lookupMap(nil))
	if err != nil || cfg.ExperimentalPub {
		t.Fatalf("Pub should be disabled by default: %v", err)
	}
}

func TestExperimentalCargoRequiresExplicitBoolean(t *testing.T) {
	for _, item := range []struct {
		value   string
		enabled bool
		valid   bool
	}{{"true", true, true}, {"false", false, true}, {"", false, false}, {"1", false, false}, {"TRUE", false, false}} {
		cfg, err := LoadFrom(lookupMap(map[string]string{"REGISTRY_EXPERIMENTAL_CARGO": item.value}))
		if item.valid && (err != nil || cfg.ExperimentalCargo != item.enabled) {
			t.Fatalf("Cargo setting %q: enabled=%v err=%v", item.value, cfg.ExperimentalCargo, err)
		}
		if !item.valid && err == nil {
			t.Fatalf("invalid Cargo setting %q was accepted", item.value)
		}
	}
	cfg, err := LoadFrom(lookupMap(nil))
	if err != nil || cfg.ExperimentalCargo {
		t.Fatalf("Cargo should be disabled by default: %v", err)
	}
}

func TestExperimentalNPMRequiresExplicitBoolean(t *testing.T) {
	for _, item := range []struct {
		value   string
		enabled bool
		valid   bool
	}{{"true", true, true}, {"false", false, true}, {"", false, false}, {"1", false, false}, {"TRUE", false, false}} {
		cfg, err := LoadFrom(lookupMap(map[string]string{"REGISTRY_EXPERIMENTAL_NPM": item.value}))
		if item.valid && (err != nil || cfg.ExperimentalNPM != item.enabled) {
			t.Fatalf("npm setting %q: enabled=%v err=%v", item.value, cfg.ExperimentalNPM, err)
		}
		if !item.valid && err == nil {
			t.Fatalf("invalid npm setting %q was accepted", item.value)
		}
	}
	cfg, err := LoadFrom(lookupMap(nil))
	if err != nil || cfg.ExperimentalNPM {
		t.Fatalf("npm should be disabled by default: %v", err)
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

func TestDatabaseAllowedNetworksAreExplicitAndCanonical(t *testing.T) {
	cfg, err := LoadFrom(lookupMap(map[string]string{"REGISTRY_DATABASE_ALLOWED_NETWORKS": "192.0.2.0/24, 2001:db8::/32"}))
	if err != nil || len(cfg.DatabaseAllowedNetworks) != 2 || cfg.DatabaseAllowedNetworks[0] != netip.MustParsePrefix("192.0.2.0/24") || cfg.DatabaseAllowedNetworks[1] != netip.MustParsePrefix("2001:db8::/32") {
		t.Fatalf("database allowed networks were not parsed: %v", err)
	}
	for _, raw := range []string{"", "192.0.2.1/24", "192.0.2.1", "192.0.2.0/24,", "::ffff:192.0.2.0/120", strings.Repeat("192.0.2.0/24,", 129)} {
		if _, err := LoadFrom(lookupMap(map[string]string{"REGISTRY_DATABASE_ALLOWED_NETWORKS": raw})); err == nil {
			t.Fatal("invalid database allowed networks were accepted")
		}
	}
	cfg, err = LoadFrom(lookupMap(nil))
	if err != nil || len(cfg.DatabaseAllowedNetworks) != 0 {
		t.Fatal("database network access did not default to denied")
	}
}

func TestDatabaseDNSServerMustBeExplicitUnicastAddress(t *testing.T) {
	cfg, err := LoadFrom(lookupMap(map[string]string{"REGISTRY_DATABASE_DNS_SERVER": "127.0.0.1:5353"}))
	if err != nil || cfg.DatabaseDNSServer != netip.MustParseAddrPort("127.0.0.1:5353") {
		t.Fatalf("database DNS server was not parsed: %v", err)
	}
	for _, raw := range []string{"", "dns.example:53", "127.0.0.1:0", "0.0.0.0:53", "224.0.0.1:53", "[::ffff:127.0.0.1]:53", "127.0.0.1:053", " 127.0.0.1:53"} {
		if _, err := LoadFrom(lookupMap(map[string]string{"REGISTRY_DATABASE_DNS_SERVER": raw})); err == nil {
			t.Fatal("invalid database DNS server was accepted")
		}
	}
	cfg, err = LoadFrom(lookupMap(nil))
	if err != nil || cfg.DatabaseDNSServer.IsValid() {
		t.Fatal("database DNS server was implicitly enabled")
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

func TestStorageDefaultsToFilesystemAndRejectsStrayS3Settings(t *testing.T) {
	cfg, err := LoadFrom(func(string) (string, bool) { return "", false })
	if err != nil || cfg.Storage.Driver != StorageFileSystem {
		t.Fatalf("default storage = %#v, %v", cfg.Storage, err)
	}
	if _, err := LoadFrom(mapLookup(map[string]string{"REGISTRY_S3_BUCKET": "packages"})); err == nil {
		t.Fatal("S3 setting without the S3 driver was accepted")
	}
	if _, err := LoadFrom(mapLookup(map[string]string{"REGISTRY_STORAGE_DRIVER": "gcs"})); err == nil {
		t.Fatal("unknown storage driver was accepted")
	}
}

func validS3Environment() map[string]string {
	return map[string]string{
		"REGISTRY_STORAGE_DRIVER":            "s3",
		"REGISTRY_S3_ENDPOINT":               "https://account.r2.cloudflarestorage.com",
		"REGISTRY_S3_REGION":                 "auto",
		"REGISTRY_S3_BUCKET":                 "registry-packages",
		"REGISTRY_S3_ACCESS_KEY_ID_FILE":     "/run/secrets/s3-access-key-id",
		"REGISTRY_S3_SECRET_ACCESS_KEY_FILE": "/run/secrets/s3-secret-access-key",
		"REGISTRY_S3_ALLOWED_NETWORKS":       "104.16.0.0/13, 2606:4700::/32",
		"REGISTRY_S3_DNS_SERVER":             "1.1.1.1:53",
	}
}

func TestStorageS3RequiresExplicitEndpointCredentialsAndNetworks(t *testing.T) {
	cfg, err := LoadFrom(mapLookup(validS3Environment()))
	if err != nil {
		t.Fatal(err)
	}
	storage := cfg.Storage
	if storage.Driver != StorageS3 || storage.S3Endpoint != "https://account.r2.cloudflarestorage.com" || storage.S3Region != "auto" || storage.S3Bucket != "registry-packages" || storage.S3Prefix != "" || len(storage.S3AllowedNetworks) != 2 || !storage.S3DNSServer.IsValid() || storage.S3MaxConcurrent != 8 || storage.S3OperationTimeout != 10*time.Minute {
		t.Fatalf("S3 storage configuration = %#v", storage)
	}
	for _, key := range []string{"REGISTRY_S3_ENDPOINT", "REGISTRY_S3_REGION", "REGISTRY_S3_BUCKET", "REGISTRY_S3_ACCESS_KEY_ID_FILE", "REGISTRY_S3_SECRET_ACCESS_KEY_FILE", "REGISTRY_S3_ALLOWED_NETWORKS"} {
		environment := validS3Environment()
		delete(environment, key)
		if _, err := LoadFrom(mapLookup(environment)); err == nil {
			t.Errorf("S3 storage without %s was accepted", key)
		}
	}
	for key, invalid := range map[string]string{
		"REGISTRY_S3_ENDPOINT":                  "http://plaintext.example",
		"REGISTRY_S3_BUCKET":                    "Upper_Case",
		"REGISTRY_S3_PREFIX":                    "../escape",
		"REGISTRY_S3_ALLOWED_NETWORKS":          "10.0.0.1/8",
		"REGISTRY_S3_DNS_SERVER":                "0.0.0.0:53",
		"REGISTRY_S3_MAX_CONCURRENT":            "0",
		"REGISTRY_S3_OPERATION_TIMEOUT_SECONDS": "7200",
		"REGISTRY_S3_REGION":                    "us east",
	} {
		environment := validS3Environment()
		environment[key] = invalid
		if _, err := LoadFrom(mapLookup(environment)); err == nil {
			t.Errorf("S3 storage accepted %s=%q", key, invalid)
		}
	}
	environment := validS3Environment()
	environment["REGISTRY_S3_ENDPOINT"] = "https://user:secret@account.example/path"
	if _, err := LoadFrom(mapLookup(environment)); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("endpoint with credentials was accepted or echoed: %v", err)
	}
}

func TestMuiraIsOptionalAndRequiresCompleteConfiguration(t *testing.T) {
	cfg, err := LoadFrom(func(string) (string, bool) { return "", false })
	if err != nil || cfg.Muira.Enabled {
		t.Fatalf("Muira enabled by default: %#v, %v", cfg.Muira, err)
	}
	if _, err := LoadFrom(mapLookup(map[string]string{"REGISTRY_MUIRA_ISSUER": "https://auth.example"})); err == nil {
		t.Fatal("Muira setting without explicit enablement was accepted")
	}
	valid := func() map[string]string {
		return map[string]string{
			"REGISTRY_MUIRA_ENABLED":            "true",
			"REGISTRY_MUIRA_ISSUER":             "https://auth.example",
			"REGISTRY_MUIRA_CLIENT_ID":          "private-registry",
			"REGISTRY_MUIRA_CLIENT_SECRET_FILE": "/run/secrets/muira-client-secret",
			"REGISTRY_MUIRA_ALLOWED_NETWORKS":   "203.0.113.0/24",
		}
	}
	cfg, err = LoadFrom(mapLookup(valid()))
	if err != nil || !cfg.Muira.Enabled || cfg.Muira.Issuer != "https://auth.example" || cfg.Muira.ClientID != "private-registry" || len(cfg.Muira.AllowedNetworks) != 1 {
		t.Fatalf("Muira configuration = %#v, %v", cfg.Muira, err)
	}
	for _, key := range []string{"REGISTRY_MUIRA_ISSUER", "REGISTRY_MUIRA_CLIENT_ID", "REGISTRY_MUIRA_CLIENT_SECRET_FILE", "REGISTRY_MUIRA_ALLOWED_NETWORKS"} {
		environment := valid()
		delete(environment, key)
		if _, err := LoadFrom(mapLookup(environment)); err == nil {
			t.Errorf("Muira without %s was accepted", key)
		}
	}
	environment := valid()
	environment["REGISTRY_MUIRA_ISSUER"] = "http://auth.example"
	if _, err := LoadFrom(mapLookup(environment)); err == nil {
		t.Error("plaintext Muira issuer was accepted")
	}
	environment = valid()
	environment["REGISTRY_MUIRA_ENABLED"] = "yes"
	if _, err := LoadFrom(mapLookup(environment)); err == nil {
		t.Error("non-boolean Muira enablement was accepted")
	}
}

func TestExperimentalOCIRequiresExplicitBoolean(t *testing.T) {
	for raw, want := range map[string]bool{"true": true, "false": false} {
		cfg, err := LoadFrom(mapLookup(map[string]string{"REGISTRY_EXPERIMENTAL_OCI": raw}))
		if err != nil || cfg.ExperimentalOCI != want {
			t.Fatalf("OCI %q = %v, %v", raw, cfg.ExperimentalOCI, err)
		}
	}
	if _, err := LoadFrom(mapLookup(map[string]string{"REGISTRY_EXPERIMENTAL_OCI": "1"})); err == nil {
		t.Fatal("non-boolean OCI enablement was accepted")
	}
}

func mapLookup(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
