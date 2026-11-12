.PHONY: build build-arm64 verify-arm64 format format-check lint test setup-floci setup-postgres setup-oci setup-authentik check-hex test-integration race verify spike-sqlite

build:
	CGO_ENABLED=0 go build ./...

build-arm64:
	GOARCH=arm64 CGO_ENABLED=0 go build ./...

# Runs the suites with an arm64 build under QEMU user emulation
# (qemu-aarch64). Without binfmt_misc registration, tests that re-execute
# their own binary or build and run a helper cannot run and are reported.
verify-arm64: build-arm64 setup-floci setup-postgres setup-oci
	GOARCH=arm64 CGO_ENABLED=0 go test -exec qemu-aarch64 -count=1 ./...
	GOARCH=arm64 CGO_ENABLED=0 go test -exec qemu-aarch64 -p=1 -timeout=60m -tags=integration -count=1 ./...

format:
	gofmt -w cmd internal

format-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

lint:
	go vet ./...
	go vet -tags=integration ./...
	bash -n scripts/setup-floci.sh
	bash -n scripts/setup-postgres.sh
	bash -n scripts/setup-oci.sh
	bash -n scripts/setup-authentik.sh
	bash -n scripts/check-hex.sh

test:
	go test -count=1 ./...

setup-floci:
	bash scripts/setup-floci.sh

setup-postgres:
	bash scripts/setup-postgres.sh

setup-oci:
	bash scripts/setup-oci.sh

setup-authentik:
	bash scripts/setup-authentik.sh

check-hex:
	bash scripts/check-hex.sh

test-integration: setup-floci setup-postgres setup-oci setup-authentik check-hex
	go test -p=1 -timeout=20m -tags=integration -count=3 ./...

race: setup-floci setup-postgres setup-oci setup-authentik check-hex
	go test -p=1 -race -timeout=20m -tags=integration -count=1 ./...

verify: build format-check lint test test-integration race

spike-sqlite:
	go run ./cmd/spikes/sqlitebackup
