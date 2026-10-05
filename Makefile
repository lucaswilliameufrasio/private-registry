.PHONY: build format format-check lint test setup-floci setup-postgres setup-oci test-integration race verify spike-sqlite

build:
	CGO_ENABLED=0 go build ./...

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

test:
	go test -count=1 ./...

setup-floci:
	bash scripts/setup-floci.sh

setup-postgres:
	bash scripts/setup-postgres.sh

setup-oci:
	bash scripts/setup-oci.sh

test-integration: setup-floci setup-postgres setup-oci
	go test -tags=integration -count=3 ./...

race: setup-floci setup-postgres setup-oci
	go test -race -tags=integration -count=1 ./...

verify: build format-check lint test test-integration race

spike-sqlite:
	go run ./cmd/spikes/sqlitebackup
