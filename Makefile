.PHONY: build format format-check lint test test-integration race verify spike-sqlite

build:
	CGO_ENABLED=0 go build ./...

format:
	gofmt -w cmd internal

format-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

lint:
	go vet ./...

test:
	go test -count=1 ./...

test-integration:
	go test -count=3 ./internal/spikes/sqlitebackup

race:
	go test -race -count=1 ./...

verify: build format-check lint test test-integration race

spike-sqlite:
	go run ./cmd/spikes/sqlitebackup
