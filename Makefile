.PHONY: build test fuzz lint snapshot
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/Anurag-Chevendra/mantis/internal/version.Version=$(VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o mantis ./cmd/mantis

test:
	go test -race ./...

fuzz:
	go test -run=^$$ -fuzz=FuzzParse -fuzztime=60s ./internal/lockfile/

lint:
	test -z "$$(gofmt -l .)" && go vet ./...

snapshot:
	goreleaser release --snapshot --clean
