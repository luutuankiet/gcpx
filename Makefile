.PHONY: build test fmt clean release-snapshot install
BIN := bin/gcpx
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	go build -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/gcpx

test:
	go test ./...

fmt:
	go fmt ./...
	go vet ./...

install: build
	install -m 0755 $(BIN) $(HOME)/.local/bin/gcpx

clean:
	rm -rf bin/ dist/

release-snapshot:
	goreleaser release --snapshot --clean
