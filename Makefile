.PHONY: build test test-race clean install completion

# Build the CLI binary
build:
	go build -ldflags "-X main.version=$(shell git describe --tags --always --dirty) -X main.commit=$(shell git rev-parse --short HEAD)" -o shorten .

# Run unit tests
test:
	go test -v ./...

# Run tests with race detector
test-race:
	go test -race -v ./...

# Clean build artifacts
clean:
	go clean
	rm -f shorten

# Install globally
install: build
	go install .

# Generate shell completions (example)
completion-bash:
	./shorten completion bash > shorten-completion.bash

completion-zsh:
	./shorten completion zsh > _shorten

completion-fish:
	./shorten completion fish > shorten.fish

# Run all tests and build
all: test build

# Development setup
dev-setup:
	go mod tidy
	go mod download

# Lint (requires golangci-lint)
lint:
	golangci-lint run

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...