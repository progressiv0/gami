BINARY   := gami
BUILD_DIR := bin
MODULE   := github.com/progressiv0/gami

.PHONY: all build test lint clean install

all: build

## build: Compile the CLI binary for the current OS/arch
build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cli

## install: Install the CLI to $GOPATH/bin
install:
	go install ./cli

## test: Run all tests
test:
	go test ./...

## lint: Run go vet
lint:
	go vet ./...

## tidy: Tidy and verify go.mod
tidy:
	go mod tidy
	go mod verify

## clean: Remove build output
clean:
	rm -rf $(BUILD_DIR)

## cross: Build binaries for Linux, macOS, and Windows
cross:
	GOOS=linux   GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-linux-amd64   ./cli
	GOOS=darwin  GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  ./cli
	GOOS=darwin  GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  ./cli
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe ./cli

## help: Show this help
help:
	@grep -E '^##' Makefile | sed 's/## //'
