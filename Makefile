BINARY    := gami
BUILD_DIR := bin
CORE_DIR  := gami-core
CLI_DIR   := gami-cli
GO        := go

.PHONY: all build install test lint tidy clean cross help

all: build

## build: Compile the CLI binary for the current OS/arch
build:
	cd $(CLI_DIR) && $(GO) build -o ../$(BUILD_DIR)/$(BINARY) .

## install: Install the CLI to $GOPATH/bin
install:
	cd $(CLI_DIR) && $(GO) install .

## test: Run all tests in both modules
test:
	cd $(CORE_DIR) && $(GO) test ./...
	cd $(CLI_DIR)  && $(GO) test ./...

## lint: Run go vet on both modules
lint:
	cd $(CORE_DIR) && $(GO) vet ./...
	cd $(CLI_DIR)  && $(GO) vet ./...

## tidy: Tidy and verify both modules
tidy:
	cd $(CORE_DIR) && $(GO) mod tidy && $(GO) mod verify
	cd $(CLI_DIR)  && $(GO) mod tidy && $(GO) mod verify

## clean: Remove build output
clean:
	rm -rf $(BUILD_DIR)

## cross: Build binaries for Linux, macOS, and Windows
cross:
	cd $(CLI_DIR) && GOOS=linux   GOARCH=amd64 $(GO) build -o ../$(BUILD_DIR)/$(BINARY)-linux-amd64   .
	cd $(CLI_DIR) && GOOS=darwin  GOARCH=amd64 $(GO) build -o ../$(BUILD_DIR)/$(BINARY)-darwin-amd64  .
	cd $(CLI_DIR) && GOOS=darwin  GOARCH=arm64 $(GO) build -o ../$(BUILD_DIR)/$(BINARY)-darwin-arm64  .
	cd $(CLI_DIR) && GOOS=windows GOARCH=amd64 $(GO) build -o ../$(BUILD_DIR)/$(BINARY)-windows-amd64.exe .

## help: Show this help
help:
	@grep -E '^##' Makefile | sed 's/## //'
