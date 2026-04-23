CLI_BINARY := gami-cli
API_BINARY := gami-api
BUILD_DIR  := bin
CORE_DIR   := gami-core
CLI_DIR    := gami-cli
API_DIR    := gami-api
GO         := go

.PHONY: all build install test lint tidy clean cross help

all: build

## build: Compile the CLI and API binaries for the current OS/arch
build:
	cd $(CLI_DIR) && $(GO) build -o ../$(BUILD_DIR)/$(CLI_BINARY) .
	cd $(API_DIR) && $(GO) build -o ../$(BUILD_DIR)/$(API_BINARY) .

## install: Install the CLI to $GOPATH/bin
install:
	cd $(CLI_DIR) && $(GO) install .

## test: Run all tests in all modules
test:
	cd $(CORE_DIR) && $(GO) test ./...
	cd $(CLI_DIR)  && $(GO) test ./...
	cd $(API_DIR)  && $(GO) test ./...

## lint: Run go vet on all modules
lint:
	cd $(CORE_DIR) && $(GO) vet ./...
	cd $(CLI_DIR)  && $(GO) vet ./...
	cd $(API_DIR)  && $(GO) vet ./...

## tidy: Tidy and verify all modules
tidy:
	cd $(CORE_DIR) && $(GO) mod tidy && $(GO) mod verify
	cd $(CLI_DIR)  && $(GO) mod tidy && $(GO) mod verify
	cd $(API_DIR)  && $(GO) mod tidy && $(GO) mod verify

## clean: Remove build output
clean:
	rm -rf $(BUILD_DIR)

## cross: Build CLI and API binaries for Linux, macOS, and Windows
cross:
	cd $(CLI_DIR) && GOOS=linux   GOARCH=amd64 $(GO) build -o ../$(BUILD_DIR)/$(CLI_BINARY)-linux-amd64   .
	cd $(CLI_DIR) && GOOS=darwin  GOARCH=amd64 $(GO) build -o ../$(BUILD_DIR)/$(CLI_BINARY)-darwin-amd64  .
	cd $(CLI_DIR) && GOOS=darwin  GOARCH=arm64 $(GO) build -o ../$(BUILD_DIR)/$(CLI_BINARY)-darwin-arm64  .
	cd $(CLI_DIR) && GOOS=windows GOARCH=amd64 $(GO) build -o ../$(BUILD_DIR)/$(CLI_BINARY)-windows-amd64.exe .
	cd $(API_DIR) && GOOS=linux   GOARCH=amd64 $(GO) build -o ../$(BUILD_DIR)/$(API_BINARY)-linux-amd64   .
	cd $(API_DIR) && GOOS=darwin  GOARCH=amd64 $(GO) build -o ../$(BUILD_DIR)/$(API_BINARY)-darwin-amd64  .
	cd $(API_DIR) && GOOS=darwin  GOARCH=arm64 $(GO) build -o ../$(BUILD_DIR)/$(API_BINARY)-darwin-arm64  .
	cd $(API_DIR) && GOOS=windows GOARCH=amd64 $(GO) build -o ../$(BUILD_DIR)/$(API_BINARY)-windows-amd64.exe .

## help: Show this help
help:
	@grep -E '^##' Makefile | sed 's/## //'
