# Makefile for breakthru proxy

# Application details
APP_NAME := breakthru
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date +%Y-%m-%d_%H:%M:%S)
LDFLAGS := -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

# Build directories
BUILD_DIR := build
BIN_DIR := $(BUILD_DIR)/bin

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt

# Default target
.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: all
all: clean test build ## Clean, test, and build for all platforms

.PHONY: build
build: build-darwin-amd64 build-darwin-arm64 build-windows-amd64 build-windows-arm64 build-linux-amd64 build-linux-arm64 ## Build for all platforms

.PHONY: build-darwin-amd64
build-darwin-amd64: ## Build for macOS (Intel)
	@echo "Building for macOS AMD64..."
	@mkdir -p $(BIN_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-darwin-amd64 ./cmd/$(APP_NAME)

.PHONY: build-darwin-arm64
build-darwin-arm64: ## Build for macOS (Apple Silicon)
	@echo "Building for macOS ARM64..."
	@mkdir -p $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-darwin-arm64 ./cmd/$(APP_NAME)

.PHONY: build-windows-amd64
build-windows-amd64: ## Build for Windows (x64)
	@echo "Building for Windows AMD64..."
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/$(APP_NAME)

.PHONY: build-windows-arm64
build-windows-arm64: ## Build for Windows (ARM64)
	@echo "Building for Windows ARM64..."
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=arm64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-windows-arm64.exe ./cmd/$(APP_NAME)

.PHONY: build-linux-amd64
build-linux-amd64: ## Build for Linux (x64)
	@echo "Building for Linux AMD64..."
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-linux-amd64 ./cmd/$(APP_NAME)

.PHONY: build-linux-arm64
build-linux-arm64: ## Build for Linux (ARM64)
	@echo "Building for Linux ARM64..."
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-linux-arm64 ./cmd/$(APP_NAME)

.PHONY: build-local
build-local: ## Build for local architecture
	@echo "Building for local architecture..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME) ./cmd/$(APP_NAME)

.PHONY: run
run: build-local ## Build and run locally
	@echo "Running $(APP_NAME)..."
	$(BIN_DIR)/$(APP_NAME) -verbose

.PHONY: test
test: ## Run tests
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: test-short
test-short: ## Run short tests
	@echo "Running short tests..."
	$(GOTEST) -v -short ./...

.PHONY: coverage
coverage: test ## Run tests and show coverage
	@echo "Generating coverage report..."
	@go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: fmt
fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) -l -w .

.PHONY: lint
lint: ## Run linter
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run

.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.txt coverage.html
	$(GOCLEAN)

.PHONY: install
install: build-local ## Install to system
	@echo "Installing $(APP_NAME)..."
	@cp $(BIN_DIR)/$(APP_NAME) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(APP_NAME)"

.PHONY: uninstall
uninstall: ## Uninstall from system
	@echo "Uninstalling $(APP_NAME)..."
	@rm -f /usr/local/bin/$(APP_NAME)
	@echo "Uninstalled from /usr/local/bin/$(APP_NAME)"

.PHONY: release
release: clean test build ## Create release artifacts
	@echo "Creating release artifacts..."
	@mkdir -p $(BUILD_DIR)/release
	@for file in $(BIN_DIR)/*; do \
		base=$$(basename $$file); \
		cp $$file $(BUILD_DIR)/release/; \
		cd $(BUILD_DIR)/release && tar -czf $$base.tar.gz $$base && rm $$base; \
	done
	@echo "Release artifacts created in $(BUILD_DIR)/release/"

.PHONY: version
version: ## Show version
	@echo "$(APP_NAME) version: $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"