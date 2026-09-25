# Tempora build, test and operations targets.
SHELL        := /bin/bash
.DEFAULT_GOAL := help

GO           ?= go
PKG          := github.com/mohammedaljohaniit1-max/test-pro
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS      := -s -w -X $(PKG)/internal/server.Version=$(VERSION)
BIN          := bin
IMAGE        ?= tempora
EVENTS       ?= 1000000
PRODUCERS    ?= $(shell nproc 2>/dev/null || echo 2)
FUZZTIME     ?= 30s

.PHONY: help build run run-dev check fmt fmt-check vet lint test test-race test-short cover \
        bench bench-e2e bench-json fuzz profile docker docker-test compose-up compose-down \
        compose-load clean ci

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

build: ## Build static binaries into ./bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/tempora ./cmd/tempora
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w' -o $(BIN)/tempora-bench ./cmd/tempora-bench

run: build ## Run the server with the bundled rules and a local WAL
	$(BIN)/tempora -rules rules -wal-dir data/wal -log-format text

run-dev: build ## Run without WAL, verbose logs, pprof enabled
	$(BIN)/tempora -rules rules -log-level debug -log-format text -pprof

check: build ## Compile and validate every rule file
	$(BIN)/tempora check rules

fmt: ## Format all Go sources
	gofmt -s -w cmd internal

fmt-check: ## Fail if any source is not gofmt-clean
	@out=$$(gofmt -s -l cmd internal); if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

vet: ## go vet
	$(GO) vet ./...

lint: fmt-check vet ## Formatting + vet (+ staticcheck when installed)
	@command -v staticcheck >/dev/null && staticcheck ./... || echo "staticcheck not installed; skipped"

test: ## Unit + integration tests
	$(GO) test -count=1 ./...

test-short: ## Fast subset
	$(GO) test -short -count=1 ./...

test-race: ## Tests under the race detector (requires cgo)
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

cover: ## Coverage report (coverage.html)
	$(GO) test -count=1 -covermode=atomic -coverprofile=coverage.out ./internal/...
	$(GO) tool cover -func=coverage.out | tail -1
	$(GO) tool cover -html=coverage.out -o coverage.html

bench: ## Micro-benchmarks (hot-path primitives)
	$(GO) test -run '^$$' -bench . -benchmem ./internal/...

bench-e2e: build ## End-to-end in-process engine benchmark
	$(BIN)/tempora-bench -events $(EVENTS) -producers $(PRODUCERS)

bench-json: build ## End-to-end benchmark, JSON output
	$(BIN)/tempora-bench -events $(EVENTS) -producers $(PRODUCERS) -json

fuzz: ## Fuzz the binary codec and rule compiler
	$(GO) test -run '^$$' -fuzz FuzzDecodeBinary -fuzztime $(FUZZTIME) ./internal/event
	$(GO) test -run '^$$' -fuzz FuzzCompile -fuzztime $(FUZZTIME) ./internal/rules

profile: build ## CPU + heap profile of the e2e benchmark, then open the top view
	$(BIN)/tempora-bench -events $(EVENTS) -producers $(PRODUCERS) -cpuprofile cpu.prof -memprofile mem.prof
	$(GO) tool pprof -top -nodecount=25 $(BIN)/tempora-bench cpu.prof

docker: ## Build the runtime image
	docker build --target runtime --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

docker-test: ## Run vet + tests inside the build image
	docker build --target test .

compose-up: ## Start tempora + prometheus
	TEMPORA_VERSION=$(VERSION) docker compose up -d --build

compose-load: ## Start the TCP load generator against the compose stack
	TEMPORA_VERSION=$(VERSION) docker compose --profile load up -d loadgen

compose-down: ## Stop the stack (keeps volumes)
	docker compose --profile load down

ci: lint test-race check ## Everything CI runs

clean: ## Remove build and profiling artefacts
	rm -rf $(BIN) coverage.out coverage.html *.prof
