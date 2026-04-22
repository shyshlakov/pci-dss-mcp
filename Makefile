.PHONY: build test lint vet clean run build-fixture test-fixture scan-fixture \
        tools fmt-check check ci validate-server-json

BINARY := pci-dss-mcp
MODULE := github.com/shyshlakov/pci-dss-mcp
FIXTURE_DIR := testdata/vulnerable-payment-service

GOLANGCI_LINT_VERSION := v2.1.6
GOLANGCI_LINT_PKG := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK_PKG := golang.org/x/vuln/cmd/govulncheck@latest
GOBIN := $(shell go env GOPATH)/bin

build:
	go build -o $(BINARY) .

test:
	go test ./... -count=1 -race

lint: tools
	$(GOBIN)/golangci-lint run --timeout=5m

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

run: build
	./$(BINARY)

build-fixture:
	cd $(FIXTURE_DIR) && go build ./...

test-fixture:
	go test -run TestVulnerablePaymentServiceFixture ./scanner/reportscanner/... -count=1
	cd $(FIXTURE_DIR) && go test ./... -count=1

scan-fixture: build
	./$(BINARY) generate_compliance_report $(FIXTURE_DIR)

# tools installs the dev tools required by `check` if they are not already
# on PATH. Idempotent: a warm cache makes this a no-op after the first run.
tools:
	@command -v $(GOBIN)/golangci-lint >/dev/null 2>&1 || { \
		echo "installing golangci-lint $(GOLANGCI_LINT_VERSION)..."; \
		go install $(GOLANGCI_LINT_PKG); \
	}
	@command -v $(GOBIN)/govulncheck >/dev/null 2>&1 || { \
		echo "installing govulncheck..."; \
		go install $(GOVULNCHECK_PKG); \
	}

# fmt-check fails if any tracked Go file is not gofmt canonical. testdata/
# and planning/ are excluded since they hold synthetic fixtures and local
# notes that are not part of the shipped module.
fmt-check:
	@out=$$(gofmt -s -l . 2>/dev/null | grep -v '^testdata/' | grep -v '^\.planning/' || true); \
	if [ -n "$$out" ]; then \
		echo "gofmt: the following files need formatting (run: gofmt -s -w .):"; \
		echo "$$out"; \
		exit 1; \
	fi

# check runs every pre-push verification step in the same order the CI
# workflows do: gofmt, vet, golangci-lint, tests with -race, golden fixture
# regression, build, and govulncheck. Any failure aborts the target so
# contributors never push code that will turn a badge red.
check: tools fmt-check vet lint test test-fixture build
	$(GOBIN)/govulncheck ./...
	@echo ""
	@echo "All checks passed. Safe to push."

# ci is an alias for check. Use from local development when you want to
# mirror exactly what the CI workflows run.
ci: check

MCP_SCHEMA_URL := https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json

validate-server-json:
	@test -f server.json || { echo "server.json missing at repo root"; exit 1; }
	@command -v npx >/dev/null 2>&1 || { echo "npx required (install Node.js 18+)"; exit 1; }
	@command -v curl >/dev/null 2>&1 || { echo "curl required"; exit 1; }
	@tmpdir=$$(mktemp -d) && \
		curl -sSLf "$(MCP_SCHEMA_URL)" -o "$$tmpdir/server.schema.json" && \
		npx --yes ajv-cli@^5 validate --spec=draft7 --strict=false -s "$$tmpdir/server.schema.json" -d server.json && \
		rm -rf "$$tmpdir"
	@echo "server.json: valid"
