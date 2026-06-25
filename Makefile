# splitdnsd build/test/lint gates (S04). Hermetic: builds from the vendored
# module tree with CGO disabled (single static binary, §1).
SHELL := /bin/bash
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS := -mod=vendor
LDFLAGS := -X main.version=$(VERSION)

# Version-forwarding (design §11.3): build with the HIGHEST apt-installed Go.
# select-go.sh prints the chosen toolchain path; override with GO=/path.
GO ?= $(shell ./scripts/select-go.sh)

# Hermetic builds: use ONLY an apt-installed Go toolchain (auto-updated via apt),
# never a network-downloaded one. CGO off => single static binary.
export GOTOOLCHAIN := local
export CGO_ENABLED := 0

.PHONY: all build test test-cover test-fuzz-short test-netns test-chaos test-e2e-cover golden-update vet lint vuln pristine install-hooks ci tidy vendor clean

all: vet test build

build:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/splitdnsd ./cmd/splitdnsd

# test runs the full suite under the race detector (the concurrency-heavy control
# plane is the whole point). The race detector needs cgo, so override the global
# CGO_ENABLED=0 here only — production binaries stay static (see build/build-deb).
test:
	CGO_ENABLED=1 $(GO) test -race $(GOFLAGS) ./...

# test-cover emits a coverage profile + summary (no race; faster signal).
test-cover:
	$(GO) test $(GOFLAGS) -coverprofile=cover.out -covermode=atomic ./...
	$(GO) tool cover -func=cover.out | tail -1

# test-fuzz-short runs every FuzzXxx target for a bounded time (CI gate, S31).
test-fuzz-short:
	./scripts/fuzz-short.sh

# test-netns runs the network-namespace e2e package (real components inside an
# isolated, egress-blocked netns, S24). Skips cleanly where userns is unavailable.
test-netns:
	$(GO) test $(GOFLAGS) -v ./internal/netnse2e/

# test-chaos runs the adversarial reliability suite (DoT-hang, cold-start-all-down,
# flood + goroutine-leak check, S29).
test-chaos:
	CGO_ENABLED=1 $(GO) test -race $(GOFLAGS) -v ./internal/chaos/

# golden-update regenerates the legacy-parity golden expectations from current
# resolver output (S26/S27). REVIEW the diff before committing.
golden-update:
	SPLITDNS_GOLDEN_UPDATE=1 $(GO) test $(GOFLAGS) ./internal/golden/

# test-e2e-cover builds the real binary with coverage, drives it against in-process
# mocks, and asserts the load-bearing targets are exercised end-to-end (S32).
test-e2e-cover:
	$(GO) test $(GOFLAGS) -v ./internal/bincover/

vet:
	$(GO) vet $(GOFLAGS) ./...

# Requires golangci-lint on PATH; enforces the anti-hang context gate (.golangci.yml).
lint:
	golangci-lint run

# vuln is a BLOCKING gate: govulncheck fails on any known-vulnerable symbol actually
# reachable from our code. Requires govulncheck on PATH (CI installs it; locally:
# go install golang.org/x/vuln/cmd/govulncheck@latest).
vuln:
	govulncheck ./...

# pristine fails if any site-private string leaked into a public/packageable file
# (denylist in local/private-patterns.txt; skipped if that file is absent).
pristine:
	./scripts/check-pristine.sh

# install-hooks points git at .githooks so the pre-commit pristine gate runs locally.
install-hooks:
	git config core.hooksPath .githooks
	@echo "installed: .githooks (pre-commit runs scripts/check-pristine.sh)"

# ci runs the gates an automated pipeline enforces, cheap-to-expensive.
ci: pristine vet vuln test test-fuzz-short

tidy:
	$(GO) mod tidy

vendor:
	$(GO) mod tidy && $(GO) mod vendor

clean:
	rm -rf bin
