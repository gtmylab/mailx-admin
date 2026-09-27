.PHONY: build build-static build-linux build-windows release test lint clean install version

BINARY := mailx-admin

# Release artifact name. This is a contract with Mailx-Installer, which downloads
# .../releases/latest/download/mailx-admin-linux-amd64 from GitHub releases;
# internal/version/version_test.go asserts the two stay in sync.
LINUX_ARTIFACT := mailx-admin-linux-amd64

# Version resolution order:
#   1. an explicit override: make VERSION=1.2.0 COMMIT=abc1234 release
#   2. git describe (a git checkout)
#   3. the VERSION file (release tarball / non-git working copy)
#   4. "dev"
# The values are stamped into internal/version by the linker, so the same
# version is reported by --version on every platform (Linux and Windows) and by
# the running server's startup log line and /metrics.
GIT_VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null)
FILE_VERSION := $(shell cat VERSION 2>/dev/null | tr -d '[:space:]')
VERSION ?= $(if $(GIT_VERSION),$(GIT_VERSION),$(if $(FILE_VERSION),$(FILE_VERSION),dev))
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X github.com/gtmylab/mailx-admin/internal/version.Version=$(VERSION) \
           -X github.com/gtmylab/mailx-admin/internal/version.Commit=$(COMMIT) \
           -X github.com/gtmylab/mailx-admin/internal/version.Date=$(DATE)

# Native build. On a Linux server this is the production binary.
build:
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/mailx-admin
	@echo "built bin/$(BINARY) as $(VERSION) (commit $(COMMIT), built $(DATE))"

# Static smoke-test build: no cgo, therefore no SQLite driver. It cannot open a
# sqlite database - use "build" or "build-linux" for anything real.
build-static:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS) -extldflags -static" -o bin/$(BINARY)-static ./cmd/mailx-admin

# Windows build, for developers running the panel locally. It is stamped with
# the very same LDFLAGS, so "mailx-admin.exe --version" reports the same
# version/commit as the Linux release built from the same checkout. Note: cgo
# is off (no gcc in the usual Windows dev environment), so this binary carries
# the non-cgo SQLite stub - use it for UI work, not against a live database.
build-windows:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY).exe ./cmd/mailx-admin
	@bin/$(BINARY).exe --version

# Linux release artifact (the file the installer downloads). CGO is required by
# mattn/go-sqlite3 and cgo cannot be cross-compiled without a cross toolchain,
# so this target must run on Linux: locally, in CI, or in Docker.
build-linux:
	@if [ "$$(uname -s)" != "Linux" ]; then \
		echo "build-linux needs Linux: cgo (go-sqlite3) cannot be cross-compiled from $$(uname -s)."; \
		echo "Build on the server or on Linux CI, then copy bin/$(LINUX_ARTIFACT) over."; \
		exit 1; \
	fi
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(LINUX_ARTIFACT) ./cmd/mailx-admin
	@echo "release artifact: bin/$(LINUX_ARTIFACT)"
	@./bin/$(LINUX_ARTIFACT) --version

# Release artifact set: the version-stamped Linux binary plus its checksum.
# GitHub Actions publishes exactly these two files (see
# .github/workflows/release.yml), and Mailx-Installer downloads the first one
# from releases/latest/download/mailx-admin-linux-amd64.
release: build-linux
	@cd bin && sha256sum $(LINUX_ARTIFACT) > SHA256SUMS
	@echo "checksums:" && cat bin/SHA256SUMS

test:
	go test ./... -race -count=1

lint:
	gofmt -l -w .
	go vet ./...

# Show what the next build will stamp into internal/version.
version:
	@echo "$(VERSION) (commit $(COMMIT), built $(DATE))"

install: build
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

clean:
	rm -rf bin/