.PHONY: build deb offline-bundle test test-integration lint check-linux check-version-docs verify verify. shellcheck-sh shellcheck-deb test-env-file test-smoke-env test-diagnostics-env test-root-env test-management-listen test-package-restart test-package-restart-e2e test-release-verify test-release-unpack test-offline-bundle test-backup-rotate test-backup-restore-workflow test-backup-restore-e2e test-body-policy-e2e vuln ci install-help dev-up clean clean-artifacts golden-update

DIST=dist
# Keep in sync with .github/workflows/ci.yml. Release tarball: .github/workflows/release.yml.
GOLANGCI_LINT_VER ?= v2.15.0
GOVULNCHECK_VER ?= v1.9.0
# go run pkg@version otherwise builds the tool with the tool's own go line.
# golangci-lint refuses to lint a module newer than the Go that built it.
GO_TOOLCHAIN := go$(shell awk '/^go /{print $$2; exit}' go.mod)
# Debian package builder. Keep in sync with .github/workflows/release.yml.
NFPM_VER ?= v2.41.1
EASY_WAF_VERSION ?= $(shell head -1 VERSION | tr -d '[:space:]')
# Release artifacts are named with the Debian architecture. Host default keeps
# `make build` native; the release workflow sets this to amd64 and to arm64.
EASY_WAF_ARCH ?= $(shell go env GOARCH 2>/dev/null || echo amd64)
# dpkg sorts 1.7.0~rc.1 before 1.7.0, but reads 1.7.0-rc.1 as a later revision of it,
# so a final release could not replace a release candidate.
EASY_WAF_DEB_VERSION ?= $(subst -,~,$(EASY_WAF_VERSION))

# One-command dev database. Prints the DATABASE_URL the tests and the API expect.
# Requires Docker Compose v2. Does not install HAProxy, nftables, or the appliance.
dev-up:
	docker compose up -d --wait
	@echo "export DATABASE_URL='postgres://easywaf:easywaf@127.0.0.1:5432/easywaf?sslmode=disable'"

install-help:
	@echo "Production install (Ubuntu 24.04 LTS, as root) — plug-and-play:"
	@echo "  sudo bash scripts/install.sh"
	@echo "  (HAProxy stack + local PostgreSQL by default, DB user/db, start api+acmed)"
	@echo "  External DB only: EASY_WAF_INSTALL_POSTGRES=0"
	@echo "  Minimal OS packages: EASY_WAF_INSTALL_OS_PACKAGES=0"
	@echo "See docs/QUICKSTART.md"

build:
	@mkdir -p $(DIST)
	# If dist/* is root-owned (e.g. after sudo install), fix: sudo chown -R $$(id -u):$$(id -g) $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(EASY_WAF_ARCH) go build -o $(DIST)/easy-waf-api ./cmd/easy-waf-api
	CGO_ENABLED=0 GOOS=linux GOARCH=$(EASY_WAF_ARCH) go build -o $(DIST)/easy-waf-acmed ./cmd/easy-waf-acmed
	CGO_ENABLED=0 GOOS=linux GOARCH=$(EASY_WAF_ARCH) go build -o $(DIST)/easy-wafd ./cmd/easy-wafd
	CGO_ENABLED=0 GOOS=linux GOARCH=$(EASY_WAF_ARCH) go build -o $(DIST)/easy-waf-admin ./cmd/easy-waf-admin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(EASY_WAF_ARCH) go build -o $(DIST)/easy-waf-hostd ./cmd/easy-waf-hostd

# Debian package — the primary way the appliance is installed and upgraded.
# Why: docs/adr/0001-packaging-and-installer.md
deb: build
	@mkdir -p $(DIST)
	@if command -v nfpm >/dev/null 2>&1; then \
		EASY_WAF_VERSION=$(EASY_WAF_DEB_VERSION) EASY_WAF_ARCH=$(EASY_WAF_ARCH) nfpm package --config packaging/nfpm.yaml --packager deb --target $(DIST)/easy-waf_$(EASY_WAF_VERSION)_$(EASY_WAF_ARCH).deb; \
	else \
		echo >&2 "nfpm not in PATH; using go run $(NFPM_VER) (install: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VER))"; \
		EASY_WAF_VERSION=$(EASY_WAF_DEB_VERSION) EASY_WAF_ARCH=$(EASY_WAF_ARCH) go run github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VER) package --config packaging/nfpm.yaml --packager deb --target $(DIST)/easy-waf_$(EASY_WAF_VERSION)_$(EASY_WAF_ARCH).deb; \
	fi
	@echo "Built $(DIST)/easy-waf_$(EASY_WAF_VERSION)_$(EASY_WAF_ARCH).deb"

# Native-architecture Ubuntu 24.04 ISO containing Easy WAF and its complete APT
# dependency closure. See docs/OFFLINE_BUNDLE.md.
offline-bundle: deb
	bash scripts/build-offline-bundle.sh

check-linux:
	bash scripts/check-linux-artifacts.sh

check-version-docs:
	bash scripts/check-version-docs.sh

# Shell LF + no committed .exe/.dll + gofmt (when go present); shellcheck on install scripts when installed
shellcheck-sh:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -x -P SCRIPTDIR scripts/test-haproxy-working-dir.sh scripts/testdata/haproxy-working-dir.sh && \
		shellcheck -x -P SCRIPTDIR scripts/test-installer-conffiles.sh scripts/testdata/installer-conffiles.sh && \
		shellcheck -x -P SCRIPTDIR scripts/test-installer-crowdsec-keys.sh scripts/test-installer-units.sh && \
		shellcheck -x -P SCRIPTDIR scripts/test-db-password.sh && \
		shellcheck -x -P SCRIPTDIR scripts/test-installer-postgres.sh && \
		shellcheck scripts/test-upgrade-staging.sh && \
		shellcheck -x -P SCRIPTDIR scripts/test-backup-publication.sh scripts/testdata/backup-publication.sh scripts/testdata/restore-permissions.sh scripts/testdata/restore-lock.sh && \
		cd scripts && shellcheck -x install.sh upgrade.sh install-interactive.sh build-offline-bundle.sh install-offline-bundle.sh download-release.sh smoke-appliance.sh diagnostics.sh test-backup-restore.sh test-backup-restore-workflow.sh test-env-file.sh test-smoke-env.sh test-diagnostics-env.sh test-root-env.sh test-management-listen.sh test-package-restart.sh test-package-restart-e2e.sh testdata/package-restart/boot.sh test-release-verify.sh release-notes.sh test-release-notes.sh test-release-unpack.sh test-offline-bundle.sh backup.sh test-backup-rotate.sh restore.sh update-geoip-db.sh fix-haproxy-easy-waf-dropin.sh fix-fail2ban-api-access.sh fix-nftables-edge.sh test-body-policy-e2e.sh test-body-policy-e2e-output.sh test-crowdsec-e2e.sh test-crowdsec-e2e-cleanup.sh lib/env-file.sh lib/backup-rotate.sh lib/fail2ban-access.sh lib/management-listen.sh lib/release-verify.sh lib/release-unpack.sh lib/github-repo.sh lib/selinux-easy-waf-haproxy.sh lib/nftables-easy-waf.sh lib/db-password.sh host/privileged.sh; \
	else \
		echo "[easy-waf] verify: shellcheck not in PATH — skip (e.g. apt install shellcheck)"; \
	fi

# Maintainer scripts run as root at install time — same review standard as the
# broker, so they are linted like the rest. POSIX sh, not bash.
shellcheck-deb:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck packaging/deb/preinst packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm; \
	else \
		echo "[easy-waf] verify: shellcheck not in PATH — skip packaging/deb"; \
	fi

test-env-file:
	bash scripts/test-env-file.sh

test-smoke-env:
	bash scripts/test-smoke-env.sh

test-diagnostics-env:
	bash scripts/test-diagnostics-env.sh

test-root-env:
	bash scripts/test-root-env.sh
	bash scripts/test-db-password.sh
	bash scripts/test-installer-postgres.sh

test-management-listen:
	bash scripts/test-management-listen.sh

test-package-restart:
	bash scripts/test-package-restart.sh

# Real systemd + offline APT/dpkg in a disposable Ubuntu OS container.
test-package-restart-e2e:
	bash scripts/test-package-restart-e2e.sh

.PHONY: test-release-notes
test-release-notes:
	bash scripts/test-release-notes.sh

test-release-verify:
	bash scripts/test-release-verify.sh

test-release-unpack:
	bash scripts/test-release-unpack.sh
	bash scripts/test-upgrade-staging.sh

test-offline-bundle:
	bash scripts/test-offline-bundle.sh

test-backup-rotate:
	bash scripts/test-backup-rotate.sh

.PHONY: test-backup-publication
# Offline private Linux config/state, fake database/service leaf commands.
test-backup-publication:
	bash scripts/test-backup-publication.sh

.PHONY: test-installer-conffiles
# Offline real APT/dpkg with dummy conffiles and private package state.
test-installer-conffiles:
	bash scripts/test-installer-conffiles.sh

.PHONY: test-haproxy-working-dir
test-haproxy-working-dir:
	bash scripts/test-haproxy-working-dir.sh

.PHONY: test-body-policy-e2e-output
test-body-policy-e2e-output:
	bash scripts/test-body-policy-e2e-output.sh

.PHONY: test-crowdsec-e2e-cleanup
test-crowdsec-e2e-cleanup:
	bash scripts/test-crowdsec-e2e-cleanup.sh

# Mocked workflow regression tests; safe without an appliance or root.
test-backup-restore-workflow:
	bash scripts/test-backup-restore-workflow.sh

# Post-upgrade checks against a LIVE appliance: real PostgreSQL, real HAProxy
# reload, installed systemd units. Not part of `verify` — needs a host, not CI.
smoke-appliance:
	bash scripts/smoke-appliance.sh

.PHONY: test-installer-crowdsec-keys
test-installer-crowdsec-keys:
	bash scripts/test-installer-crowdsec-keys.sh

.PHONY: test-installer-units
test-installer-units:
	bash scripts/test-installer-units.sh

verify: check-linux check-version-docs shellcheck-sh shellcheck-deb test-env-file test-smoke-env test-diagnostics-env test-root-env test-management-listen test-package-restart test-release-verify test-release-notes test-release-unpack test-offline-bundle test-backup-rotate test-backup-restore-workflow test-body-policy-e2e-output test-crowdsec-e2e-cleanup test-installer-crowdsec-keys test-installer-units

# Punctuation after "verify" in docs/shell often becomes `make verify.` — forward to verify.
verify.:
	@$(MAKE) verify

# Exits 0 with SKIP unless RUN_BACKUP_RESTORE_E2E=1 and root (destructive on real appliance).
test-backup-restore-e2e:
	bash scripts/test-backup-restore.sh

# Integration packages share DATABASE_URL; match CI's package serialization.
test:
	go test -p 1 ./...

# The PostgreSQL tests CI runs. Uses DATABASE_URL when it is set; otherwise
# starts the Compose database from `make dev-up` and uses that.
test-integration:
	@set -e; \
	if [ -n "$$DATABASE_URL" ]; then \
	  dsn="$$DATABASE_URL"; \
	else \
	  $(MAKE) dev-up; \
	  dsn='postgres://easywaf:easywaf@127.0.0.1:5432/easywaf?sslmode=disable'; \
	fi; \
	DATABASE_URL="$$dsn" go test -p 1 -count=1 \
	  ./internal/api/ ./internal/auth/ ./internal/store/ ./internal/engine/ ./cmd/easy-waf-acmed/ ./internal/admin/

# Regenerate internal/haproxy/testdata/golden/*.cfg and companion .crt-list.txt from Render().
golden-update:
	UPDATE_GOLDEN=1 go test ./internal/haproxy/... -run Golden -count=1

test-body-policy-e2e:
	bash scripts/test-body-policy-e2e.sh

vuln:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VER) ./...

lint:
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./... --timeout=5m; \
	else \
		echo >&2 "golangci-lint not in PATH; using go run $(GOLANGCI_LINT_VER) (optional install: https://golangci-lint.run/welcome/install/)"; \
		GOTOOLCHAIN=$(GO_TOOLCHAIN) go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VER) run ./... --timeout=5m; \
	fi

# Same gates as .github/workflows/ci.yml
ci: lint test verify

clean: clean-artifacts

clean-artifacts:
	bash scripts/clean-artifacts.sh
