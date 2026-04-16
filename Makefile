.PHONY: build test lint check-linux verify verify. shellcheck-sh test-backup-restore-e2e ci install-help clean clean-artifacts golden-update

DIST=dist
# Keep in sync with .github/workflows/ci.yml. Release tarball: .github/workflows/release.yml.
GOLANGCI_LINT_VER ?= v1.62.2

install-help:
	@echo "Production install (Alma/RHEL or Debian/Ubuntu, as root) — plug-and-play:"
	@echo "  sudo bash scripts/install.sh"
	@echo "  (HAProxy stack + local PostgreSQL by default, DB user/db, start api+acmed)"
	@echo "  External DB only: EASY_WAF_INSTALL_POSTGRES=0"
	@echo "  Minimal OS packages: EASY_WAF_INSTALL_OS_PACKAGES=0"
	@echo "See docs/QUICKSTART.md"

build:
	@mkdir -p $(DIST)
	# If dist/* is root-owned (e.g. after sudo install), fix: sudo chown -R $$(id -u):$$(id -g) $(DIST)
	CGO_ENABLED=0 go build -o $(DIST)/easy-waf-api ./cmd/easy-waf-api
	CGO_ENABLED=0 go build -o $(DIST)/easy-waf-acmed ./cmd/easy-waf-acmed
	CGO_ENABLED=0 go build -o $(DIST)/easy-wafd ./cmd/easy-wafd
	CGO_ENABLED=0 go build -o $(DIST)/easy-waf-admin ./cmd/easy-waf-admin

check-linux:
	bash scripts/check-linux-artifacts.sh

# Shell LF + no committed .exe/.dll + gofmt (when go present); shellcheck on install scripts when installed
shellcheck-sh:
	@if command -v shellcheck >/dev/null 2>&1; then \
		cd scripts && shellcheck -x install.sh install-interactive.sh test-backup-restore.sh; \
	else \
		echo "[easy-waf] verify: shellcheck not in PATH — skip (e.g. dnf install epel-release 'ShellCheck' || apt install shellcheck)"; \
	fi

verify: check-linux shellcheck-sh

# Punctuation after "verify" in docs/shell often becomes `make verify.` — forward to verify.
verify.:
	@$(MAKE) verify

# Exits 0 with SKIP unless RUN_BACKUP_RESTORE_E2E=1 and root (destructive on real appliance).
test-backup-restore-e2e:
	bash scripts/test-backup-restore.sh

test:
	go test ./...

# Regenerate internal/haproxy/testdata/golden/*.cfg and companion .crt-list.txt from Render().
golden-update:
	UPDATE_GOLDEN=1 go test ./internal/haproxy/... -run Golden -count=1

lint:
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./... --timeout=5m; \
	else \
		echo >&2 "golangci-lint not in PATH; using go run $(GOLANGCI_LINT_VER) (optional install: https://golangci-lint.run/welcome/install/)"; \
		go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VER) run ./... --timeout=5m; \
	fi

# Same gates as .github/workflows/ci.yml
ci: lint test verify

clean: clean-artifacts

clean-artifacts:
	bash scripts/clean-artifacts.sh
