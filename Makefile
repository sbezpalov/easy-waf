.PHONY: build test lint check-linux verify ci install-help clean-artifacts golden-update

DIST=dist

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

# Shell LF + no committed .exe/.dll + gofmt (when go present)
verify: check-linux

test:
	go test ./...

# Regenerate internal/haproxy/testdata/golden/*.cfg and companion .crt-list.txt from Render().
golden-update:
	UPDATE_GOLDEN=1 go test ./internal/haproxy/... -run Golden -count=1

lint:
	go vet ./...
	golangci-lint run ./...

# Same gates as .github/workflows/ci.yml (install golangci-lint: https://golangci-lint.run/welcome/install/)
ci: lint test verify

clean-artifacts:
	bash scripts/clean-artifacts.sh
