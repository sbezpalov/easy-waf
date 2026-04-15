# 🚀 Project Prompt — Easy Home WAF (HAProxy + CrowdSec)

**Состояние реализации относительно этого файла:** [docs/PROMPTS_ALIGNMENT.md](docs/PROMPTS_ALIGNMENT.md) — таблица **AC-01 … AC-10** (ТЗ v1.1) в §9; релизная метка в корневом **`VERSION`** (текущий MVP: **1.0.0-rc1**).

## 1. Context

We are building a **self-hosted WAF / secure reverse proxy appliance** for **smart home / homelab users**.

Typical use cases:

* Publishing Home Assistant, Frigate, Nextcloud, Node-RED, Grafana, Vaultwarden, etc.
* Running behind NAT with port forwarding (80/443 only)
* Need secure HTTPS, basic WAF, bot protection, and visibility

Environment:

* OS: AlmaLinux 10
* Reverse proxy: HAProxy 3.x
* Security: CrowdSec + HAProxy SPOA/SPOE bouncer + Fail2Ban
* TLS: ACME / Let's Encrypt
* Management: local Web UI (no cloud dependency)

This is NOT enterprise WAF — this is **practical, reliable, secure-by-default home gateway**.

---

## 2. Goals

Build an **installable, production-ready MVP** that:

### Core

* Publishes local services via domains (e.g. `ha.example.com → 192.168.1.50:8123`)
* Terminates TLS with HAProxy
* Automatically provisions and renews certificates (ACME)
* Supports WebSocket-based apps (Home Assistant, etc.)
* Uses HAProxy as the single entry point

### Security

* Rate limiting (stick-tables)
* Basic WAF rules (ACL-based)
* CrowdSec integration (log ingestion + decisions)
* HAProxy SPOE bouncer integration
* Fail2Ban for SSH and optional services
* Country filtering (GeoIP, cached)

### UX

* Local Web UI (LAN-only by default)
* Add/edit/remove applications
* Issue certificates
* View logs and blocked IPs
* Enable/disable security profiles
* Backup / restore config

### Observability

* Request statistics per app
* Blocked IPs / decisions
* Country distribution
* Certificate expiration tracking
* Backend health

---

## 3. Constraints

### Platform

* AlmaLinux 10 ONLY (first-class support)
* systemd-native
* firewalld-compatible
* SELinux must remain **Enforcing**

### HAProxy

* Must validate config before reload (`haproxy -c`)
* Must support:

  * SPOE (required)
  * WebSocket
  * SNI routing
  * HTTP→HTTPS redirect

### CrowdSec

* Must use **SPOA/SPOE bouncer (NOT legacy Lua)**
* Must validate LAPI connectivity
* Must expose decisions to UI

### Config Management

* NO manual editing of haproxy.cfg by users
* Must implement:

  * config generator
  * validation pipeline
  * atomic apply
  * rollback to last working config

### Security

* Least privilege (dedicated users)
* Proper file permissions
* Secrets not stored in plaintext where avoidable
* Input validation in UI/API
* No shell injection risks

### GeoIP

* Must support API-based GeoIP (e.g. ipinfo lite)
* Must implement caching layer
* Must be replaceable with local DB later

---

## 4. Non-Goals (for MVP)

Do NOT implement:

* Full OWASP CRS engine
* Kubernetes / cloud-native orchestration
* Multi-node clustering
* External SaaS dependencies

---

## 5. High-Level Architecture

### Components

* **Core Service (backend API)**

  * config storage
  * orchestration
  * ACME integration
  * HAProxy config rendering

* **HAProxy**

  * TLS termination
  * routing
  * ACL / rate limiting
  * SPOE integration

* **CrowdSec**

  * log ingestion
  * detection engine
  * decisions

* **SPOA Bouncer**

  * HAProxy ↔ CrowdSec bridge

* **Web UI**

  * frontend + backend API
  * local access only

* **ACME Manager**

  * certificate lifecycle
  * renewal scheduler

* **Metrics/Stats collector**

  * HAProxy stats
  * CrowdSec decisions

---

## 6. Repository Structure

Create:

```
/cmd
/internal
  /config
  /haproxy
  /acme
  /security
  /geo
  /crowdsec
  /stats
/web
  /frontend
  /backend
/templates
  haproxy.cfg.tmpl
  spoe.conf.tmpl
/configs
/scripts
  install.sh
  upgrade.sh
  backup.sh
  restore.sh
/docs
/examples
/tests
```

---

## 7. Core Features to Implement

### 7.1 App Publishing

* Domain → backend mapping
* Protocol (HTTP/HTTPS)
* WebSocket support
* Health checks
* Security profile selection

---

### 7.2 ACME

* HTTP-01 support (required)
* DNS-01 pluggable architecture (future)
* Auto-renew
* HAProxy reload hook
* Certificate expiration tracking

---

### 7.3 HAProxy Config Engine

* Template-based generation
* Validation before apply
* Versioned backups
* Rollback support

---

### 7.4 Security Profiles

Implement:

* `balanced`
* `strict`
* `trusted-lan`
* `public-app`
* `home-assistant`

Each defines:

* rate limits
* headers
* ACL rules
* geo defaults

---

### 7.5 CrowdSec Integration

* Detect installation
* Register bouncer
* Validate LAPI
* Show decisions in UI
* Allow unblock / whitelist

---

### 7.6 GeoIP

* API-based lookup (ipinfo lite or equivalent)
* caching layer
* ACL integration in HAProxy
* allow/deny country lists

---

### 7.7 UI

Pages:

* Dashboard
* Applications
* Certificates
* Security
* Logs
* Blocked IPs
* Settings
* Backup/Restore

Must include:

* validation before apply
* error feedback
* safe apply

---

### 7.8 Statistics

* requests per app
* blocked requests
* top IPs
* country distribution
* backend health

---

## 8. Lessons Learned (CRITICAL)

Must respect:

* SPOE config syntax is strict
* SPOE engine name MUST match config section
* HAProxy variables require scope:

  * `txn.variable_name`
* path fetch = `path`, NOT `req.path`
* Always validate config before reload
* Always support rollback
* HA apps require WebSocket support
* Certificates must be HAProxy-compatible PEM bundles
* SELinux must not be broken
* Avoid reliance on unstable repo structures (CrowdSec ecosystem evolves)

---

## 9. Acceptance Criteria (MVP)

System is considered DONE when:

* User installs via `install.sh`
* Adds an app via UI
* Gets valid HTTPS cert automatically
* Can access app externally
* CrowdSec blocks malicious traffic
* HAProxy returns 403 for banned IP
* Config changes apply without downtime
* Broken config triggers rollback
* UI shows:

  * apps
  * cert status
  * blocked IPs
* System survives reboot
* SELinux remains enabled

---

## 10. First Tasks (Start Here)

### Step 1

Design:

* architecture diagram
* config model
* data structures

### Step 2

Create repository skeleton

### Step 3

Implement:

* basic backend service
* config storage
* HAProxy config generator

### Step 4

Implement:

* ACME issuance (HTTP-01)
* cert storage

### Step 5

Implement:

* HAProxy reload pipeline
* validation + rollback

### Step 6

Integrate:

* CrowdSec detection
* SPOE config generation

### Step 7

Build:

* minimal UI (CRUD apps)

### Step 8

Add:

* security profiles
* stats
* logs

---

## 11. Engineering Approach

* Work iteratively
* Do not hand-wave — produce real code
* Keep modules clean and testable
* Prefer clarity over premature optimization
* Validate everything before applying
* Always consider failure scenarios

---

## 12. Deliverables

You must produce:

* working codebase
* install scripts
* configs
* templates
* systemd units
* documentation
* example configs

Final result must be:
👉 clone → install → working WAF
