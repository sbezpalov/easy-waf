# REST API reference

The management API of `easy-waf-api`: the same API the built-in web UI uses.
Every route is registered in [`internal/api/server.go`](../internal/api/server.go)
and, for `/api/v1/host/*`, in [`internal/api/host_handlers.go`](../internal/api/host_handlers.go).
When this page and the code disagree, the code is right — please fix the page.

## Contents

- [Basics](#basics)
- [Authentication](#authentication)
- [Status and catalogue](#status-and-catalogue)
- [Applications](#applications)
- [Application security](#application-security)
- [Apply and revisions](#apply-and-revisions)
- [Certificates](#certificates)
- [Settings](#settings)
- [Statistics](#statistics)
- [Audit log](#audit-log)
- [Diagnostics](#diagnostics)
- [IP blocklist (IPBL)](#ip-blocklist-ipbl)
- [IP allowlist](#ip-allowlist)
- [Blocked user agents](#blocked-user-agents)
- [GeoIP](#geoip)
- [CrowdSec](#crowdsec)
- [Fail2Ban](#fail2ban)
- [Health and metrics](#health-and-metrics)
- [Host management](#host-management)

## Basics

**Base URL.** The API is served on the management listeners, not on the
HAProxy edge:

- HTTPS on **`EASY_WAF_LISTEN_HTTPS`** (default `0.0.0.0:8443`);
- plain HTTP on **`EASY_WAF_LISTEN_HTTP`** only if you enable it (off by default;
  loopback only unless `EASY_WAF_ALLOW_INSECURE_HTTP=1`).

Paths below are relative to that origin, e.g. `https://<appliance>:8443/api/v1/status`.
Request and response bodies are JSON unless stated otherwise.

**Every request passes, in order:** security headers → a 4 MiB request-body
cap → trusted-proxy client-IP resolution → the management source-address ACL →
the `X-Requested-With` check → for `/api/v1` (except the three public auth
routes) session authentication, the audit of mutating calls and the
password-change gate.

### Management ACL

Requests are accepted only from addresses in the `management_allowed_cidrs`
global setting (default: loopback, `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`). Others get **403**
`{"error":"management access denied for this source address"}`.
`/health` and `/health/ready` are exempt; `/metrics` is not.

The client address is the TCP peer. Only when the peer is in
`EASY_WAF_TRUSTED_PROXY_CIDRS` is the rightmost `X-Forwarded-For` value used
instead, so the proxy must overwrite that header rather than append to it.
Emergency bypass: `EASY_WAF_BYPASS_MGMT_ACL=1` (see [ADMIN-CLI.md](ADMIN-CLI.md#environment-bypass-lockout)).

### `X-Requested-With` (CSRF guard)

Every `POST`, `PUT`, `PATCH` and `DELETE` must carry
`X-Requested-With: XMLHttpRequest`; otherwise **403**
`{"error":"missing X-Requested-With header"}`. `GET`, `HEAD` and `OPTIONS` do
not need it. See [SECURITY.md](SECURITY.md#csrf-protection).

### Signing in and sessions

1. **First start:** with no operator account, `GET /api/v1/auth/status` reports
   that enrollment is required. Print the one-time secret on the appliance with
   `sudo easy-waf-admin print-enrollment` and create the account with
   `POST /api/v1/auth/enroll`. There is no default `admin/admin`.
2. **Sign in:** `POST /api/v1/auth/login` returns
   `{"token": "...", "must_change_password": false, "expires_in_seconds": 86400}`.
3. **Call the API** with `Authorization: Bearer <token>`. Tokens are HS256 JWTs
   valid for **24 hours**; they are never set as cookies.
4. **Sign out** with `POST /api/v1/auth/logout`: it bumps the account's session
   version, which revokes *every* token issued to that account, not only the
   one used.

A missing, invalid, expired or revoked token gets **401** `{"error":"unauthorized"}`.

**Password-change gate.** While an account still has to change its initial
password, every authenticated route except `GET /api/v1/auth/me` and
`POST /api/v1/auth/change-password` returns **403**
`{"error":"password_change_required","must_change_password":true}`.

**Automation token.** If `EASY_WAF_ADMIN_TOKEN` is set (at least 24
characters), that value is also accepted as a bearer token. It acts as the
principal `automation`, skips the password-change gate and is not revoked by
logout — rotate it by changing the environment and restarting the API. Prefer
a session token for anything interactive.

**Login rate limit.** `POST /auth/login`, `POST /auth/enroll` and
`POST /auth/change-password` share a per-IP limit: the 10th attempt within
5 minutes starts a **15-minute** lockout, during which they return **429**
with `Retry-After: <seconds>`. A successful attempt resets the counter for that
address.

### Errors

Errors are reported with an HTTP status code. The body is **not uniform**:

- the middleware above and many handlers return JSON `{"error": "<message>"}`;
- other handlers return the message as **`text/plain`** (Go's `http.Error`).

Rely on the status code and treat the body as a human-readable message. The
endpoint sections say which form a handler uses where it matters.

Common statuses: **400** malformed JSON or failed validation, **401** no valid
session, **403** ACL / `X-Requested-With` / password-change gate, **404**
unknown id, **413** body over 4 MiB, **422** HAProxy rejected a change (it has
been undone), **429** login lockout, **500** database or internal error,
**502/503** an upstream (CrowdSec LAPI, the host broker, PostgreSQL) is
unavailable.

### Audit

Every `POST`, `PUT`, `PATCH` and `DELETE` under `/api/v1` that passes
authentication is recorded in the audit log as `"<METHOD> <path>"` with its
HTTP status, a coarse category, the user and the source address — whether it
succeeded or not. Request bodies are never stored. Some handlers also record a
more specific action. Read the log with [`GET /api/v1/audit`](#get-apiv1audit).

### Response headers

All responses carry `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive
`Content-Security-Policy` and `Permissions-Policy`; HTTPS responses add
`Strict-Transport-Security: max-age=31536000; includeSubDomains`.

### Example

```bash
BASE=https://192.0.2.10:8443
TOKEN=$(curl -sk "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
  -d '{"username":"operator","password":"…"}' | jq -r .token)

curl -sk "$BASE/api/v1/applications" -H "Authorization: Bearer $TOKEN"

curl -sk -X POST "$BASE/api/v1/apply" \
  -H "Authorization: Bearer $TOKEN" -H 'X-Requested-With: XMLHttpRequest'
```

`-k` is only for the self-signed management certificate of a fresh appliance;
switch to `--cacert` once you install your own (`PUT /api/v1/settings/management-tls`).

## Authentication

`status`, `login` and `enroll` need no session. `login`, `enroll` and `change-password` share one per-IP limiter (`LoginRateLimiter`, configured in `internal/bootstrap/run.go` as 10 attempts per 5-minute sliding window, then a 15-minute lockout). Every request that gets past the limiter counts as an attempt, whether it succeeds or not. The 10th attempt in the window is still processed, but it starts the lockout. While the lockout runs, requests are refused without being counted. A successful login, enrollment or password change clears the counter for that IP. When the client IP cannot be determined, no limit is applied. These three handlers cap their own request body at 16 KiB (`maxLoginRequestBodyBytes`).

### `GET /api/v1/auth/status`
Reports whether the appliance is still waiting for first-operator enrollment. Unauthenticated, read-only.
- **Response:** `200`
  ```json
  {"enrollment_required": true, "enrollment_file": "/var/lib/easy-waf/secrets/enrollment"}
  ```
  `enrollment_required` is true when no operator exists and the enrollment secret has not been consumed. `enrollment_file` is the resolved path of the enrollment secret, `<state_dir>/secrets/enrollment`.
- **Errors:** `500` (text/plain) on a database error.

### `POST /api/v1/auth/login`
Checks a local operator's username and password and issues a session JWT valid for 24 hours (`sessionTTL`). Failures write a `login_failed` audit row, and rate-limited requests write `login_rate_limited`.
- **Request body:**
  - `username` (string, required; surrounding whitespace is trimmed; max 128 bytes)
  - `password` (string, required; max 256 bytes)
  ```json
  {"username": "admin", "password": "correct horse battery"}
  ```
- **Response:** `200`
  ```json
  {"token": "<jwt>", "must_change_password": false, "expires_in_seconds": 86400}
  ```
  If `must_change_password` is true, the session can only reach `/auth/me`, `/auth/logout` and `/auth/change-password` until the password is changed.
- **Errors:**
  - `400` (text/plain): invalid JSON, missing username or password, or credentials over the length limits.
  - `401` (JSON): `{"error": "invalid credentials"}` for an unknown user or a wrong password. When the user is unknown and enrollment is still pending, the body is `{"error": "enrollment required"}` instead.
  - `429` (JSON) with a `Retry-After` header in seconds: `{"error": "too many login attempts, try again later"}`.
  - `500` (text/plain): the token could not be signed.

### `POST /api/v1/auth/enroll`
Creates the first operator from the one-time enrollment secret, deletes the enrollment file, and returns a session the same way login does. Writes the audit actions `enrollment_completed`, `enrollment_failed` or `enrollment_rate_limited`.
- **Request body:**
  - `secret` (string, required; whitespace is trimmed; max 256 bytes): the contents of `<state_dir>/secrets/enrollment`.
  - `username` (string, optional; defaults to `admin`; max 128 bytes).
  - `password` (string, required; at least 8 characters after trimming; at most 72 bytes, the bcrypt input limit).
  ```json
  {"secret": "<64 hex chars>", "username": "admin", "password": "a-long-passphrase"}
  ```
- **Response:** `200`, same shape as login. `must_change_password` is always `false`.
- **Errors:**
  - `400` (text/plain): invalid JSON, missing secret or password, values too long (`credentials are too long`), a password shorter than 8 characters, or a password longer than 72 bytes (`password must be at most 72 bytes`).
  - `401` (JSON): `{"error": "invalid enrollment secret"}`. Returned for a wrong secret and also when no enrollment record exists.
  - `409` (JSON): `{"error": "enrollment already completed"}`. An operator already exists or the secret was already used.
  - `429` (JSON) with `Retry-After`: `{"error": "too many enrollment attempts, try again later"}`.
  - `500` (text/plain): hashing, database or token error.

### `GET /api/v1/auth/me`
Returns the caller's identity. Works while a password change is pending.
- **Response:** `200` `{"username": "admin", "must_change_password": false}`. With the legacy `EASY_WAF_ADMIN_TOKEN`, the response is always `{"username": "automation", "must_change_password": false}`.
- **Errors:** `404` (text/plain) if the user row no longer exists.

### `POST /api/v1/auth/logout`
Signs the caller out server-side by incrementing the user's `session_version`. This revokes every JWT issued to that user, on every device, not just the current one. No request body. The request produces two audit rows: the handler's own `logout` row and the generic `"POST /api/v1/auth/logout"` mutation row.
- **Response:** `200` `{"revoked": true}`
- **Errors:** `400` (text/plain) when called with the legacy automation token, which has no session to revoke. `404` (text/plain) if the user is not found. `500` (text/plain) on a database error.

### `POST /api/v1/auth/change-password`
Changes the caller's password, clears `must_change_password`, revokes all existing sessions (by incrementing `session_version`), and returns a fresh token. Works while a password change is pending. Subject to the shared per-IP limiter; a successful change clears the counter for the caller's IP. The request produces two audit rows: `password_changed` and the generic `"POST /api/v1/auth/change-password"` mutation row.
- **Request body:**
  - `current_password` (string, required)
  - `new_password` (string, required; at least 8 characters after trimming; at most 72 bytes)
  ```json
  {"current_password": "old-secret", "new_password": "a-new-long-passphrase"}
  ```
- **Response:** `200`, same shape as login, with `must_change_password: false`. The token used for this call stops working, so the client must switch to the returned one.
- **Errors:**
  - `400` (text/plain): legacy token (`use local user session to change password`), invalid JSON, a new password shorter than 8 characters, or longer than 72 bytes (`password must be at most 72 bytes`).
  - `401` (text/plain): `current password incorrect`.
  - `404` (text/plain): user not found.
  - `429` (JSON) with `Retry-After`: `{"error": "too many attempts, try again later"}`.
  - `500` (text/plain): hashing or database error, or `password changed but session could not be issued` when the password was changed but the user could not be re-read to sign the new token.

## Status and catalogue

### `GET /api/v1/status`
Minimal status for the control plane.
- **Response:** `200` `{"state_dir": "/var/lib/easy-waf", "version": "1.4.0"}`. `version` is read from the `EASY_WAF_VERSION` environment variable and is an empty string when that variable is unset.

### `GET /api/v1/system/services`
Reports the systemd `ActiveState` of the appliance's core units. Each unit is queried in turn (`systemctl show -p ActiveState --value`, falling back to `systemctl is-active`) with a 5-second timeout per unit, covering all attempts for that unit. With eight units, a hung systemd can delay the response by up to about 40 seconds.
- **Response:** `200`
  ```json
  {"services": [
    {"id": "easy_waf_api", "unit": "easy-waf-api.service", "label": "Control plane + UI", "active_state": "active"}
  ]}
  ```
  The fixed list of IDs is `easy_waf_api`, `easy_waf_acmed`, `haproxy`, `crowdsec`, `crowdsec_spoa`, `nftables`, `fail2ban` and `postgresql`. `active_state` is whatever systemd reports (`active`, `inactive`, `failed`, `activating`, and so on), or `unknown` if systemctl is unavailable.
- **Errors:** none. Failures show up as `unknown`.

### `GET /api/v1/profiles`
Returns the built-in profile catalogue (`profiles.All()` in `internal/profiles/profiles.go`) as an object keyed by profile name: `balanced`, `strict`, `trusted-lan`, `public-app`, `home-assistant`, `none` and `custom`.
- **Response:** `200`. Each value has the fields `name`, `description`, `rate_limit_rps`, `rate_limit_burst`, `connect_timeout_ms`, `server_timeout_ms` (integers, milliseconds), `http_keep_alive`, `block_paths` and `extra_blocked_methods` (arrays, `[]` when empty), `geo_default_deny`, and `notes` (omitted when empty).
  ```json
  {"balanced": {"name": "balanced", "description": "Reasonable defaults for most home apps",
    "rate_limit_rps": 50, "rate_limit_burst": 100, "connect_timeout_ms": 5000, "server_timeout_ms": 50000,
    "http_keep_alive": true, "block_paths": ["/.git", "..."], "extra_blocked_methods": ["TRACE", "CONNECT"],
    "geo_default_deny": false}}
  ```

### `GET /api/v1/security/modes`
Returns the catalogue of security-mode presets (`profiles.SecurityModeCatalog()` in `internal/profiles/mode_descriptions.go`).
- **Response:** `200`, an array of `{id, label, description, toggles, profile_hint?}` objects. The IDs, in order, are `full`, `balanced`, `trusted-lan`, `reverse-proxy-only` and `custom`. `toggles` maps the keys `rate_limit`, `path_acl`, `method_filter`, `basic_waf`, `bot_protection`, `ip_blacklist`, `ip_allowlist`, `geoip` and `crowdsec` to booleans. For `custom`, `toggles` is empty. `profile_hint` is the profile that the preset also sets: `strict` for `full`, `balanced` for `balanced`, and `trusted-lan` for `trusted-lan`. It is absent for `reverse-proxy-only` and `custom`.

## Applications

An application (`config.Application`, `internal/config/types.go`) maps a public hostname to a backend. Its JSON fields are `id`, `name`, `public_host`, `backend_host`, `backend_port`, `backend_https`, `backend_tls_verify`, `backend_tls_ca_file`, `backend_tls_server_name`, `websocket`, `health_path`, `path_prefix`, `restricted_paths` (`[{path_prefix, allowed_cidrs}]`), `profile`, `certificate_id`, `listen_mode`, `enabled`, `security` (see [Application security](#application-security)), `created_at` and `updated_at`.

Mutating endpoints in this section and the next write to the database first and then apply the change to HAProxy. If the apply fails, the database change is undone and the endpoint returns an error (text/plain) with a message such as `change not saved, edge apply failed: …`. If the undo itself fails, the message instead reads `edge apply failed: …; undoing the database change also failed, so it is saved but not live: …`. The status code is:
- `503` when the apply ran out of time. An apply waits at most 2 minutes, including the time spent waiting for the apply lock, so this typically means another apply was still running; a retry can succeed.
- `422` for any other apply failure (validation, reload, …).

With `EASY_WAF_NO_AUTO_APPLY=1`, the apply step is skipped and changes go live only after `POST /api/v1/apply`.

### `GET /api/v1/applications`
Lists all applications, ordered by `public_host`.
- **Response:** `200`, an array of `config.Application`; `[]` when there are none.
- **Errors:** `500` (text/plain) on a database error.

### `GET /api/v1/applications/{id}`
Returns one application.
- **Path params:** `id`, the application ID.
- **Response:** `200` `config.Application`.
- **Errors:** `404` (text/plain, `not found`) for an unknown ID. `500` (text/plain) on a database error.

### `POST /api/v1/applications`
Creates or replaces an application (upsert), then applies it to HAProxy. A body without `id`, or with an `id` that does not exist yet, creates the application; a server-generated UUID is used when `id` is omitted. A body with an existing `id` replaces the whole stored row. The audit label for the apply is `api-application`. Extra audit rows are written for:
- `app_listen_mode_changed`, when an existing application's `listen_mode` changes. Its detail is `app_id`, `app_name`, `from` and `to`, plus `severity: "warn"` when either side is `http_only`.
- `backend_tls_verify_disabled`, when the saved application has `backend_https: true` and `backend_tls_verify: "none"`.
- **Request body:** a `config.Application`. Server-side processing:
  - `profile` is required and must be one of the names from `GET /profiles`.
  - `listen_mode` is normalised to `https_only` (default), `http_only`, `http_and_https` or `redirect_to_https`. Unknown values become `https_only`.
  - `certificate_id` is required unless `listen_mode` is `http_only`.
  - `id`, if given, must match `^[A-Za-z0-9][A-Za-z0-9_-]*$` and be at most 128 bytes.
  - `public_host` must be lowercase `a-z0-9.-`.
  - `backend_host` must be `A-Za-z0-9._:-`.
  - `backend_port` must be between 1 and 65535.
  - `name` can be at most 200 bytes and must not contain control characters.
  - `health_path`, `path_prefix` and `restricted_paths[].path_prefix` must pass HAProxy path validation. Each entry in `restricted_paths[].allowed_cidrs` must be an IP address or a CIDR.
  - `backend_tls_verify` must be `required` (the default) or `none`. When it is empty on an update, the stored `backend_tls_verify`, `backend_tls_ca_file` and `backend_tls_server_name` are kept.
  - `backend_tls_ca_file` must be an absolute path to an allowlisted file.
  - `security`: the toggles and other fields sent are kept, and `security.mode` is ignored and recomputed from the nine toggles (`profiles.DetectMode`). Only a block with nothing set (no `mode`, every toggle false, no GeoIP policy or country list, no rate-limit overrides), including an omitted `security`, is replaced with the default `balanced` settings. To store every toggle off, include a `mode` or use `POST /applications/{id}/security/mode` with `reverse-proxy-only`.
  - `created_at` and `updated_at` are set by the server. On an update, the stored `created_at` is kept and returned.
  ```json
  {
    "name": "Home Assistant",
    "public_host": "ha.example.com",
    "backend_host": "192.168.1.20",
    "backend_port": 8123,
    "backend_https": false,
    "websocket": true,
    "profile": "home-assistant",
    "certificate_id": "ha-example-com",
    "listen_mode": "redirect_to_https",
    "enabled": true,
    "security": {"mode": "balanced", "rate_limit_enabled": true, "path_acl_enabled": true,
                 "method_filter_enabled": true, "basic_waf_enabled": true, "bot_protection_enabled": true,
                 "ip_blacklist_enabled": true, "ip_allowlist_enabled": true, "geoip_enabled": false,
                 "crowdsec_enabled": true, "geoip_policy": "allow", "geoip_country_list": []}
  }
  ```
- **Response:** `200`, the saved `config.Application`, including the assigned `id`. When backend TLS verification is disabled, the same object comes back with an extra `warning` string field.
- **Errors:**
  - `400` (text/plain): invalid JSON, an unknown profile, a missing `certificate_id`, or any validation failure listed above.
  - `422` / `503` (text/plain): the apply failed and the change was undone (see above). For a new application, undoing means deleting it again.
  - `500` (text/plain): database error.

### `DELETE /api/v1/applications/{id}`
Deletes an application and applies the result to HAProxy (audit label `api-application-delete`). If the apply fails, the deleted row is put back.
- **Path params:** `id`.
- **Response:** `204`, no body.
- **Errors:** `404` (text/plain, `not found`) for an unknown ID; nothing is applied. `422` / `503` (text/plain) if the apply failed and the row was restored. `500` (text/plain) on a database error.

## Application security

`config.ApplicationSecurity` (`internal/config/types.go`) has these fields:
- `mode`: one of `full`, `balanced`, `trusted-lan`, `reverse-proxy-only` or `custom`.
- Toggles (all boolean): `rate_limit_enabled`, `path_acl_enabled`, `method_filter_enabled`, `basic_waf_enabled`, `bot_protection_enabled`, `ip_blacklist_enabled`, `ip_allowlist_enabled`, `geoip_enabled` and `crowdsec_enabled`.
- `geoip_policy`: `allow` or `deny`. Any value other than `deny` is stored as `allow`.
- `geoip_country_list`: an array of ISO 3166-1 alpha-2 codes.
- `rate_limit_rps_override` and `rate_limit_burst_override`: optional integers.

On PUT and PATCH, the server recomputes `mode` from the nine toggles. It becomes the name of the preset whose toggles match exactly, or `custom` if none does. All three write endpoints return the saved `ApplicationSecurity` and apply it to HAProxy, with the undo and `422`/`503` behaviour described under [Applications](#applications). For all four endpoints, an unknown application is `404` (text/plain, `not found`) and a database error while loading it is `500`.

### `GET /api/v1/applications/{id}/security`
Returns the application's `security` object.
- **Response:** `200` `config.ApplicationSecurity`.
- **Errors:** `404`, `500` (text/plain).

### `PUT /api/v1/applications/{id}/security`
Replaces the whole security object, then applies (audit label `api-application-security`). Fields that are omitted are reset to their zero values; `mode` is recomputed from the toggles. Only a body with nothing set (see the `security` rule under `POST /applications`) is replaced with the `balanced` defaults.
- **Request body:** `config.ApplicationSecurity`.
  ```json
  {"rate_limit_enabled": true, "path_acl_enabled": true, "method_filter_enabled": true,
   "basic_waf_enabled": true, "bot_protection_enabled": false, "ip_blacklist_enabled": true,
   "ip_allowlist_enabled": true, "geoip_enabled": true, "crowdsec_enabled": true,
   "geoip_policy": "deny", "geoip_country_list": ["CN", "RU"], "rate_limit_rps_override": 30}
  ```
- **Response:** `200`, the saved `config.ApplicationSecurity`. In the example, `mode` comes back as `custom`.
- **Errors:** `400` (text/plain) for invalid JSON, or when the application's stored `profile` is unknown. `404` if the application does not exist. `422` / `503` if the apply failed and the change was undone. `500` on a database error.

### `PATCH /api/v1/applications/{id}/security`
Merges a partial JSON object over the stored security object (top-level keys only; `config.MergeApplicationSecurityJSON`), then applies (audit label `api-application-security`). Keys that are omitted keep their stored values.
- **Request body:** any subset of the `ApplicationSecurity` fields, for example `{"geoip_enabled": true, "geoip_policy": "deny", "geoip_country_list": ["CN"]}`. At most 1 MiB.
- **Response:** `200`, the merged `config.ApplicationSecurity`.
- **Errors:** `400` (text/plain) for invalid JSON, a type mismatch, or an unknown stored profile. `404` if the application does not exist. `413` (text/plain, `request body exceeds 1048576 bytes`) for a body over 1 MiB. `422` / `503` if the apply failed and the change was undone. `500` on a database error.

### `POST /api/v1/applications/{id}/security/mode`
Applies a one-click preset (`profiles.ApplyModePreset`), then applies to HAProxy (audit label `api-application-security-mode`). On success, writes an `app_security_mode_changed` audit row. Its detail is `app_id`, `app_name`, `from`, `to` and the resulting `toggles`, plus `level: "warn"` for `reverse-proxy-only`.

What each preset does:
- `full`: turns every toggle on and sets the application's `profile` to `strict`.
- `balanced`: turns every toggle on except GeoIP and sets `profile` to `balanced`.
- `trusted-lan`: turns off path ACL, basic WAF, bot protection and GeoIP, and sets `profile` to `trusted-lan`.
- `reverse-proxy-only`: turns every toggle off and leaves `profile` unchanged.
- `custom`: sets `mode` to `custom` and leaves the toggles and `profile` unchanged. Unlike PUT and PATCH, the mode is not re-detected, so it stays `custom` even when the toggles match a preset.

GeoIP policy, the country list and the rate-limit overrides are never changed by a preset.
- **Request body:** `{"mode": "trusted-lan"}`. `mode` is required and is matched case-insensitively after trimming.
- **Response:** `200`, the resulting `config.ApplicationSecurity`.
- **Errors:** `400` (text/plain) for invalid JSON, `unknown mode`, or an unknown profile. `404` if the application does not exist. `422` / `503` if the apply failed and the change was undone. `500` on a database error.

## Apply and revisions

### `POST /api/v1/apply`
Renders the full HAProxy configuration from the database and applies it. This means validating with `haproxy -c`, promoting the managed artifact set, saving a revision snapshot, reloading HAProxy, and writing a config revision plus an `apply` audit row in one step. On any failure, the previous files are restored. This is the endpoint that puts certificate, settings, IP list and user-agent changes live; those write endpoints do not apply on their own.
- **Request body:** optional `{"label": "string"}`. The label is stored with the revision. A missing or invalid body is ignored and the label is then empty.
- **Response:** `200` `{"status": "applied"}`
- **Errors (text/plain, engine error message):**
  - `422` for an apply failure, for example `validation failed: …`, an empty TLS crt-list (`TLS: crt-list would be empty — …`) or a reload failure.
  - `503` when the apply timed out. It waits at most 2 minutes, including the time spent waiting for the apply lock (`acquire HAProxy apply lock: context deadline exceeded`). A retry can succeed.

### `GET /api/v1/revisions`
Lists HAProxy config revisions, newest first.
- **Query params:** `limit` (integer, default 30). Values ≤ 0, and anything that is not an integer, fall back to 30. Values above 200 are capped at 200.
- **Response:** `200`, an array. `[]` when there are no revisions.
  ```json
  [{"id": 42, "sha": "<sha256 hex>", "label": "api-application", "created_at": "2026-10-19T08:12:03.123456Z",
    "is_current": true, "config_snippet_preview": "global log stdout ..."}]
  ```
  `label` is the label stored with the revision: the `label` sent to `POST /apply` (empty if none), the audit label of an auto-applying mutation such as `api-application`, or `rollback from <sha[:12]>`. `is_current` is true when `sha` equals the SHA-256 of the live `haproxy.cfg`. `config_snippet_preview` holds the first 240 characters of `<state_dir>/revisions/haproxy-<sha[:12]>.cfg`, with newlines collapsed to spaces and `…` appended when truncated. It is an empty string when that file is missing.
- **Errors:** `500` (text/plain) on a database error.

### `POST /api/v1/revisions/{id}/rollback`
Restores the managed artifact set of an earlier revision, then validates it, reloads HAProxy, and records a new revision labelled `rollback from <sha[:12]>` together with a `rollback` audit row. The detail of that audit row includes `from_revision_id` and `from_label`. Revisions that have an artifact manifest restore the full artifact set. Legacy revisions without one restore `haproxy.cfg` only. On failure, the previous files are restored. The rollback waits at most 2 minutes, including the time spent waiting for the lock. No request body.
- **Path params:** `id`, a positive integer revision ID.
- **Response:** `200` `{"status": "ok"}`
- **Errors:**
  - `400` (text/plain): `invalid revision id` for an `id` that is not a positive integer.
  - `404` (text/plain): `revision not found`.
  - `422` (text/plain): the rollback failed — a missing snapshot, a checksum mismatch, `validation failed: …`, a reload failure, or `already using this configuration` (legacy, cfg-only revisions only). The previous files are back in place.
  - `503` (text/plain): it timed out, typically waiting for another apply to finish; retrying can succeed.

A rollback changes only HAProxy's files. The database (applications, settings) is left as it is, so the next apply, or the next API mutation that triggers one, renders the current database state again.

## Certificates

The certificate endpoints write to the database only. None of them runs an HAProxy apply, unlike the application endpoints. A changed certificate reaches the edge on the next apply, which can be a manual `POST /api/v1/apply`, an application change, or `easy-waf-acmed` after an issuance.

### `GET /api/v1/certificates/summary`
Dashboard view: status counters plus one compact row per certificate. The status is computed at request time (UTC).
- **Response:** `200`, `config.CertificateSummaryResponse`:
  - `total`, `valid`, `expiring_soon`, `expired`, `failed` (int). `pending` rows count toward `total` only.
  - `certificates`: array of `config.CertificateSummaryEntry`, sorted by `primary_domain`, with these fields:
    - `id`, `primary_domain`
    - `not_after` (RFC 3339, omitted if unknown)
    - `days_remaining` (int, floor of the days until `not_after`; negative once expired; omitted if unknown)
    - `status`: `valid`, `expiring`, `expired`, `pending` or `failed`
    - `mode`: `http-01`, `dns-01` or `manual`. Any stored mode other than an ACME one, including `self-signed`, is reported as `manual`.
    - `last_error`, `next_attempt_at`: only when `status` is `failed`.
- **Status rules, in order:**
  1. `not_after` in the past → `expired`.
  2. `acme_status` is `pending` or `issuing` → `pending`.
  3. `acme_status` is `failed` → `failed`, even if an older certificate is still valid.
  4. No `not_after` → `pending`.
  5. Fewer than 30 days left → `expiring`.
  6. Otherwise → `valid`.
- **Example:**
  ```json
  {"total":2,"valid":1,"expiring_soon":0,"expired":0,"failed":1,
   "certificates":[
    {"id":"c1","primary_domain":"app.example.com","not_after":"2027-01-10T08:00:00Z","days_remaining":82,"status":"valid","mode":"http-01"},
    {"id":"c2","primary_domain":"nas.example.com","status":"failed","mode":"dns-01","last_error":"dns: timeout","next_attempt_at":"2026-10-19T14:00:00Z"}]}
  ```
- **Errors:** `500` (text/plain) on a database error.

### `GET /api/v1/certificates`
Lists every certificate row, ordered by `primary_domain`.
- **Response:** `200`, a JSON array of `config.Certificate` (`internal/config/types.go`); `[]` when there are none. Fields:
  - `id`, `primary_domain`, `san` (string[], omitted when empty)
  - `mode` (`http-01`, `dns-01`, `self-signed`, …)
  - `dns_provider`, `dns_credentials_env_file`
  - `acme_status` (`ready`, `pending`, `issuing` or `failed`), `acme_attempts`, `acme_next_attempt_at`
  - `staging` (bool)
  - `pem_crt_path`, `pem_key_path`, `fullchain_path`
  - `not_before`, `not_after`, `last_error`
  - `created_at`, `updated_at`

  `bundle_path` is not stored, so it is never returned.
- **Errors:** `500` (text/plain) on a database error.

### `POST /api/v1/certificates`
Creates or updates (upserts) one certificate row, keyed by `id`.
- **Request body:** a `config.Certificate` object. No field is required by the handler.
  - `id`: omit or send `""` to create a new row with a generated UUID. If present, it must match `^[A-Za-z0-9][A-Za-z0-9_-]*$` and be at most 128 bytes.
  - `pem_crt_path`, `pem_key_path`, `bundle_path`, `fullchain_path`: optional. When set, each must contain only `[A-Za-z0-9._~+@:/-]`, contain no `..` segment, and be at most 4096 characters. Absoluteness is not checked. `bundle_path` is validated but not stored.
  - `dns_provider`: trimmed and stored lower-case. For a `dns-01` certificate it must be empty (meaning the default, `cloudns`), `cloudflare`, `cloudns`, `route53` or `webhook`.
  - `dns_credentials_env_file`: for a `dns-01` certificate, empty or a clean absolute path (no `.`/`..` segments, no duplicate or trailing slashes, no control characters) strictly below `/etc/easy-waf/` or `<state_dir>/secrets/`. `easy-waf-acmed` loads this file's `KEY=value` lines into its environment for the DNS-01 provider. Other modes do not use either field, and they are not checked there.
  - `acme_status`: defaults to `ready` when empty. Sending `pending` resets `acme_attempts` and `acme_next_attempt_at` in the database.
  - On update, every stored column is overwritten by the request value, so a partial body clears the fields it omits. `created_at` is kept. `acme_attempts`, `acme_next_attempt_at` and `bundle_path` are never taken from the body.
  ```json
  {"primary_domain":"app.example.com","san":["www.app.example.com"],"mode":"self-signed",
   "pem_crt_path":"/var/lib/easy-waf/certs/app.crt","pem_key_path":"/var/lib/easy-waf/certs/app.key"}
  ```
- **Response:** `200`, the stored `config.Certificate`, re-read after the write.
- **Errors (text/plain):**
  - `400` for malformed JSON, an invalid `id`, an unsafe path, an unsupported `dns_provider` (`dns_provider "…" is not supported (use cloudflare, cloudns, route53 or webhook)`), or a rejected `dns_credentials_env_file` (`… must be a clean absolute path`, `… must be under /etc/easy-waf/ or <state_dir>/secrets/`).
  - `500` on a database error.

### `DELETE /api/v1/certificates/{id}`
Deletes a certificate row. It refuses while an application still references the certificate.
- **Path params:** `id`, the certificate ID.
- **Response:** `204`, empty body.
- **Errors:**
  - `409` (JSON) with `{"error":"<n> application(s) still reference this certificate; detach or delete them first"}`.
  - `404` (text/plain, `not found`) when no row has that ID.
  - `500` (text/plain) on a database error.

### `POST /api/v1/certificates/{id}/request-issue`
Queues an ACME issuance or renewal. The handler sets `acme_status` to `pending` and saves the row, which also resets `acme_attempts` and `acme_next_attempt_at`. `easy-waf-acmed` claims pending rows on its next pass. The request itself performs no ACME work.
- **Path params:** `id`, the certificate ID.
- **Request body (optional):** an empty body keeps the stored settings, as described per field.
  - `mode` (string): `http-01` or `dns-01`, case-insensitive. When omitted, the stored mode is kept if it is already `http-01` or `dns-01`. Otherwise it defaults to `http-01`, so the call means "start issuing this with ACME".
  - `dns_provider` (string): overwrites the stored value only if non-empty.
  - `dns_credentials_env_file` (string): overwrites the stored value only if non-empty.

  When the resulting mode is `dns-01`, its DNS fields are validated with the same rules as `POST /certificates`; `dns_provider` is stored lower-case.
  ```json
  {"mode":"dns-01","dns_provider":"cloudflare","dns_credentials_env_file":"/etc/easy-waf/dns-cloudflare.env"}
  ```
- **Response:** `200`, the updated `config.Certificate` with `acme_status: "pending"`.
- **Errors (text/plain):**
  - `400` for malformed JSON, `mode must be http-01 or dns-01` for any other mode, or a rejected `dns_provider` / `dns_credentials_env_file`.
  - `404` (`not found`) for an unknown ID.
  - `500` on a database error.

## Settings

Global settings are stored as one JSON document in the database. The Go type is `config.GlobalSettings` in `internal/config/types.go`; the defaults are in `config.DefaultSettings`.

Saving settings updates the database and this process's in-memory copy, and reconfigures the in-process GeoIP runtime. It does **not** run an HAProxy apply. Edge-affecting settings (WAF rules, map paths, GeoIP enforcement, IP lists, …) take effect on the next `POST /api/v1/apply` or the next application mutation, which auto-applies. The management ACL and `prometheus_enabled` are read per request, so they take effect immediately.

### `GET /api/v1/settings`
Returns the current global settings.
- **Response:** `200`, every JSON field of `config.GlobalSettings` plus `crowdsec_lapi_key_set` (bool). The CrowdSec LAPI key itself is never returned. Durations (`geoip_cache_ttl`, `acme_renewal_interval`) are Go duration strings such as `"24h0m0s"`.
  ```json
  {"acme_staging":true,"crowdsec_lapi_url":"http://127.0.0.1:8080/","haproxy_config_path":"/var/lib/easy-waf/haproxy/haproxy.cfg",
   "geoip_enabled":false,"geoip_provider":"ipinfo","geoip_cache_ttl":"24h0m0s","management_allowed_cidrs":["127.0.0.0/8","::1/128","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"],
   "prometheus_enabled":false,"crowdsec_lapi_key_set":true, "...": "..."}
  ```

### `PUT /api/v1/settings` and `PATCH /api/v1/settings`
Both methods behave identically: they **merge** the body over the stored settings. `PUT` does not replace the whole document.
- **Merge semantics:**
  - The body must be a single JSON object of at most 1 MiB; trailing data is rejected.
  - Only keys present in the body are applied. Omitted keys keep their stored values, and unknown keys are ignored.
  - The merge starts from the settings currently stored in the database, not this process's cached copy, under a lock. A concurrent change made through the admin CLI or another instance is therefore kept.
- **Request body:** any subset of the JSON keys of `config.GlobalSettings`, plus the write-only `crowdsec_lapi_key`. Durations accept a Go duration string (`"12h"`) or a number of nanoseconds. Example:
  ```json
  {"geoip_enabled":true,"geoip_provider":"maxmind","geoip_mmdb_path":"/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb","geoip_default_policy":"deny","geoip_country_list":["CN","RU"]}
  ```
- **Fields with special handling:**
  - `crowdsec_lapi_key` (write-only): an empty string leaves the stored key unchanged, so the key cannot be cleared through this API. `crowdsec_lapi_key_set` in the response shows whether a key is stored.
  - `acme_email`: an empty string keeps the stored value, so the address cannot be cleared through this API.
  - `management_allowed_cidrs`: `null` keeps the stored list. Otherwise the list must contain at least one entry, and every entry must be a valid CIDR prefix (`netip.ParsePrefix`, so a bare IP without `/n` is rejected). The new list is enforced from the next request on. A list that excludes your own address locks you out of the API and UI.
  - `prometheus_enabled`: turns `GET /metrics` on or off immediately.
  - GeoIP:
    - `geoip_default_policy` must be `allow`, `deny` or empty.
    - `geoip_provider` must be `ipinfo`, `maxmind` or empty.
    - When `geoip_enabled` is `true` and the provider is `maxmind`, `geoip_mmdb_path` is required.
  - Required absolute paths (non-empty, absolute, render-safe): `haproxy_config_path`, `haproxy_stats_socket_path`, `haproxy_binary`, `geoip_enforce_map_path`, `ip_blacklist_map_path`, `ip_allowlist_map_path`, `blocked_user_agents_map_path`.
  - `spoe_config_path`: if set, must be absolute.
  - `geoip_mmdb_path` and `spoe_config_path` must also be render-safe: only `[A-Za-z0-9._~+@:/-]` and no `..`.
  - `crowdsec_engine_name`: if set, 1–64 characters from `[A-Za-z0-9_.-]`.
  - `acme_internal_http`: empty, meaning the default `127.0.0.1:8089`, or an `IP:port` literal. Hostnames are rejected.
  - `crowdsec_lapi_url`: if set, must pass the CrowdSec LAPI URL validator.
- **Response:** `200`, the full merged settings in the same shape as `GET /api/v1/settings`.
- **Errors (text/plain):**
  - `400` for an unreadable body, invalid JSON or a wrong value type (message prefixed with the key, e.g. `geoip_enabled: json: cannot unmarshal ...`), or any validation failure above.
  - `413` (`request body exceeds 1048576 bytes`) for a body over 1 MiB.
  - `500` when reading or saving the stored settings fails.

### `PUT /api/v1/settings/management-tls`
Replaces the TLS certificate of the HTTPS management listener. The handler validates that the certificate and key form a pair, writes both files atomically (certificate mode `0644`, key `0600`), and swaps the in-memory certificate. New TLS handshakes use it immediately, with no restart. Nothing is stored in the database.
- **Request body:**
  - `certificate_pem` (string, required): PEM certificate, optionally with chain.
  - `private_key_pem` (string, required): PEM private key.
  ```json
  {"certificate_pem":"-----BEGIN CERTIFICATE-----\n...","private_key_pem":"-----BEGIN PRIVATE KEY-----\n..."}
  ```
- **Response:** `200` with `{"status":"ok"}`.
- **Errors:**
  - `400` (JSON) with `{"error":"HTTPS management is disabled (EASY_WAF_MANAGEMENT_HTTPS=0)"}` when the listener runs without TLS.
  - `400` (JSON) with `{"error":"certificate_pem and private_key_pem required"}`.
  - `400` (JSON) with `{"error":"invalid pem pair: ..."}` for a bad or mismatched pair.
  - `400` (text/plain) for malformed JSON.
  - `500` (JSON) when the certificate or key file cannot be written.

## Statistics

Both endpoints read HAProxy `show stat` from the stats Unix socket. The socket is `haproxy_stats_socket_path` from settings; an empty value, or the legacy `<state_dir>/haproxy/admin.sock`, maps to `/run/haproxy/easy-waf-admin.sock`. Reads are cached for 5 seconds per socket path, and concurrent requests share a single socket read. An unreachable socket is **not** an HTTP error: both endpoints still return `200` with an `error` string in the body.

### `GET /api/v1/stats/haproxy`
Per-frontend and per-backend HAProxy statistics.
- **Response:** `200`, `metrics.HAProxyReport` (`internal/metrics/haproxy.go`):
  - `collected_at` (RFC 3339; the zero time when the read failed)
  - `frontends`: array of objects with `name`, `status`, `sessions_cur`, `sessions_max`, `bytes_in`, `bytes_out`, `req_rate`, `http_2xx`, `http_4xx`, `http_5xx`, and `total_req_hint` (sum of the cumulative `hrsp_*` counters).
  - `backends`: array of objects with the same counters (except `total_req_hint`) plus `health` (`healthy`, `degraded` or `down`, derived from the servers) and `servers` (each with `name`, `status`, `sessions_cur`).
  - `error` (string, only on failure, e.g. `stats socket "/run/haproxy/easy-waf-admin.sock": dial unix ...: connect: no such file or directory`). On failure `frontends` and `backends` are `null`.
- **Errors:** none returned as an HTTP error. If the client disconnects while waiting for the read, nothing is written.

### `GET /api/v1/stats/summary`
Dashboard aggregate computed from the same report.
- **Response:** `200`, `metrics.SummaryReport`:
  - `total_requests`: sum of `total_req_hint` over all frontends, i.e. cumulative HTTP responses since the HAProxy counters last reset.
  - `blocked_requests`: `http_4xx + http_5xx` on frontend `fe_https`, or on all frontends if there is no `fe_https`. This counts every 4xx and 5xx response, including those that come from the backends, not only WAF denials.
  - `active_sessions`: sum of frontend `sessions_cur`.
  - `req_rate` (float): sum of frontend `req_rate`.
  - `backends_up`, `backends_down`: counts of backend **servers**, not backends. A server whose status is `UP` (including transitional `UP n/m`) counts as up; one whose status contains `DOWN` or starts with `MAINT` or `NOLB` counts as down; other states are not counted.
  - `error` (string, only when the socket read failed; the counters are then `0`).
  ```json
  {"total_requests":184220,"blocked_requests":312,"active_sessions":7,"req_rate":3,"backends_up":4,"backends_down":0}
  ```
- **Errors:** as for `/stats/haproxy`.

## Audit log

### `GET /api/v1/audit`
Lists audit-log rows, newest first (by `id` descending). Every mutating request in the session-protected API (`POST`/`PUT`/`PATCH`/`DELETE`) appears here with action `"<METHOD> <path>"` and `details` `{"http_status":<code>,"category":"<area>"}`, along with the named entries written by handlers and other components.
- **Query params:**

  | Param | Type | Meaning |
  |---|---|---|
  | `limit` | int | Page size. Default `100`, maximum `500`. Values `<= 0` or non-numeric fall back to `100`. |
  | `before_id` | int64 > 0 | Keyset cursor: only rows with `id < before_id`. Recommended for paging. |
  | `offset` | int | Legacy offset paging, applied after the filters and the cursor. Negative or non-numeric values become `0`. It gets slower the deeper you page. |
  | `user` | string | Case-insensitive substring match on `user_name`. |
  | `action` | string | Case-insensitive substring match on `action`, e.g. `certificates` or `PUT /api/v1/settings`. The value `all` (any case) disables the filter. |
  | `from` | RFC 3339 | Inclusive lower bound on the entry time. |
  | `to` | RFC 3339 | **Exclusive** upper bound on the entry time. |
  | `include_total` | `1` or `true` | Also return `total`. This runs a full `COUNT(*)` and is expensive on large tables. |

  The `user` and `action` filters match literally: `%` and `_` in the value have no wildcard meaning.
- **Response:** `200`:
  - `entries`: array of `config.AuditLogEntry`, each with `id`, `timestamp` (RFC 3339), `user_name`, `action`, `details` (raw JSON, `null` if none), `source_ip`. Always an array, never `null`.
  - `limit`, `offset` (int): the effective values after clamping.
  - `has_more` (bool): more matching rows exist beyond this page. The server detects this by reading one extra row, with no count query.
  - `next_before_id` (int64): present only when `has_more` is `true`; it is the `id` of the last entry. Pass it as `before_id` to get the next page, keeping the same filters.
  - `total` (int64): present only with `include_total`. It counts rows matching the filters **and** `before_id`, ignoring `offset`. On a later page it is the number of rows remaining from the cursor on, not the grand total, so request it on the first page.
- **Paging example:**
  ```
  GET /api/v1/audit?limit=50&action=certificates
  → {"entries":[{"id":9812,...}, ..., {"id":9701,...}],"limit":50,"offset":0,"has_more":true,"next_before_id":9701}
  GET /api/v1/audit?limit=50&action=certificates&before_id=9701
  → {"entries":[...],"limit":50,"offset":0,"has_more":false}
  ```
- **Errors (text/plain):**
  - `400` for `invalid before_id (positive integer)`, `invalid from (use RFC3339)` or `invalid to (use RFC3339)`.
  - `500` on a database error, including a failed count.

## Diagnostics

### `POST /api/v1/diagnostics/bundle`
Builds a support bundle on the server and returns it as a gzipped tar. This can take several minutes in the worst case: the server runs many local commands one after another with per-command timeouts of up to 45 s, including `journalctl`, `systemctl status`, `haproxy -c`, and `nft list ruleset`, and there is no overall deadline beyond the request context.
- **Request body:** none. Any body is ignored.
- **Bundle contents** (all under `easy-waf-diag-api-<UTC stamp>/`):
  - `MANIFEST.txt` with the version and hostname.
  - System info: uname, os-release, free, df, uptime, `ss -tlnp`, AppArmor status.
  - `systemctl status` and `is-enabled` for `easy-waf-api`, `easy-waf-acmed`, `easy-waf-hostd`, `haproxy`, `crowdsec`, `fail2ban` and `nftables`.
  - The last 24 h of journal (up to 500 lines each) for `easy-waf-api`, `easy-waf-acmed`, `easy-waf-hostd` and `haproxy`. Journal lines are not masked.
  - `/etc/easy-waf/easy-waf.env` with secrets masked.
  - The generated `haproxy.cfg`, read only if it lies inside `<state_dir>/haproxy/`.
  - The crt-list file names only, not the keys.
  - `haproxy -vv` and `haproxy -c` output.
  - The last 5 config revisions (id, sha256, time).
  - The nftables ruleset and `/etc/nftables/easy-waf.nft`.
- **Response:** `200`, `Content-Type: application/gzip`, `Content-Disposition: attachment; filename="easy-waf-diag-api-YYYYMMDD-HHMMSS.tar.gz"`. The body is the `.tar.gz` bytes.
- **Errors (JSON):** `500` with `{"error":"..."}` when the bundle cannot be built. Examples are an uncompressed tar larger than 40 MiB (`diagnostics: bundle size N exceeds limit 41943040`) or a tar write error. A failing individual command does not fail the request; its output, or nothing, lands in the file.

## IP blocklist (IPBL)

None of the IP blocklist, IP allowlist or blocked-user-agent write endpoints apply the change to HAProxy; they only write the database. The change reaches HAProxy on the next `POST /api/v1/apply` (or the next application mutation, which auto-applies). `POST /api/v1/ipbl/sync` rewrites the map files but does not reload HAProxy, which reads map files when it (re)loads.

### `GET /api/v1/ipbl/local`
Lists all local blocklist entries, enabled and disabled, ordered by `cidr`.
- **Response:** `200`, array of entries; `[]` when there are none:
  ```json
  [
    {
      "id": "6f1c0e8a-3c55-4a43-9a43-0c1f2b8f0d11",
      "cidr": "203.0.113.0/24",
      "note": "scanner range",
      "enabled": true,
      "created_at": "2026-10-01T12:00:00Z",
      "updated_at": "2026-10-01T12:00:00Z"
    }
  ]
  ```
  `note` is omitted when empty.
- **Errors:** `500` (text/plain) on a database error.

### `POST /api/v1/ipbl/local`
Creates or updates a local blocklist entry. This is an upsert keyed on `id`: without `id` (or with an empty one) a new UUID is assigned and a row is inserted. With an `id`, the row with that id is updated, or inserted under that id if none exists.
- **Request body** (JSON, `config.IPBLLocalEntry`):

  | Field | Type | Notes |
  |---|---|---|
  | `id` | string | optional; omit to create |
  | `cidr` | string | **required**; trimmed; must be a valid IP address or CIDR (`net.ParseIP` / `net.ParseCIDR`) |
  | `note` | string | optional |
  | `enabled` | bool | defaults to `true` when omitted |

  `updated_at` is set by the server. On update, the stored `created_at` is kept in the database.

  ```json
  { "cidr": "198.51.100.7", "note": "brute force" }
  ```

- **Response:** `200` with the stored entry, including the assigned `id` and its `created_at`.
- **Errors (text/plain):** `400` for malformed JSON, `cidr required` (empty after trim), or an invalid IP/CIDR (`invalid ip or cidr`, or the Go CIDR parse error). `500` on a database error.

### `DELETE /api/v1/ipbl/local/{id}`
Deletes a local blocklist entry.
- **Path params:** `id`, the entry id.
- **Response:** `204`, no body.
- **Errors (text/plain):** `404` (`not found`) for an unknown id. `500` on a database error.

### `GET /api/v1/ipbl/sources`
Lists the external blocklist feeds, ordered by `name`.
- **Response:** `200`, array; `[]` when there are none:
  ```json
  [
    {
      "id": "b0b5c2c4-0f7e-4f0e-9a51-1d0c7c6f8a22",
      "name": "spamhaus-drop",
      "url": "https://www.spamhaus.org/drop/drop.txt",
      "enabled": true,
      "refresh_seconds": 3600,
      "last_fetch_at": "2026-10-19T08:00:00Z",
      "last_error": "",
      "created_at": "2026-10-01T12:00:00Z",
      "updated_at": "2026-10-19T08:00:00Z"
    }
  ]
  ```
  `last_fetch_at` and `last_error` are omitted when unset. They are written only by the feed fetcher during sync/apply.
- **Errors:** `500` (text/plain) on a database error.

### `POST /api/v1/ipbl/sources`
Creates or updates an external feed. This is an upsert keyed on `id`, with the same semantics as `POST /ipbl/local`. It does not fetch the feed; fetching happens on sync/apply.
- **Request body** (JSON, `config.IPBLExternalSource`):

  | Field | Type | Notes |
  |---|---|---|
  | `id` | string | optional; omit to create |
  | `name` | string | display name, not validated |
  | `url` | string | required; `http` or `https` only; checked by the SSRF guard (below) |
  | `enabled` | bool | defaults to `true` when omitted |
  | `refresh_seconds` | int | `<= 0` or omitted is stored as `3600` |

  `last_fetch_at` and `last_error` in the body are ignored: a new source starts without them, and an update keeps the stored values.

  ```json
  { "name": "firehol-level1", "url": "https://iplists.firehol.org/files/firehol_level1.netset", "refresh_seconds": 86400 }
  ```

  **URL validation:** the URL is parsed, and the scheme must be `http`/`https`. The host is resolved, and **every** resolved address (or the literal IP) must pass the feed SSRF policy. Loopback, link-local (including `169.254.x` metadata), CGNAT `100.64.0.0/10` and unspecified addresses are always rejected. Private (RFC 1918) addresses are rejected unless they fall inside `ipbl_fetch_allowed_cidrs`, or the deprecated `ipbl_allow_private_fetch` is on and that list is empty. The hostname must resolve at save time.

- **Response:** `200` with the stored source (same shape as the list items), including its current fetch status.
- **Errors:** `400` (JSON) `{"error": "..."}` when the URL fails validation (bad scheme, DNS failure, blocked destination). `400` (text/plain) for malformed JSON. `500` (text/plain) on a database error.

### `DELETE /api/v1/ipbl/sources/{id}`
Deletes an external feed. Its saved feed copy on disk is removed by the next sync or apply.
- **Path params:** `id`, the source id.
- **Response:** `204`, no body.
- **Errors (text/plain):** `404` (`not found`) for an unknown id. `500` on a database error.

### `POST /api/v1/ipbl/sync`
Regenerates the IP map files on disk, under the engine's apply lock and with the settings currently stored in the database. The steps are:

1. Merge the enabled local blocklist entries.
2. If `ipbl_external_enabled` is true, download every enabled external feed through the SSRF-guarded fetcher. Each feed is capped at 16 MiB and 250,000 entries. A failed download falls back to that feed's last good copy, for up to 7 days; a failing feed does not fail the sync. The fetch result is recorded on each source (`last_fetch_at`, `last_error`). Saved copies of deleted or disabled sources are removed. If external feeds are disabled, all saved feed copies are deleted.
3. Write the blocklist map (`ip_blacklist_map_path`, default `<state>/haproxy/ip_blacklist.map`).
4. Rewrite the allowlist map from `ipwl_local`.
5. Rewrite the GeoIP enforcement map (or its disabled placeholder).

It does **not** render the HAProxy configuration or reload HAProxy.

- **Request body:** none.
- **Response:** `200`, `ipbl.SyncResult`:

  ```json
  {
    "local_lines": 12,
    "external_lines": 48210,
    "total_lines": 47987,
    "map_path": "/var/lib/easy-waf/haproxy/ip_blacklist.map"
  }
  ```

  `local_lines` is the number of unique valid local entries. `external_lines` is the number of feed lines merged, counted per feed and including duplicates. `total_lines` is the number of unique lines written to `map_path`.
- **Errors:** `500` (text/plain) for any failure: lock, settings reload, database, file write or GeoIP map.

## IP allowlist

### `GET /api/v1/ipwl/local`
Lists local allowlist entries ordered by `cidr`.
- **Response:** `200`, array; `[]` when there are none:
  ```json
  [
    { "id": "1d7c...", "cidr": "192.168.1.0/24", "comment": "office LAN", "created_at": "2026-10-01T12:00:00Z" }
  ]
  ```
  `comment` is omitted when empty.
- **Errors:** `500` (text/plain) on a database error.

### `POST /api/v1/ipwl/local`
Creates or updates an allowlist entry. This is an upsert keyed on `id` (omit to create). On update only `cidr` and `comment` change; `created_at` is the server's.
- **Request body** (JSON, `config.IPWLLocalEntry`):

  | Field | Type | Notes |
  |---|---|---|
  | `id` | string | optional |
  | `cidr` | string | **required**; trimmed; must be a valid IP address or CIDR (`net.ParseIP` / `net.ParseCIDR`) |
  | `comment` | string | optional |

  ```json
  { "cidr": "192.168.1.0/24", "comment": "office LAN" }
  ```

- **Response:** `200` with the stored entry.
- **Errors (text/plain):** `400` for malformed JSON, `cidr required` (empty after trim), or an invalid IP/CIDR (`invalid ip or cidr`, or the Go CIDR parse error). `500` on a database error.

Allowlist entries are enforced only when `ipwl_enabled` is true. The map file is rewritten on apply and on `POST /ipbl/sync`.

### `DELETE /api/v1/ipwl/local/{id}`
Deletes an allowlist entry.
- **Path params:** `id`.
- **Response:** `204`, no body.
- **Errors (text/plain):** `404` (`not found`) for an unknown id. `500` on a database error.

## Blocked user agents

Patterns are written to a HAProxy map and matched as **case-insensitive substrings** of the `User-Agent` header (`-m sub -i`). They are enforced only when the global `blocked_user_agents_enabled` setting is on, and only for applications with bot protection enabled. Fresh installs seed several scanner patterns (`Nmap`, `Nikto`, `sqlmap`, ...).

### `GET /api/v1/security/blocked-ua`
Lists all patterns ordered by `pattern`.
- **Response:** `200`, array; `[]` when the table is empty:
  ```json
  [
    { "id": "seed-nmap", "pattern": "Nmap", "comment": "scanner", "created_at": "2026-01-01T00:00:00Z" }
  ]
  ```
  `comment` is omitted when empty.
- **Errors:** `500` (text/plain) on a database error.

### `POST /api/v1/security/blocked-ua`
Adds a pattern. This always **creates** a new row: any `id` in the body is ignored and a new UUID is assigned. There is no update endpoint; delete and re-add instead.
- **Request body** (JSON, `config.BlockedUserAgent`):

  | Field | Type | Notes |
  |---|---|---|
  | `pattern` | string | **required**; trimmed; must be non-empty and contain no control characters (newline, tab, …) |
  | `comment` | string | optional |

  ```json
  { "pattern": "masscan", "comment": "scanner" }
  ```

- **Response:** `200` with the stored row, including its new `id` and `created_at`.
- **Errors (text/plain):** `400` for malformed JSON, `pattern required`, or `pattern must not contain control characters`. `500` on a database error.

Duplicate patterns are accepted in the database. They are de-duplicated when the map file is generated.

### `DELETE /api/v1/security/blocked-ua/{id}`
Deletes a pattern. Seeded patterns have ids like `seed-nmap`.
- **Path params:** `id`.
- **Response:** `204`, no body.
- **Errors (text/plain):** `404` (`not found`) for an unknown id. `500` on a database error.

## GeoIP

### `GET /api/v1/geoip/lookup`
Resolves the country for one IP address with the configured provider (`ipinfo` or `maxmind`). Results from the configured provider are stored in, and served from, the in-memory TTL cache (`geoip_cache_ttl`).
- **Query params:**
  - `ip` (required): an IPv4 or IPv6 address.
  - `nocache` (optional): `1` evicts this IP from the cache before the lookup, which forces a fresh provider query. The fresh answer is cached again.
  - `probe_mmdb_path` (optional): an absolute path to a `.mmdb` file on the appliance. For this request only, it overrides the settings with `geoip_provider=maxmind` and `geoip_mmdb_path=<path>`. The database is opened just for the lookup and closed afterwards. The result is neither read from nor written to the cache, and the configured reader is not replaced. Use it to check a path before saving settings.
- **Response:** `200`:

  ```json
  { "ip": "8.8.8.8", "country": "US", "cached": false }
  ```

  `country` is the code returned by the provider. `cached` is true only when the answer came from the cache.
- **Errors (text/plain):** `400` with `ip query parameter required`, or `invalid ip`. `502` when the provider lookup fails, for example when the MMDB cannot be opened, ipinfo is unreachable or rate-limited, or the GeoIP runtime is not initialized. With ipinfo, a lookup can take several seconds (rate limit plus an HTTP timeout of up to 15 s).

### `GET /api/v1/geoip/stats`
Returns counters for the GeoIP lookup cache.
- **Response:** `200`:

  ```json
  { "size": 128, "hits": 5402, "misses": 311 }
  ```

  All fields are zero when the GeoIP runtime or its cache is not initialized.

### `GET /api/v1/geoip/providers`
Lists the supported providers and whether each can be used.
- **Response:** `200`, always two rows:

  ```json
  [
    { "name": "ipinfo", "available": true },
    { "name": "maxmind", "available": true, "mmdb_path": "/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb" }
  ]
  ```

  `ipinfo` is always `available: true`. `maxmind` is `available: true` when the configured `geoip_mmdb_path` is non-empty and points at an existing non-directory file. The file is not opened or validated. `mmdb_path` is the configured path and is omitted when empty.

### `POST /api/v1/geoip/reload`
Re-opens the MaxMind database in the API process and clears the lookup cache. Use it after replacing the `.mmdb` file in place.
- **Request body:** optional JSON `{"mmdb_path": "/path/to/file.mmdb"}`. When the body is empty or `mmdb_path` is absent or empty, the configured `geoip_mmdb_path` is used. The handler reads at most 4096 bytes; a longer body is cut off and then fails to parse.
- **Response:** `200` `{"status": "ok"}`.
- **Errors (JSON `{"error": "..."}`):**
  - `400` `geoip_provider is not maxmind`: the configured provider is not `maxmind`. This is checked before the body is read.
  - `400` for a malformed JSON body.
  - `400` `geoip_mmdb_path is empty`: no path in the body or in the settings.
  - `502`: the database could not be opened or reloaded.

An `mmdb_path` that differs from the configured `geoip_mmdb_path` is loaded, but the runtime keys its reader on the configured path, so normal lookups do not use it. Point `geoip_mmdb_path` at the file instead.

### `POST /api/v1/geoip/database`
Uploads and installs a MaxMind GeoLite2 (or compatible) database. This route is **exempt from the global 4 MiB body limit** and applies its own cap.
- **Request body:** the **raw file bytes** (send `Content-Type: application/octet-stream`; the header is not checked). This is not multipart/form-data. Two formats are accepted, detected from the content (gzip magic `1f 8b`) and never from a file name:
  - a plain `.mmdb` file
  - a MaxMind `.tar.gz` archive. The first regular-file member whose name ends in `.mmdb` (case-insensitive) is extracted. Other members are skipped.

  **Limits:** the request body is capped at **128 MiB** (`geoip.MaxMMDBBytes`, enforced as 128 MiB + 1 byte). The extracted database is also capped at 128 MiB. Empty input is rejected.

  ```sh
  curl --data-binary @GeoLite2-Country.tar.gz \
       -H 'Content-Type: application/octet-stream' \
       https://<host>:8443/api/v1/geoip/database   # plus session/CSRF headers
  ```

- **Processing:**
  1. Uploads are serialized: only one install runs at a time.
  2. The file is written to a temporary file in `<state>/geoip/`.
  3. The file is validated. It must open as a MaxMind DB, its `database_type` must contain `country` or `city`, and a lookup of `8.8.8.8` must return a country.
  4. The file is renamed atomically to `<state>/geoip/<database_type>.mmdb`. The name falls back to `GeoLite2-Country.mmdb` when the type is unsafe as a file name. The destination is never taken from the request.
  5. If `geoip_provider` is `maxmind` **and** `geoip_mmdb_path` equals the installed path, the live reader is hot-swapped and the cache cleared (`reloaded: true`). Otherwise the file is stored but not activated, and `activate_hint` explains what to change.

  A rejected upload leaves the existing database untouched. A successful install records the audit action **`geoip_database_uploaded`**, with `mmdb_path`, `database_type`, `build_epoch`, `size_bytes`, `node_count` and `reloaded`.
- **Response:** `200`:

  ```json
  {
    "path": "/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb",
    "database_type": "GeoLite2-Country",
    "build_epoch": "2026-10-14T00:00:00Z",
    "node_count": 1234567,
    "ip_version": 6,
    "size_bytes": 9876543,
    "probe_ip": "8.8.8.8",
    "probe_country": "US",
    "reloaded": false,
    "activate_hint": "set geoip_provider=maxmind and geoip_mmdb_path=/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb, then save settings"
  }
  ```

  `activate_hint` is omitted when `reloaded` is true.
- **Errors (JSON `{"error": "..."}`):**
  - `400`: the payload is not a usable database. Causes include empty input, a bad gzip/tar stream, an archive without a `.mmdb` member, a file that is not a MaxMind DB, a database type without country data, or a failed probe lookup.
  - `413`: the request body or the extracted database is over 128 MiB.
  - `500`: the GeoIP directory or its files could not be created or written.
  - `502` `database installed but reload failed: ...`: the file was installed, but the hot-swap failed. The body then also contains `mmdb_path`.

## CrowdSec

All CrowdSec endpoints talk to the CrowdSec Local API (LAPI). The URL and key are resolved as follows:

- **URL:** `CROWDSEC_LAPI_URL` from the environment (`/etc/easy-waf/easy-waf.env`) wins over the `crowdsec_lapi_url` setting. The default is `http://127.0.0.1:8080/`.
- **Key:** `CROWDSEC_LAPI_KEY` from the environment wins over the stored `crowdsec_lapi_key`. It is sent as `X-Api-Key`.

The URL must pass the LAPI destination allowlist (by default only `http://127.0.0.1:8080` and `http://[::1]:8080`; extra origins come from `CROWDSEC_LAPI_ALLOWED_ORIGINS`). A URL that fails this check is reported as `crowdsec lapi url rejected: <reason>`; how each endpoint reports it is listed below. Redirects from LAPI are refused.

### `GET /api/v1/integrations/crowdsec`
Checks whether LAPI answers by sending `GET /v1/watchers/login` to it.
- **Response:** always `200`:

  ```json
  { "reachable": true, "last_message": "http 405" }
  ```

  `reachable` means only that LAPI answered with a non-redirect HTTP response. It does **not** check the bouncer key: a `401` or `403` (bad or missing key) still counts as reachable, with `last_message` showing the status (`http 403`). Use `GET /integrations/crowdsec/decisions` to confirm the key works. `reachable` is false when there is a connection error (`last_message` holds the error), when LAPI redirects (`lapi redirect refused`), or when the URL is rejected (`crowdsec lapi url rejected: ...`). `last_message` is omitted when empty.

### `GET /api/v1/integrations/crowdsec/decisions`
Returns the active decisions by sending `GET /v1/decisions?limit=100` to LAPI.
- **Response:** `200`, with LAPI's JSON body **passed through verbatim** (`Content-Type: application/json`). This is CrowdSec's decision array; its fields (`id`, `value`, `type`, `duration`, `scenario`, `origin`, ...) are defined by CrowdSec, not by easy-waf. CrowdSec answers `null` rather than `[]` when there are no decisions.
- **Errors:** `502` (JSON) `{"error": "..."}` when the LAPI URL is rejected, LAPI is unreachable, refuses with a redirect, returns a non-2xx status (`crowdsec lapi decisions: http 403`), or sends more than 1 MiB (`crowdsec lapi decisions: response exceeds 1048576 bytes`).

### `POST /api/v1/integrations/crowdsec/decisions`
Adds a manual decision for a single IP by sending `POST /v1/decisions` to LAPI. The request is a one-element array with `scope: "Ip"` and `origin: "easy-waf"`, and `reason` is sent as `scenario`. On success, records the audit action **`crowdsec.decision_added`** with `ip`, `type`, `duration` and `reason`.
- **Request body** (JSON, `crowdsec.AddDecisionRequest`):

  | Field | Type | Notes |
  |---|---|---|
  | `ip` | string | **required**; a single IPv4/IPv6 address (no CIDR) |
  | `type` | string | default `ban`. `whitelist` is handled specially. Other values are passed to LAPI unchecked |
  | `duration` | string | see the mapping below; other values (for example `30m`) are passed through unchanged |
  | `reason` | string | default `manual ban from UI` (`manual allowlist from UI` for `whitelist`) |

  Duration mapping: an empty value or `24h` becomes `24h`. `1h` and `4h` are unchanged. `7d` and `168h` become `168h`. `permanent` becomes `876000h`. For `type: whitelist`, an empty value, `permanent` or `876000h` becomes `876000h`.

  ```json
  { "ip": "203.0.113.50", "type": "ban", "duration": "168h", "reason": "manual: credential stuffing" }
  ```

- **Response:** `200` `{"status": "ok"}`.
- **Errors:**
  - `400` (text/plain) for malformed JSON.
  - `400` (JSON) when `ip` is empty or not a valid IP address (`crowdsec: invalid IP address: ...`). This is checked first.
  - `502` (JSON) when the LAPI URL is rejected, LAPI is unreachable, redirects, or returns non-2xx (for example `crowdsec lapi add decision: http 403` with a bad key).

### `DELETE /api/v1/integrations/crowdsec/decisions/{id}`
Deletes one decision by sending `DELETE /v1/decisions/{id}` to LAPI. On success, records the audit action **`crowdsec.decision_deleted`** with `decision_id`.
- **Path params:** `id`, the LAPI decision id from the decisions list. It is URL-path-escaped before being forwarded.
- **Response:** `204`, no body. LAPI 200 and 204 both count as success.
- **Errors (JSON):** `400` `missing decision id`. `404` when LAPI answers 404 (`crowdsec: decision not found`). `502` for every other failure: rejected URL, unreachable, redirect, or another non-2xx status.

## Fail2Ban

All Fail2Ban endpoints run `fail2ban-client` through the privileged host broker (`easy-waf-hostd`), never directly. Each `fail2ban-client` call has a 12-second timeout.

### `GET /api/v1/integrations/fail2ban`
Pings the daemon, lists its jails, and fetches the banned IPs of each jail. This runs `ping`, then `status`, then `status <jail>` for each jail.
- **Response:** `200`:

  ```json
  {
    "status": { "installed": true, "running": true, "message": "pong" },
    "jails": [
      { "name": "sshd", "banned_ips": ["198.51.100.23", "203.0.113.9"] },
      { "name": "recidive", "banned_ips": [] }
    ]
  }
  ```

  - `jails` is `[]` when the daemon has no jails, and `banned_ips` is `[]` when a jail has no bans.
  - If a single jail's status fails, that jail is still listed, with `banned_ips: []`.
  - If fail2ban is not installed: `200` with `status.installed: false`, `status.message: "fail2ban: fail2ban-client not found"`, `jails: []`.
  - If it is installed but the daemon is not answering `pong`: `200` with `status.running: false`, the client output in `status.message`, and `jails: []`.
- **Errors:** `502` (JSON) `{"error": "...", "status": {...}}` when the `status` command fails after a successful ping. The `status` object has the same shape as above, and its `message` holds the command output.

### `GET /api/v1/integrations/fail2ban/jails/{jail}`
Returns the banned IPs of one jail (`fail2ban-client status <jail>`).
- **Path params:** `jail`, matching `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$` after trimming.
- **Response:** `200` `{"name": "sshd", "banned_ips": ["198.51.100.23"]}`. `banned_ips` is `[]` when the jail has no bans or the output could not be parsed.
- **Errors (JSON):** `400` `fail2ban: invalid jail name`. `502` when the command fails. This covers an unknown jail, a stopped daemon, fail2ban not being installed and broker errors, and the message includes the client output.

### `POST /api/v1/integrations/fail2ban/unban`
Removes one IP from a jail's ban list (`fail2ban-client set <jail> unbanip <ip>`). On success, records the audit action **`fail2ban.unban`** with `jail` and `ip`.
- **Request body** (JSON):

  | Field | Type | Notes |
  |---|---|---|
  | `jail` | string | **required**; same pattern as above |
  | `ip` | string | **required**; a single IPv4/IPv6 address |

  ```json
  { "jail": "sshd", "ip": "203.0.113.1" }
  ```

- **Response:** `200` `{"status": "ok"}`.
- **Errors:** `400` (text/plain) for malformed JSON. `400` (JSON) `fail2ban: invalid jail name` or `fail2ban: invalid IP address`. `502` (JSON) `fail2ban unban: <client output>` when the command fails, for example for an unknown jail or an IP that is not banned.

## Health and metrics

These three routes are mounted outside `/api/v1` and need no session JWT.

### `GET /health`
Liveness probe. It returns as soon as the process can serve HTTP and does not touch the database. It is exempt from the management source-CIDR ACL.
- **Response:** `200` with `{"status":"ok"}`.
- **Errors:** none of its own. Only `GET` is registered, so the router rejects other methods with `405`.

### `GET /health/ready`
Readiness probe. It pings PostgreSQL with a 2-second timeout. Like `/health`, it is exempt from the management ACL, so it never returns error details.
- **Response:** `200` with `{"status":"ok","database":"ok"}`.
- **Errors (JSON):**
  - `503` with `{"status":"unavailable","database":"unreachable"}` when the ping fails or times out.
  - `503` with `{"status":"unavailable","database":"not configured"}` when the server has no store.

### `GET /metrics`
Prometheus text exposition for the `easy_waf_*` series. The series cover HAProxy frontend request totals and rates, backend sessions and up/down, certificate days remaining, CrowdSec decision count, IP blacklist entry counts, applications by security mode, and apply/apply-error counters. The control plane refreshes the HAProxy-derived values in the background (about every 15 s), not on each scrape. See `metrics.PrometheusExporter` in `internal/metrics/prometheus.go`.

Unlike `/health`, this route **is** subject to the management ACL. It does not accept a session JWT.
- **Auth:** none by default. When the `EASY_WAF_METRICS_TOKEN` environment variable is set (at least 16 characters, read at process start), the request must send `Authorization: Bearer <token>`. A shorter token is ignored with a log line, which leaves the endpoint open.
- **Response:** `200`, Prometheus text format.
- **Errors (text/plain):**
  - `404` (`404 page not found`) when `prometheus_enabled` is `false` in settings, which is the default, or when no exporter is configured.
  - `401` (`unauthorized`) when a metrics token is configured and the bearer value is missing or wrong.
  - `405` (`method not allowed`) for non-`GET` methods. In practice a `POST`/`PUT`/`PATCH`/`DELETE` without `X-Requested-With` is rejected earlier by the CSRF middleware with `403` JSON.

## Host management

The `/api/v1/host/*` routes manage the appliance host itself (network, firewall, services, packages, power, local users, network diagnostics). They do not run commands directly: each call goes through the privileged host broker (`easy-waf-hostd`). Network and firewall changes have a rollback flow: an `apply` returns a `token` and `expires_at`, and the change is reverted automatically unless it is confirmed with `commit` before it expires. See [HOST-API.md](HOST-API.md) for request and response details.

| Method and path | Purpose |
|---|---|
| `GET /api/v1/host/network` | Current interfaces and addresses (`ip -j` snapshot) |
| `PUT /api/v1/host/network/netplan` | Write and apply netplan YAML immediately, without rollback |
| `POST /api/v1/host/network/netplan/apply` | Apply netplan YAML with automatic rollback; returns a token |
| `POST /api/v1/host/network/netplan/commit` | Confirm a pending netplan apply by token |
| `GET /api/v1/host/firewall` | nftables status and ruleset |
| `PUT /api/v1/host/firewall/ruleset` | Validate, install and apply the managed nftables ruleset immediately, without rollback |
| `POST /api/v1/host/firewall/apply` | Load the installed managed ruleset, without rollback |
| `POST /api/v1/host/firewall/apply-rollback` | Apply a ruleset with automatic rollback; returns a token |
| `POST /api/v1/host/firewall/commit` | Confirm a pending firewall apply by token |
| `GET /api/v1/host/services` | List the allowlisted systemd units and their state |
| `POST /api/v1/host/services/{unit}/{action}` | Run `start`, `stop`, `restart`, `reload`, `enable`, `disable` or `try-restart` on an allowlisted unit |
| `GET /api/v1/host/journal` | Read journal lines (`unit`, `since`, `until`, `priority`, `lines`) |
| `GET /api/v1/host/updates` | List available package updates |
| `POST /api/v1/host/updates/update` | Run `apt update` |
| `POST /api/v1/host/updates/upgrade` | Run `apt upgrade` |
| `POST /api/v1/host/updates/upgrade/stream` | Run `apt upgrade`, streaming its output as NDJSON |
| `GET /api/v1/host/updates/upgrade/log` | Output of the last upgrade (text/plain) |
| `GET /api/v1/host/updates/upgrade/status` | Whether an upgrade is running |
| `GET /api/v1/host/updates/autoremove/preview` | Packages `apt autoremove` would remove |
| `POST /api/v1/host/updates/autoremove/stream` | Run `apt autoremove`, streaming its output |
| `POST /api/v1/host/updates/clean` | Run `apt clean` |
| `GET /api/v1/host/disk` | Disk usage |
| `POST /api/v1/host/power/reboot` | Reboot the host |
| `POST /api/v1/host/power/shutdown` | Power off the host |
| `GET /api/v1/host/users` | List local accounts (uid ≥ 1000, plus `root`) |
| `POST /api/v1/host/users` | Create a local user |
| `DELETE /api/v1/host/users/{name}` | Delete a local user |
| `PUT /api/v1/host/users/{name}/ssh-keys` | Replace a user's SSH authorized keys |
| `POST /api/v1/host/diagnostics/ping` | Ping a target from the host |
| `POST /api/v1/host/diagnostics/trace` | Traceroute to a target from the host |
