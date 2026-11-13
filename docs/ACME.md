# ACME / Let's Encrypt

## Modes

- **Staging**: Let's Encrypt staging URL; avoids rate limits during testing.
- **Production**: live Let's Encrypt.

**A fresh appliance issues from staging.** `acme_staging` defaults to **`true`** (`internal/config/types.go`), and the effective mode is `certificate.staging || settings.acme_staging` — the global flag **overrides** a per-certificate `staging: false`. Turn `acme_staging` off in global settings before you expect trusted certificates.

## HTTP-01

Requires HAProxy on port **80** with a frontend rule for `/.well-known/acme-challenge/`. **Lego** writes token files under **`${ACMEWebrootPath}/.well-known/acme-challenge/`** (default `${EASY_WAF_STATE_DIR}/acme/webroot/...`).

The generated HAProxy config routes those URLs to **`bk_acme` → `127.0.0.1:8089`**. **`easy-waf-api`** listens on that loopback address and serves files from the webroot so HAProxy health checks succeed.

**To move it, change the setting, not the environment.** The address is the global
setting **`acme_internal_http`** (default `127.0.0.1:8089`), and both sides read
it: `easy-waf-api` listens on it, and the renderer writes it into the `bk_acme`
backend. It must be `ip:port` — a hostname is refused, because a `server` line
naming a host would need a `resolvers` section the renderer only emits for
application backends.

```bash
# STEP_UP_TOKEN is returned by POST /api/v1/auth/confirm and is valid for
# password-confirmed operations for 5 minutes.
curl -X PATCH https://127.0.0.1:8443/api/v1/settings \
  -H "Content-Type: application/json" -H "X-Requested-With: XMLHttpRequest" \
  -H "Authorization: Bearer $STEP_UP_TOKEN" \
  -d '{"acme_internal_http":"127.0.0.1:9090"}'
```

`EASY_WAF_ACME_INTERNAL_HTTP` (see `configs/defaults/easy-waf.env.example`) still
works for **switching the helper off** — `0` / `off` / `false` — and unset means
"use the setting". Using it to move the listener moves only the listener: the
rendered backend follows the setting, so the two disagree and HTTP-01 fails on a
backend nobody looks at. `easy-waf-api` logs a warning naming both addresses when
it starts in that state.

## When something needs attention

A failed issuance or renewal, or fewer than 21 days left, is shown on the dashboard and once a day in the `easy-waf-acmed` journal. Set **`notify_webhook_url`** (`PATCH /api/v1/settings`, or Settings → Certificate notifications) to also POST a JSON body `{source, event, certificates}` to one URL. Point it at ntfy, a mail bridge, or a Telegram bridge. The worker does not follow redirects, refuses link-local addresses, and does not log the URL. The same warning also goes to Telegram when `notify_telegram_chat_id` and `notify_telegram_bot_token` are set (see [MONITORING.md](MONITORING.md#notifications)); email is not built in.

Real Let's Encrypt issuance still has to be checked on a host that owns the domain. See [ACCEPTANCE.md](ACCEPTANCE.md).

## DNS-01

Implemented via **Lego** (`easy-waf-acmed`): `dns_provider` is one of `cloudflare`, `cloudns` (default when empty), `route53`, `webhook` (Lego `httpreq`). Credentials live in an env file referenced by `dns_credentials_env_file` — see [DNS01.md](DNS01.md) and `configs/examples/dns-*.env.example`.

The file must be **readable by `easy-waf`**, not root-only: `easy-waf-acmed` runs as `User=easy-waf` (`packaging/systemd/easy-waf-acmed.service`) and opens the file itself. Use `chown easy-waf:easy-waf` + `chmod 0600`: `0600 root:root` fails issuance with `dns env: … permission denied`.

### Split-DNS and propagation checks

After publishing the TXT record, Lego polls **recursive resolvers** until the challenge is visible publicly. If the appliance uses an **internal DNS forwarder** that does not expose the public TXT view, DNS-01 can hang or fail.

Set global **`acme_dns_resolvers`** to public resolvers, for example:

```json
{ "acme_dns_resolvers": ["1.1.1.1:53", "8.8.8.8:53"] }
```

Empty list = system resolver (`/etc/resolv.conf`). See [DNS.md](DNS.md).

## Renewal

- `easy-waf-acmed` runs a periodic loop (`EASY_WAF_ACME_TICK`, default 30s). Each tick it claims due rows with `FOR UPDATE SKIP LOCKED` (so two workers never issue the same certificate) and marks them `issuing`. A row is due when it is:
  - `pending` (new, or the operator pressed **Request issue** / **Retry now**);
  - `failed` and its `acme_next_attempt_at` has passed;
  - `ready`, ACME-managed and its `not_after` falls inside the renewal window;
  - `issuing` for more than an hour (a worker died mid-issuance).
- **Failures retry on their own** with exponential backoff: 10m, 20m, 40m, … capped at 24h (`internal/acme/retry.go`). `acme_attempts` counts consecutive failures; success or a manual request resets it. The certificate dashboard shows such rows as **failed** (red), with the error and the next retry time on hover — including a renewal that failed while the old certificate is still valid.
- On success the worker writes a validated `privkey.pem` / `fullchain.pem` pair into a fresh private `certs/<id>/generation-*` directory while holding the HAProxy apply lock. It commits those immutable paths, validity/status and a pending apply token in one PostgreSQL transaction. If the operator edited the row during issuance, the claim check rejects completion before writing the generation.
- During issuance a heartbeat refreshes the claim every five minutes. Before final touch/complete/failure, the worker stops and joins that heartbeat, including an in-flight database query and its claim-stamp update. A running heartbeat retains its own bounded 30-second query context through lifecycle cancellation; stopping does not abandon an ambiguous write or let it race finalization. Idle stop is prompt and repeated stop is safe.
- **Attempt ownership:** each HTTP-01/DNS-01 attempt runs in an owned child of the same `easy-waf-acmed` binary. The parent waits/reaps it before releasing the claim heartbeat or finalizing the row. Parent cancellation/deadline terminates the child (and its process group on Linux/macOS), with bounded inherited pipe waits. The parent keeps a private stdin control pipe open: its death/pipe closure terminates the child too. The child also enforces its own hard deadline, at most 45 minutes. This contains Lego steps that ignore context instead of leaving an Obtain goroutine running after a failed attempt. The service's first TERM lets the attempt finish within its budget; a second signal or hard deadline terminates it. No extra service, root privilege or listener is added; see [ADR 0009](adr/0009-acme-attempt-process.md).
- **Private result transport:** bounded, versioned stdin/stdout JSON carries options and the certificate/key, without putting PEMs or credentials in argv or temporary protocol files. The request is at most 64 KiB JSON plus a newline delimiter; captured results at most 4 MiB, and success requires a complete valid certificate/key pair. Malformed/duplicate/case-folded/contradictory protocol replies are failures, never success; raw reply bodies and SDK stderr are not journaled. Parent journal messages identify attempt start and final failure; bounded actionable SDK errors still reach the existing failed row/audit. Verbose SDK progress is discarded and cannot exhaust the certificate-result budget.
- **Timeout is an unknown external outcome:** stopping an attempt closes its live connections, but cannot undo a CA order already accepted or promise DNS cleanup. Hard termination may leave a TXT challenge or HTTP-01 token behind. The row reports failure with possible incomplete cleanup and uses the existing retry backoff; inspect the CA/provider and remove stale challenge records/tokens if needed. Existing live certificates are not replaced by partial/unverified results. Real public-CA issuance/cleanup acceptance remains manual.
- **The renewal window is a hardcoded 30 days** (`cmd/easy-waf-acmed/main.go`). The `acme_renewal_interval` setting (default 12h) is **not read by acmed** — changing it has no effect today.
- **Nothing is issued until `acme_email` is set** in global settings. Without it the worker logs `acmed: ACMEEmail not set in global settings — idle` once per tick and does nothing else. This is the first thing to check when certificates stay `pending`.
- On success: `engine.ApplyIfChanged` takes the committed generation live when needed. It snapshots pending tokens before rendering and acknowledges only those exact generations after success or verified no-change. Failed/cancelled apply or acknowledgement leaves work for a later tick/start; a concurrent renewal keeps its newer token. Applies are skipped when `EASY_WAF_ACME_SKIP_APPLY` is true (`1`, `true`, `yes`, `on`), preserving pending work. `0`, `false` and `off` mean "do not skip"; an unparseable value is treated as off and logged.
- Account private key is stored at `${EASY_WAF_STATE_DIR}/acme/account.pem` (Lego HTTP-01 webroot: `${ACMEWebrootPath}` / default `.../acme/webroot`).

On first use, the worker writes the account key to a private temporary file in
the same directory, syncs and closes it, then publishes it with a hard link that
cannot replace an existing destination. Concurrent issuers use the winning key;
an existing unreadable or malformed key fails issuance instead of being replaced.
The account directory must support regular-file hard links (the normal Ubuntu
local filesystems do); unsupported storage fails explicitly without a direct-write
fallback. Existing readable keys do not require a new publication.

Process termination before publication leaves the canonical path absent; after
publication it contains a complete key. A forced stop can leave a private
`.account.pem.tmp-*` staging file. It is never loaded as the account key and is
not removed automatically, since another issuer may still own it. Inspect and
remove abandoned stages only with issuance stopped; do not delete `account.pem`
to retry a failed issuance. This publication policy does not guarantee directory
entry durability after power loss; keep the account key in state backups.

## Certificate publication and recovery

Migration 027 adds `acme_apply_pending`, with one current publication token per
certificate and cascading deletion. A process dying before the ready transaction
commits leaves the previous paths intact; after commit, both new PEM files and
the pending apply intent already exist. No post-commit two-file rename remains.
A connection failure during commit is indeterminate, so the worker keeps the
generation rather than risking deletion of files referenced by a committed row.
Apply retries compare the generated edge artifacts and loaded certificate hashes,
so a crash after reload but before acknowledgement does not require another reload.
See [ADR 0010](adr/0010-acme-publication.md).

Existing certificate paths remain readable. The worker still consumes the old
`acme/apply-pending` marker on upgrade, clearing it after successful reconciliation;
new publications use PostgreSQL only. Allow the package's graceful worker restart
to finish: an already-running older worker still uses its old publication code.
Do not operate mixed worker versions as a steady state. This change does not
automatically repair old partially promoted `.pem.new` files or reconstruct a
previously corrupted pair; retain those files and inspect the certificate/key
and database metadata together before recovery.

Old and unreferenced generation directories are retained for recovery and matched
database/state restores. No automatic garbage collection is performed; do not
remove a generation merely because a newer one exists. Back up PostgreSQL and
the certificate state together. File contents are synced before publication, but
directory-entry durability under physical power loss is not guaranteed by this
change. Schema downgrade protection rejects older binaries after migration 027;
rollback requires the normal matched pre-upgrade database/state restore procedure,
tested on a copy first, rather than deleting the pending-work table.

## Multiple hostnames / one public IP

Each **certificate** is a separate row (DNS names in `primary_domain` / `san`). Each **application** sets `certificate_id` to the cert that covers its `public_host`. HAProxy uses a **single `crt-list`** on **:443** so **SNI** selects the right PEM while **Host** routes to the backend — see **TLS, SNI, and per-application certificates** in [ARCHITECTURE.md](ARCHITECTURE.md).

## HAProxy PEM layout

One file per certificate, and the generated `crt-list` carries exactly that one path per line — there is no separate `crt` + `key` form. The engine resolves it on apply (`internal/engine`):

- `fullchain_path` **and** `pem_key_path` set and both non-empty → concatenated into `${EASY_WAF_STATE_DIR}/certs/<id>/bundle.pem` (`internal/pemutil`). This is the ACME path.
- otherwise, `pem_crt_path` if set → used as-is, on the assumption that it already contains chain and key.
- otherwise → the certificate is **skipped** when the `crt-list` is built (`internal/haproxy/render.go`), which is why an incomplete certificate silently disappears from `:443` instead of failing loudly.
