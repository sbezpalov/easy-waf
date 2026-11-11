# Monitoring (Prometheus / Grafana)

The management API (`easy-waf-api`) can expose a **Prometheus text exposition** endpoint at **`GET /metrics`**.

## Security

- **Disabled by default** (`prometheus_enabled: false` in global settings).
- When enabled, **`/metrics` is not protected by JWT** (Prometheus scrapes rarely support Bearer tokens). It **is** protected by the same **`management_allowed_cidrs`** ACL as the UI and `/api/v1` (see `docs/SECURITY.md`).
- **`/health`** remains reachable for probes regardless of CIDR list; **`/metrics`** does not bypass the ACL.
- **`/health`** only says the API process answers. **`/health/ready`** (same exemptions) also pings PostgreSQL and returns **503** `{"status":"unavailable","database":"unreachable"}` when it cannot — point load balancers and uptime checks at it. The edge keeps serving on its last applied config while the database is down; only changes and renewals stop.
- `easy-waf-api` and `easy-waf-acmed` restart every 5s without a start limit, so they come back on their own once a late or remote PostgreSQL is reachable.

Enable the toggle in the UI (**Settings → Monitoring**) or `PATCH /api/v1/settings` with `{"prometheus_enabled": true}`.

## Prometheus scrape configuration

Scrape the **management HTTPS** listener from an address allowed by `management_allowed_cidrs` (often a private network or VPN). Cleartext HTTP is disabled by default and should only be used when an explicit legacy listener is configured.

Example `prometheus.yml` fragment:

```yaml
scrape_configs:
  - job_name: easy-waf
    scrape_interval: 30s
    scheme: https
    metrics_path: /metrics
    static_configs:
      - targets:
          - "192.168.1.10:8443"
    tls_config:
      insecure_skip_verify: true # bootstrap self-signed cert only
```

Replace `insecure_skip_verify` with a trusted `ca_file` and `server_name` after installing a management certificate that covers the scrape hostname. When Prometheus runs on the appliance, `127.0.0.1:8443` is also available in both installer defaults; copy the required CA/certificate to a Prometheus-readable path instead of granting access to the Easy Home WAF secrets directory.

## Grafana

Import **`configs/grafana/easy-waf-dashboard.json`** (Dashboards → Import → Upload JSON). Adjust datasource UID if yours differs from `prometheus`.

## Certificate expiry

Renewal starts 30 days before expiry and is silent when it fails, so alert on it. Without Prometheus, the dashboard shows a warning, and `easy-waf-acmed` writes one to its journal once a day (`journalctl -u easy-waf-acmed -g WARNING`), for a certificate that failed to renew or has fewer than 21 days left. Nothing is pushed to you.

```yaml
- alert: EasyWafCertificateNotRenewing
  expr: easy_waf_certificate_days_remaining < 21
  for: 1h
  annotations:
    summary: "{{ $labels.domain }}: {{ $value }} days left and not renewed"
```

## Notifications

Settings → Notifications (or `PATCH /api/v1/settings`) sends operational events to a webhook (`notify_webhook_url`), a Telegram chat (`notify_telegram_chat_id` + `notify_telegram_bot_token`), or both. **Send test** (`POST /api/v1/notify/test`) checks the channels.

| Event | Severity | When |
|-------|----------|------|
| `apply_failed` | critical | Any HAProxy apply fails (from the panel, a certificate renewal or a feed refresh). The edge keeps its previous configuration. |
| `backend_down` / `backend_up` | critical / info | A server's health check state changes between `UP` and `DOWN` and stays so for two reads 30 s apart. Only servers with health checks are watched. |
| `blocked_spike` | warning | The frontends refused at least `notify_blocked_spike_threshold` requests (`dreq`) within 5 minutes; at most once per 30 minutes. `0` turns it off. |
| `certificate_attention` | warning | Once a day from `easy-waf-acmed` (see [ACME.md](ACME.md)). |

The webhook gets `{"source":"easy-waf","host":...,"time":...,"event":...,"severity":...,"title":...,"text":...}`; `certificate_attention` keeps its older body `{source, event, certificates}`. Telegram gets `title` and `text` as one message. Backend and spike events come from `easy-waf-api` polling the HAProxy stats socket every 30 s, so they stop while the API is down. Neither the URL nor the token is logged.

## Metrics reference

All names use the `easy_waf_` prefix.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `easy_waf_haproxy_frontend_requests_total` | Counter | `frontend` | Increments by the delta of HAProxy `TotalReqHint` between internal 15s refreshes (approximation of new responses since last poll). |
| `easy_waf_haproxy_frontend_req_rate` | Gauge | `frontend` | Current HAProxy frontend request rate (`rate` from `show stat`). |
| `easy_waf_haproxy_backend_sessions_current` | Gauge | `backend` | Current backend sessions (`scur`). |
| `easy_waf_haproxy_backend_up` | Gauge | `backend` | `1` if aggregate backend health is not `down`, else `0`. |
| `easy_waf_certificate_days_remaining` | Gauge | `domain`, `mode` | Days until `NotAfter` when known (per certificate row from the summary builder). |
| `easy_waf_crowdsec_decisions_total` | Gauge | — | Length of the last LAPI decisions sample (capped at 100); not total decisions in CrowdSec. |
| `easy_waf_ipbl_entries_total` | Gauge | `type=local\|external` | **local**: enabled local CIDR rows in DB. **external**: count of **enabled external feed URLs** configured (not merged line count from downloads). |
| `easy_waf_applications_total` | Gauge | `mode` | Applications grouped by `security.mode`. |
| `easy_waf_apply_total` | Counter | — | Successful applies started by the API: `POST /api/v1/apply` and the apply after each change. Applies by `easy-waf-acmed` are not counted. |
| `easy_waf_apply_errors_total` | Counter | — | Failed applies, counted the same way. |

Internal refresh cadence for HAProxy stats, certificates, apps, CrowdSec sample, and IPBL counts: **15 seconds** (independent of scrape interval).
