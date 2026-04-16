# Monitoring (Prometheus / Grafana)

The management API (`easy-waf-api`) can expose a **Prometheus text exposition** endpoint at **`GET /metrics`**.

## Security

- **Disabled by default** (`prometheus_enabled: false` in global settings).
- When enabled, **`/metrics` is not protected by JWT** (Prometheus scrapes rarely support Bearer tokens). It **is** protected by the same **`management_allowed_cidrs`** ACL as the UI and `/api/v1` (see `docs/SECURITY.md`).
- **`/health`** remains reachable for probes regardless of CIDR list; **`/metrics`** does not bypass the ACL.

Enable the toggle in the UI (**Settings → Monitoring**) or `PATCH /api/v1/settings` with `{"prometheus_enabled": true}`.

## Prometheus scrape configuration

Scrape the **management HTTP or HTTPS** listener from an address allowed by `management_allowed_cidr` (often a private network or VPN).

Example `prometheus.yml` fragment:

```yaml
scrape_configs:
  - job_name: easy-waf
    scrape_interval: 30s
    metrics_path: /metrics
    static_configs:
      - targets:
          - "192.168.1.10:8000"
        # Or TLS management port:
        # - "192.168.1.10:8443"
    # tls_config:
    #   insecure_skip_verify: true   # only if using bootstrap self-signed management cert
```

## Grafana

Import **`configs/grafana/easy-waf-dashboard.json`** (Dashboards → Import → Upload JSON). Adjust datasource UID if yours differs from `prometheus`.

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
| `easy_waf_apply_total` | Counter | — | Successful `POST /api/v1/apply` completions. |
| `easy_waf_apply_errors_total` | Counter | — | Failed apply attempts (same route, error response). |

Internal refresh cadence for HAProxy stats, certificates, apps, CrowdSec sample, and IPBL counts: **15 seconds** (independent of scrape interval).
