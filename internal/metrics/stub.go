// Package metrics is reserved for HAProxy stats / CrowdSec counters (prompts.md §7.8, §5 Metrics).
//
// Roadmap: Unix socket or Prometheus scrape → per-app request counts, blocked requests, top IPs,
// country histogram, backend health — exposed via GET /api/v1/metrics/summary or Prometheus /metrics.
package metrics
