# Easy WAF management MCP

`easy-waf-mcpd` exposes Easy WAF diagnostics over Streamable HTTP at `/mcp`.
It pins MCP protocol revision `2025-11-25` and serves stateless requests.
See the [transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
and [ADR 0002](adr/0002-mcp-server.md).

| Tool | Response |
| --- | --- |
| `status` | Management API and PostgreSQL readiness |
| `edge_status` | Saved and applied generations and managed HAProxy artifact identity |
| `haproxy_check` | Runtime statistics availability, sample time and counts of frontend and backend states |
| `list_applications` | Publication names, hostnames, profiles and enabled or maintenance state |
| `describe_application` | Given an `id` from `list_applications`, check publication, DNS, TLS, applied routing and backend availability |
| `certificate_expiry` | Recorded expiry dates, days remaining and issuance status |
| `config_revisions` | The latest 30 revisions, with the live revision marked when it can be observed |
| `geoip_status` | Configured provider, enablement and cache counters |
| `why_blocked` | Given one `ip`, report saved local IP-list matches, cached country and current CrowdSec IP or range bans |
| `recent_events` | Up to 30 management attempts in the last 24 hours, with UTC timestamps, fixed categories and HTTP status codes |

`why_blocked` reports evidence from each source independently. A `null` list
count means the database lookup was unavailable. CrowdSec states distinguish
`present`, `absent`, `not_configured` and `unavailable`. GeoIP uses the
existing cache. Request-level outcomes, Fail2Ban and external IP lists are
outside this check. [CrowdSec LAPI query mode](https://docs.crowdsec.net/docs/local_api/bouncers/)

`recent_events` covers publication, certificate, edge configuration and
protection changes recorded in the management audit. It includes failed
attempts and indicates whether more matching rows exist in the window.
Request paths, source IPs, usernames, raw audit details and HAProxy traffic
are excluded.

`haproxy_check` uses the same short-lived stats sample as the dashboard.
It reports aggregate runtime states across the configured HAProxy instance
and omits proxy names, socket paths and command output. Configuration syntax
validation remains part of Apply and the operator CLI.

## Enable the packaged service

The package installs `easy-waf-mcpd.service` without enabling it. Before
enabling it, configure the same randomly generated `EASY_WAF_MCP_API_TOKEN`
in the management API's environment and in a root-owned `/etc/easy-waf-mcp.env`
with mode `0600`. Restart `easy-waf-api` after changing its environment.
In `easy-waf-mcp.env`, also set `EASY_WAF_MCP_LISTEN` and a distinct client token
`EASY_WAF_MCP_TOKEN`.

Install the management TLS trust certificate as `/etc/easy-waf-mcp-ca.pem`,
owned by root with mode `0644`. For the self-signed management listener, copy
the public `management.crt`.
Set `EASY_WAF_MCP_API_URL` if the management HTTPS origin differs from the
default. The unit's dynamic user can read the public certificate and has no
direct access to the appliance configuration and state directories.
Repeat the certificate copy and restart the MCP service when the trusted
certificate changes. Keep these two service files with your private appliance
backups. Restore the environment file with its root ownership and mode `0600`.

Enable with `sudo systemctl enable --now easy-waf-mcpd.service` and check
`systemctl status easy-waf-mcpd.service`. To disable the packaged service,
use `sudo systemctl disable --now easy-waf-mcpd.service`. Before downgrading
to a release without MCP, disable the service first.

When migrating a script-installed unit to the package, the installer
preserves existing persistent or runtime enablement. It queues a restart
only when MCP was already active.

The post-install and upgrade smoke test checks for the absence of a TCP
listener when the unit is disabled and inactive. For an active unit it checks
that the running binary matches the installed binary and that exactly one TCP
listener belongs to its main process, bound to loopback. This check needs root
to inspect socket ownership.

## Run from source

1. Build the daemon with `go build ./cmd/easy-waf-mcpd`.
2. Set `EASY_WAF_MCP_API_TOKEN` in the management API's environment and restart
   `easy-waf-api`. Keep the loopback source in the management ACL. Use a distinct
   random token of at least 32 characters.
3. Supply the daemon with the settings below, using a private environment file
   or your service manager, then run the binary.

| Setting | Value |
| --- | --- |
| `EASY_WAF_MCP_LISTEN` | Loopback IP and port, for example `127.0.0.1:8446`. Unset keeps the daemon off. |
| `EASY_WAF_MCP_TOKEN` | A separate random client bearer of at least 32 characters. |
| `EASY_WAF_MCP_API_TOKEN` | The same diagnostics token configured for `easy-waf-api`. |
| `EASY_WAF_MCP_API_URL` | Management HTTPS origin on a loopback IP. Default `https://127.0.0.1:8443`. |
| `EASY_WAF_MCP_API_CA_FILE` | PEM trust certificate for the management HTTPS listener. For the default self-signed certificate, use the public `management.crt`, with no private key. |

Configure your MCP client for Streamable HTTP, endpoint
`http://127.0.0.1:8446/mcp` and header `Authorization: Bearer <client token>`.

MCP tool errors from the management API include a `code` and, when the API
returned an HTTP error, `http_status`. After an upgrade or restore, use
`status` to distinguish these outcomes:

| Code | What to check locally |
| --- | --- |
| `api_certificate_rejected` | The management certificate, its IP subject alternative name and the MCP trust file |
| `api_token_rejected` | The API and MCP service copies of the diagnostics token |
| `api_access_forbidden` | Direct loopback HTTPS and the management ACL |
| `api_not_found` | The configured API origin and whether diagnostics routes are enabled. For `describe_application`, also check the application ID |
| `api_unreachable` or `api_timeout` | Whether the management API is running and reachable at the configured loopback origin |

A reachable API with PostgreSQL unavailable returns the database readiness
message from `status`. Transport and HTTP errors omit URLs and raw error
details.
For a remote client, use SSH local forwarding to the appliance's loopback
listener. The daemon accepts loopback connections with a local Host header
and refuses browser requests carrying an Origin header.

To disable the feature, stop the daemon and remove `EASY_WAF_MCP_LISTEN`.
Remove `EASY_WAF_MCP_API_TOKEN` and restart `easy-waf-api` to remove the
diagnostics routes as well. Calls through those routes appear as
`mcp.diagnostics` in the management audit log.
