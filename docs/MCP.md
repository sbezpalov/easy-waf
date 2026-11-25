# Easy WAF management MCP

`easy-waf-mcpd` exposes Easy WAF diagnostics over Streamable HTTP at `/mcp`.
It pins MCP protocol revision `2025-11-25` and serves stateless requests.
See the [transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
and [ADR 0002](adr/0002-mcp-server.md).

| Tool | Response |
| --- | --- |
| `status` | Management API and PostgreSQL readiness |
| `edge_status` | Saved and applied generations and managed HAProxy artifact identity |
| `list_applications` | Publication names, hostnames, profiles and enabled or maintenance state |
| `describe_application` | Given an `id` from `list_applications`, check publication, DNS, TLS, applied routing and backend availability |
| `certificate_expiry` | Recorded expiry dates, days remaining and issuance status |
| `config_revisions` | The latest 30 revisions, with the live revision marked when it can be observed |
| `geoip_status` | Configured provider, enablement and cache counters |

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
For a remote client, use SSH local forwarding to the appliance's loopback
listener. The daemon accepts loopback connections with a local Host header
and refuses browser requests carrying an Origin header.

To disable the feature, stop the daemon and remove `EASY_WAF_MCP_LISTEN`.
Remove `EASY_WAF_MCP_API_TOKEN` and restart `easy-waf-api` to remove the
diagnostics routes as well. Calls through those routes appear as
`mcp.diagnostics` in the management audit log.
