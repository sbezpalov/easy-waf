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
