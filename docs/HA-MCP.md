# Expose Home Assistant MCP safely

**English** | [Русский](HA-MCP.ru.md)

Home Assistant can speak [MCP](https://modelcontextprotocol.io/) to a desktop
assistant. That endpoint is an API, not a web page: a client that can call it
can read state and, depending on the user you created, change it. Easy Home WAF
can publish it without publishing the rest of Home Assistant.

This is edge policy. It does not replace a locked-down Home Assistant user.

## What the `ha-mcp` profile does

Select profile `ha-mcp` and leave `path_policy` unset. The API stores this
preset (`profiles.HAMCPPathPolicy`):

| Control | Value |
|---------|--------|
| Allowlist | `/api/mcp`, `/mcp_server/sse`, `/auth`, `/.well-known/oauth-authorization-server` |
| Everything else | **404**. Profile block lists and `restricted_paths` still run, including on an allowed path |
| `/api/mcp` | `Authorization` must begin with `Bearer `, or the edge returns **401**. 20 requests / 10 s |
| `/mcp_server/sse` | server inactivity timeout 3600 s, 10 requests / 10 s. The edge does not check `Authorization` here |
| `/auth` | 40 requests / 10 s, so OAuth is not cut off by the tighter MCP limit |
| Application rate limit | 40 requests / 10 s (`rate_limit_burst` of the profile) |
| Backend `timeout server` | 3600 s |

A prefix matches that path and everything under it. `/api/mcp` allows
`/api/mcp/assist`. It does not allow `/api/mcp-other`.

`/.well-known/security.txt` stays blocked. The OAuth discovery document is a
different path and stays published.

An omitted `path_policy` on update keeps the stored one. Send
`"path_policy": {"mode": "default"}` when you want the `ha-mcp` timeouts
without the allowlist. The same object is returned by `GET /api/v1/profiles`
on the `ha-mcp` entry.

## Client timeout on HAProxy 2.8

Ubuntu 24.04 ships HAProxy 2.8. Its `http-request set-timeout` action changes
**server** and **tunnel** timeouts only. There is no per-request `timeout
client`.

When any application on a frontend asks for a client timeout (the preset asks
for 3600 s on `/mcp_server/sse`), that frontend's `timeout client` becomes the
longest value any of its applications asked for, and `timeout http-request 10s`
is set so an incomplete request is still aborted. Other hostnames on the same
port share that client timeout. Their own `timeout server` is unchanged, so a
quiet backend still stops at the profile server timeout.

Per-path **server** timeouts use `http-request set-timeout server` and apply
only to the matching prefix. The longest matching prefix wins.

## On Home Assistant

Do this on the Home Assistant host. Easy Home WAF cannot do it for you.

1. **Create a user that is not an administrator** and use only that user for
   the assistant. An owner or admin token can turn off the alarm and unlock
   doors.
2. Prefer **OAuth with PKCE**. A long-lived access token is acceptable only if
   you can revoke it and you treat it like a password. Put it in the
   `Authorization: Bearer` header. The edge checks that the header is present
   and shaped like a bearer token. Home Assistant checks the token itself.
3. **Expose a small set of entities** to that user (or to the Assist pipeline
   you point at `/api/mcp/assist`). Do not expose locks, alarms, or covers
   unless you mean to.
4. Set **`trusted_proxies`** to the address Home Assistant sees for this
   appliance (the LAN address of the WAF, or the docker bridge address if HA
   runs in a container on the same host). Without it, Home Assistant logs every
   request as the proxy and rate limits or IP bans inside HA hit the wrong
   address.
5. If the assistant runs in a cloud and connects from outside your country,
   turn on **GeoIP** for this application and allow the countries you actually
   use. A cloud client is not your home IP. See [GEOIP.md](GEOIP.md).

`/mcp_server/sse` is on the allowlist because some Home Assistant builds stream
there after OAuth. If your build requires a bearer token on that path as well,
add a path rule with `require_header: Authorization` and
`require_value_prefix: "Bearer "`.

## Optional edge token

A path rule may name `edge_token_header` (for example `X-Edge-Token`) and, on
write, `edge_token`. The token is stored in a file under
`<state>/secrets/edge-tokens/`, mode `0640`, so HAProxy (in the `easy-waf`
group) can compare the header and the generated config never contains the
value. It is not written to PostgreSQL, not returned by GET, and not captured
in the HAProxy httplog (the log stays on the request line; the config does not
use `capture request header`). The edge deletes the header before the backend
sees it.

Send a new `edge_token` to rotate it, or `clear_edge_token: true` to remove it.
If the file is missing while the rule says a token is configured, apply fails
closed.

The panel password field is write-only. Leaving it empty on save keeps the
current token.

## Checks that need a real Home Assistant

- A non-admin user, with a token, can call `/api/mcp` through the published
  name. The same call without `Authorization` is 401 at the edge.
- A path outside the allowlist, including the Home Assistant UI, is 404.
- An SSE or streamable session stays up through a minute of silence.
- `trusted_proxies` shows the real client in the Home Assistant log.
- Revoking the token in Home Assistant stops the assistant even though the edge
  only checked the header shape.
