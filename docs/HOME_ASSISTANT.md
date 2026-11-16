# Publish Home Assistant

One publication normally serves the Home Assistant web UI, Companion mobile app
and API. They share the same backend; separate mobile/API publications are not
required. Use the external HTTPS URL in the [Companion app](https://companion.home-assistant.io/docs/getting_started/).

## Full Home Assistant

Create an application with your public hostname and certificate:

- Backend host: the Home Assistant LAN address; backend port: its actual HTTP
  port (often `8123`, but use the port configured on that installation).
- Profile: `home-assistant`; WebSocket enabled.
- Backend HTTPS only when HA itself serves HTTPS. Edge HTTPS and backend HTTPS
  are separate connections.
- HTTPS listen mode and a certificate matching the public hostname.
- Leave path exposure unrestricted for the full HA application. New forms do
  not add LAN restrictions automatically. Existing path rules are kept when
  editing or switching profiles; review them explicitly.

The selected-profile explanation shows defaults for timeouts, rate thresholds,
probe paths, methods and request bodies. The separate Security mode controls
which protection layers are active. Profile selection does not reset HTTPS,
WebSocket, custom path rules or security toggles. The HA profile allows `/config`
for settings while continuing to block probes such as `/.git` and `/.env`.

Do not restrict `/api` to private/LAN CIDRs if external HA clients must use it:
that prefix also covers `/api/websocket` and blocks requests needed by the web
UI, Companion and API clients. Removing an existing restriction is an explicit
operator decision; an upgrade does not remove stored rules.

In HA, configure [reverse proxy trust](https://www.home-assistant.io/integrations/http/#reverse-proxies):
enable Trust X-Forwarded-For and trust the specific address HA sees for the WAF.
Current HA exposes these controls under Settings → System → Network → HTTP
server. Older versions use `http.use_x_forwarded_for` and `http.trusted_proxies`
in `configuration.yaml`. The WAF does not configure HA or replace HA sign-in.

If direct HA access works but a request with `X-Forwarded-For` returns HTTP 400,
inspect HA's HTTP logs and reverse-proxy settings before changing edge rules.
Check the address HA actually sees: a WAF running behind VM/container NAT can
appear with the host's address rather than the guest address. Trust that specific
proxy address. Keep client-address forwarding enabled so HA can distinguish
clients correctly; a WAF profile cannot configure HA's proxy trust.

A normal GET to `/api/websocket` is not a WebSocket transport check. A real
client must complete HTTP 101 Upgrade and exchange framed messages. HA initially
sends [`auth_required`](https://contributors.home-assistant.io/core/internals/websocket-api/);
that proves the unauthenticated channel is reachable, while sign-in and actual
Companion/API operations still need their own checks.

## MCP-only publication

`ha-mcp` installs a path allowlist on a new, unset path policy. It publishes MCP
and OAuth endpoints and returns 404 for other paths, so it is not a full HA UI
or Companion profile. Existing explicit path policies are retained. See the
exact edge rules in [HA-MCP.md](HA-MCP.md).

Use a separate hostname only when you want this separate MCP-only exposure.
Enable/configure the [HA MCP integration](https://www.home-assistant.io/integrations/mcp_server/)
and copy the endpoint URL it provides for the intended tool set. The WAF profile
does not enable MCP or authenticate to HA on the client's behalf.

## Remove a publication

Applications → the application's **Delete** button opens a confirmation naming
the application and hostname. After password step-up if needed, deletion uses
the existing API and applies removal automatically unless manual Apply mode is
enabled. The backend service and certificates are retained. Failed/rejected
deletion stays visible as an error; the API restores the row when Apply is
rejected. Other applications are not removed.
