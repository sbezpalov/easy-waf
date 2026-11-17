# Publish OpenClaw Gateway

Use one HTTPS publication for the OpenClaw Control UI and its Gateway
WebSocket. For remote administration, keep this hostname reachable only
through your LAN or VPN. The Control UI can administer the Gateway.

1. In OpenClaw, keep Gateway token or password authentication and device
   pairing enabled. Use the loopback bind when OpenClaw and Easy Home WAF
   share a host. For a separate host, bind to an interface reachable by
   HAProxy and firewall the Gateway port so only HAProxy can connect.
2. Set `gateway.trustedProxies` to the specific address OpenClaw sees for
   HAProxy. Use `127.0.0.1` only when HAProxy connects over IPv4 loopback.
   Set `gateway.controlUi.allowedOrigins` to the exact external origin,
   such as `https://claw.example.com`.
3. In **Applications → Add**, select **openclaw**, set the backend to the
   Gateway address and port (18789 by default), enable **WebSocket**, and
   select **HTTPS only** and the certificate for the hostname. Review the
   [application example](../examples/application-openclaw.json).
4. Apply, open the HTTPS hostname from an authorized network and pair the
   browser in OpenClaw. Verify the UI stays connected and can reconnect
   after a reload.

The profile allows the Control UI's `/config` path while retaining common
probe blocks when Path ACL is enabled. It keeps the server timeout at one
hour. The WebSocket setting gives upgraded connections a one-hour tunnel
timeout. HAProxy rebuilds `X-Forwarded-For` from the client address selected
by the frontend and removes incoming `Forwarded` and `X-Real-IP` headers.
OpenClaw handles authentication and authorization.

The same host can carry APIs you deliberately enable in OpenClaw. Keep unused
HTTP APIs and plugin routes disabled. Evaluate OpenClaw plugin or MCP routes
individually before exposing them to another client group. Configure
route-specific access and identity-provider integration separately when needed.

Before rolling back to an Easy Home WAF version that predates this profile,
remove its OpenClaw publications and Apply using the current version.

See [OpenClaw network exposure](https://docs.openclaw.ai/gateway/security/network-exposure)
and [Control UI pairing](https://docs.openclaw.ai/web/control-ui/connect-and-pair).
