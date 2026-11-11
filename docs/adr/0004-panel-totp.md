# ADR 0004 — A second factor for the management panel

- **Status:** accepted (option C)
- **Date:** 2026-11-10
- **Deciders:** repository maintainer
- **Context version:** 1.6.0
- **Implementation:** option C — optional TOTP at login, hashed one-time
  recovery codes, admin reset and `easy-waf-admin disable-totp`. Host step-up
  stays a password confirmation.

## Context

The panel is the control plane. A stolen password today is a session, and a
session can read the configuration. Since 1.6.0 a session cannot change the
host until it confirms the password again (`POST /api/v1/auth/confirm`). That
step-up stops a stolen token. It does not stop someone who has the password.

Enrollment is already a one-time secret on the console. There is no second
factor, no recovery code, and no existing ADR that says the panel should grow
one. Adding TOTP changes who can be locked out, and a lockout on this
appliance is repaired from the console, not from a vendor.

## Options considered

### A. Leave the password as the only factor

Nothing new to lose. A phished password is still a full login. Step-up still
limits what a stolen token can do to the host.

### B. TOTP required for every operator

Enrollment, a shared secret, recovery codes, and a lockout path. Stronger
against a phished password. The cost is a panel nobody can open when the phone
is gone, unless recovery codes were stored, and those codes are a second
password that must be hashed and shown once.

### C. TOTP optional, at login, recovery codes hashed — *recommended if this is accepted*

An operator who turns it on must present a TOTP code after the password before
a JWT is issued. Recovery codes are generated once, stored as hashes, and each
code works once. Host step-up stays the password confirmation it is today: a
TOTP code does not replace it, because the host broker is gated on "this
person still knows the password", which a phone does not prove.

Codes are verified in `easy-waf-api`. They are not sent to HAProxy and not
written into the journal. The enrollment secret on the console remains the way
back in if both the password and the phone are lost: `easy-waf-admin` can
clear the TOTP secret the same way it can reset the password, and that stays a
local root action.

## Decision

Do not implement this until the record is accepted. The current step-up and
enrollment already match the appliance. TOTP is a product choice about lockout,
not a hole in the host broker. Option C is the shape to build if it is
accepted. Option B is rejected because a required factor with a lost phone
makes the console emergency path the normal path.

## Consequences

- Recovery codes are as sensitive as the password. They are shown once and
  stored only as hashes.
- Clock skew of one step in each direction has to be accepted, and replay of
  the same step has to be rejected.
- Nothing in the edge proxy changes. This ADR is the panel only.
