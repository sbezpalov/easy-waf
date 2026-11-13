# 0010: Commit an immutable ACME generation with its apply intent

Status: accepted

## Context

The worker staged two `.pem.new` files, committed a ready certificate row pointing
at canonical filenames, then renamed the key and chain separately. A promotion
failure or process crash could leave ready metadata with old or mismatched PEMs.
The apply-pending file was written later and only best effort, leaving another
crash gap. A shared marker could also be cleared after a newer publication.

## Decision

Each successful issuance writes a validated matching certificate/key pair to a
fresh private `certs/<id>/generation-*` directory. Both files are complete before
the claim-checked row transaction commits. That transaction changes the row's
paths, validity and status and upserts one fresh generation token into
`acme_apply_pending`. There is no post-commit PEM promotion. Already referenced
generations are never modified by subsequent issuances.

Reconciliation snapshots a bounded batch of pending tokens before calling the
existing `ApplyIfChanged`. Success or verified no-change acknowledges only exact
certificate/token pairs. Concurrent publications therefore retain their newer
work. Failed apply, cancellation, uncertain acknowledgement and process death
keep retry intent. Deleting a certificate cascades to its token. The old local
marker remains a read-only upgrade input until successful reconciliation.

## Alternatives considered

- Promoting before commit merely reverses the inconsistency: rollback/crash can
  leave a new pair behind an old row. Two independent renames cannot publish a
  pair atomically, and compensating rollback can itself fail.
- A post-commit file marker still has a DB/filesystem gap. Writing a shared
  marker earlier needs ownership-safe acknowledgement and is not transactional
  with PostgreSQL. A database token makes intent part of the source of truth.
- Copying private PEM material into each config revision would change the
  existing rollback/key-retention policy. This decision preserves that policy.

## Consequences

An uncertain commit must not delete its generation: the database might already
reference it. Old and unreferenced generations remain recovery material, with
no automatic GC. Contents are synced and private; physical power-loss/directory
durability remains a separate concern. Normal backups/restores must include
matching PostgreSQL and certificate state.

Existing paths are accepted, and a legacy apply marker is not discarded during
upgrade. Already-running older workers retain their old behavior until the
package's graceful restart finishes; mixed versions are not a supported steady
state. Old partial sidecars are not guessed at or automatically repaired.
Migration 027 invokes the existing schema downgrade protection; restore a matched
pre-upgrade database/state backup on a copy before considering a rollback.

Tests cover actual process kills before/after commit, a transaction failure after
the ready update, repeated immutable renewals, generation-specific stale
acknowledgement, migration/cascade, restart recovery and failed acknowledgement
after a successful edge apply without a duplicate revision on retry.
