# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 26C asynchronous geographic-resolution lifecycle (SQL API v0024).

Adds the durable asynchronous work lifecycle on the existing
``ati.geo_resolution`` table from PR 26A: no second queue table and no
broker. SQL API v0024 installs four versioned stored functions:

- ``ati.claim_geo_resolutions``: bounded ``FOR UPDATE SKIP LOCKED`` claim of
  eligible PENDING / expired-PROCESSING work into PROCESSING with a
  claimant/lease, attempt +1, and a fresh database version, in one short
  transaction that MUST commit before resolution work;
- ``ati.complete_geo_resolution_resolved``: atomic successful completion
  (status/version/claimant/live-lease + exact Entity/Evidence/Location
  provenance validation, one immutable observation append reusing the SQL
  API v0022 append semantics, current EntityLocation reconciliation, and
  RESOLVED termination) with replay idempotency;
- ``ati.complete_geo_resolution_unresolvable``: terminal UNRESOLVABLE
  transition with a stable reason code and no observation;
- ``ati.record_geo_resolution_failure``: bounded retry (deterministic
  exponential backoff, no jitter) or terminal FAILED at exhaustion.

No existing Locations, observations, current-state rows, or work rows are
rewritten; existing PENDING work remains eligible for the new lifecycle.
The claim-support partial indexes back the two eligibility predicates, and
the lifecycle CHECK constraints pin the durable invariants (PROCESSING
requires claimant + lease; terminal states clear lease/claim state; a
RESOLVED row records its resolved Location).

The downgrade drops only the PR 26C functions/indexes/constraints,
restoring the pre-PR-26C API behavior while preserving all authoritative
data. SQL API v0021/v0022/v0023 remain immutable.
"""

from pathlib import Path

from alembic import op

revision = "0028_geo_resolution_lifecycle"
down_revision = "0027_geoint_reference_spatial"


def upgrade() -> None:
    """Install the PR 26C lifecycle SQL API, claim indexes, and constraints."""
    # Claim-support partial indexes: PENDING rows are eligible by next_attempt_at
    # (NULL means immediately due); PROCESSING rows by lease expiry. The partial
    # predicates narrow each index to exactly one eligibility predicate and the
    # deterministic (eligibility time, created_at, id) ordering is index-order.
    op.execute(
        "CREATE INDEX IF NOT EXISTS geo_resolution_pending_claim_idx "
        "ON ati.geo_resolution (next_attempt_at, created_at, id) "
        "WHERE status = 'pending'"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS geo_resolution_processing_claim_idx "
        "ON ati.geo_resolution (lease_expires_at, created_at, id) "
        "WHERE status = 'processing'"
    )
    # Lifecycle CHECK constraints (absent from SQL API v0021).
    op.execute(
        "ALTER TABLE ati.geo_resolution ADD CONSTRAINT "
        "geo_resolution_processing_shape_check CHECK ("
        "status <> 'processing' "
        "OR (claimed_by IS NOT NULL AND lease_expires_at IS NOT NULL))"
    )
    op.execute(
        "ALTER TABLE ati.geo_resolution ADD CONSTRAINT "
        "geo_resolution_terminal_clear_check CHECK ("
        "status NOT IN ('resolved', 'unresolvable', 'failed') "
        "OR (claimed_by IS NULL AND lease_expires_at IS NULL))"
    )
    op.execute(
        "ALTER TABLE ati.geo_resolution ADD CONSTRAINT "
        "geo_resolution_resolved_location_check CHECK ("
        "status <> 'resolved' OR resolved_location_id IS NOT NULL)"
    )
    op.execute(
        "ALTER TABLE ati.geo_resolution ADD CONSTRAINT "
        "geo_resolution_pending_clear_check CHECK ("
        "status <> 'pending' OR (claimed_by IS NULL AND lease_expires_at IS NULL))"
    )
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0024/geo_resolution_lifecycle.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove only the PR 26C lifecycle objects in dependency-safe order.

    Terminal/processing work rows created by the new API remain intact (their
    schema is the PR 26A schema); only the new functions, indexes, and CHECK
    constraints are dropped, restoring the pre-PR-26C API behavior. PENDING
    rows remain eligible for any future re-installation.
    """
    op.execute(
        "DROP FUNCTION IF EXISTS ati.record_geo_resolution_failure("
        "uuid, bigint, text, text, boolean, double precision, "
        "double precision, integer)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.complete_geo_resolution_unresolvable("
        "uuid, bigint, text, text)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.complete_geo_resolution_resolved("
        "uuid, bigint, text, uuid, uuid, text, timestamptz, timestamptz, "
        "timestamptz, text)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.claim_geo_resolutions("
        "text, integer, integer, integer)"
    )
    op.execute("DROP INDEX IF EXISTS ati.geo_resolution_processing_claim_idx")
    op.execute("DROP INDEX IF EXISTS ati.geo_resolution_pending_claim_idx")
    op.execute(
        "ALTER TABLE ati.geo_resolution DROP CONSTRAINT IF EXISTS "
        "geo_resolution_pending_clear_check"
    )
    op.execute(
        "ALTER TABLE ati.geo_resolution DROP CONSTRAINT IF EXISTS "
        "geo_resolution_resolved_location_check"
    )
    op.execute(
        "ALTER TABLE ati.geo_resolution DROP CONSTRAINT IF EXISTS "
        "geo_resolution_terminal_clear_check"
    )
    op.execute(
        "ALTER TABLE ati.geo_resolution DROP CONSTRAINT IF EXISTS "
        "geo_resolution_processing_shape_check"
    )
