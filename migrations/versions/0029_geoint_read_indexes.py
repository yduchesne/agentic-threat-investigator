# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 26D GEOINT read-path indexes (read-only migration).

PR 26A shipped exactly one observation index
(``entity_location_observation_entity_retrieved_idx`` on
``(entity_id, retrieved_at DESC, id ASC)``) backing Entity-relative
history. PR 26D's Investigation-scoped read layer adds two more analyst
read shapes that no existing access path serves:

- ``entity_location_observation_location_idx`` on ``(location_id,
  retrieved_at DESC, id ASC)``: the Location reverse lookup (Locations ->
  Entities/observations) filters observation rows by the selected Location
  before joining exact Evidence scope. Without it PostgreSQL has no
  observation-side access path for the Location dimension and must scan
  (or hash-join) the whole observation table per analyst Location read.
- ``entity_location_observation_evidence_idx`` on ``(evidence_id)``:
  every Analysis-scope read drives the exact Evidence chain
  (``observation.evidence_id -> Evidence.investigation_id``); Evidence
  Investigation filtering uses the existing Evidence indexes, and this
  index is the observation-side continuation of that join for the summary
  and scope-driven paths.
  ``created_at``/``id`` are deliberately not appended: the two new
  collections page by the PR 26A effective-time ordering
  (``COALESCE(observed_at, retrieved_at)``), which is an expression no
  plain b-tree serves; the (bounded) filtered sort is accepted and proven
  by the EXPLAIN tests.

Both indexes are read-only: no data rewrite, no mutation SQL change, no
schema/API change. The downgrade drops only the two new indexes.
"""

from alembic import op

revision = "0029_geoint_read_indexes"
down_revision = "0028_geo_resolution_lifecycle"


def upgrade() -> None:
    """Install the two PR 26D observation read indexes."""
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS entity_location_observation_location_idx
          ON ati.entity_location_observation(location_id, retrieved_at DESC, id ASC)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS entity_location_observation_evidence_idx
          ON ati.entity_location_observation(evidence_id)
        """
    )


def downgrade() -> None:
    """Remove only the PR 26D read indexes."""
    op.execute("DROP INDEX IF EXISTS ati.entity_location_observation_location_idx")
    op.execute("DROP INDEX IF EXISTS ati.entity_location_observation_evidence_idx")
