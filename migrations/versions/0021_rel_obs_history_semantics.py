# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0018: remove redundant RelationshipObservation history.

PR 22E corrects persistence semantics so ``RelationshipObservation`` is
treated as the historical record itself: ``ati.append_relationship_observation``
stops writing the redundant CREATE ``domain_object_history`` row while
retaining the immutable observation append, database-allocated version, and
all provenance/integrity constraints. The stable ``Relationship`` remains
historized exactly as before (CREATE history for new edges, reuse as a
no-op, soft-delete history), and Evidence historization is unchanged.

The schema is untouched: no table, sequence, or constraint changes. Existing
redundant legacy ``relationship_observation`` history rows from databases
upgraded from before this revision are deliberately preserved.
"""

from pathlib import Path

from alembic import op

revision = "0021_rel_obs_history_semantics"
down_revision = "0020_research_execution"


def upgrade() -> None:
    """Install the v0018 relationship write functions (observation history removed)."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0018/relationship_persistence.sql")
        .read_text()
    )


def downgrade() -> None:
    """Restore the original v0008 relationship write functions."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0008/relationship_persistence.sql")
        .read_text()
    )
