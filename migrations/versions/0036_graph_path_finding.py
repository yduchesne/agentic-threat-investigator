# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0031: bounded deterministic graph path finding (PR 31I).

Adds one read-only PostgreSQL stored function
(``ati.find_graph_paths``) implementing the entire PR 31I path query
inside the database: both-endpoint Investigation visibility, eligible
Relationship/RelationshipObservation selection under the exact PR 31G
scope/source/time filters, Entity-path cycle-safe recursive simple-path
search, deterministic shortest-first ordering with a canonical path
signature, the ``max_paths + 1`` truncation probe, canonical graph closure
and observation/support aggregation. The Python adapter only binds
validated parameters, invokes the function once and maps returned rows; no
path SQL exists outside the stored function.

The migration is a versioned stored-function change only: no table, column,
constraint or index change is introduced (PR 31I adds an index only with
measured ``EXPLAIN (ANALYZE, BUFFERS)`` evidence; the plan's default
expectation is none). The downgrade drops the path function only and leaves
``ati.traverse_graph`` and all authoritative graph tables/data untouched; no
historical migration file is edited.
"""

from pathlib import Path

from alembic import op

revision = "0036_graph_path_finding"
down_revision = "0035_graph_traversal"


def upgrade() -> None:
    """Install the bounded path-finding stored function."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0031/graph_path_finding.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove the path-finding stored function and nothing else."""
    op.execute(
        """
        DROP FUNCTION ati.find_graph_paths(
          p_investigation_id uuid,
          p_source_entity_id uuid,
          p_target_entity_id uuid,
          p_max_depth integer,
          p_max_paths integer,
          p_scope text,
          p_direction text,
          p_relationship_type text,
          p_entity_type text,
          p_source text,
          p_observed_from timestamptz,
          p_observed_to timestamptz
        );
        """
    )
