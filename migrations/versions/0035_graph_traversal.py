# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0030: bounded multi-hop graph traversal (PR 31H).

Adds one read-only PostgreSQL stored function
(``ati.traverse_graph``) implementing the entire PR 31H traversal inside
the database: focal visibility, eligible Relationship/RelationshipObservation
selection under the exact PR 31G scope/source/time filters, direction-
relative recursive traversal with Entity-path cycle prevention, minimum-hop-
depth derivation, canonical deduplication, observation/support aggregation,
endpoint Entity projection, deterministic ordering and the ``limit + 1``
truncation probe. The Python adapter only binds validated parameters, invokes
the function and maps rows; no traversal SQL exists outside the stored
function.

The migration is a versioned stored-function change only: no table, column,
constraint or index change is introduced (PR 31H adds an index only with
measured ``EXPLAIN (ANALYZE, BUFFERS)`` evidence; none is required after
evaluating the existing adjacency indexes). The downgrade drops the
traversal function; no historical migration file is edited.
"""

from pathlib import Path

from alembic import op

revision = "0035_graph_traversal"
down_revision = "0034_timeline_error_message"


def upgrade() -> None:
    """Install the bounded graph-traversal stored function."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0030/graph_traversal.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove the traversal stored function and nothing else."""
    op.execute(
        """
        DROP FUNCTION ati.traverse_graph(
          p_investigation_id uuid,
          p_entity_id uuid,
          p_max_depth integer,
          p_scope text,
          p_direction text,
          p_relationship_type text,
          p_entity_type text,
          p_source text,
          p_observed_from timestamptz,
          p_observed_to timestamptz,
          p_limit integer
        );
        """
    )
