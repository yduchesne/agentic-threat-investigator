# SPDX-License-Identifier: AGPL-3.0-only
"""Install v0009 PR 18C graph-integrity semantics."""

from pathlib import Path

from alembic import op

revision = "0012_pr18c_graph_integrity"
down_revision = "0011_relationship_persistence"


def upgrade() -> None:
    """Install the v0009 write functions and the Evidence provenance FK."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0009/graph_integrity.sql")
        .read_text()
    )
    op.execute("""
        ALTER TABLE ati.relationship_observation
          ADD CONSTRAINT relationship_observation_evidence_fk
          FOREIGN KEY (evidence_id) REFERENCES ati.evidence(id)
    """)


def downgrade() -> None:
    """Restore the v0008 semantics and drop the provenance foreign key."""
    op.execute(
        "ALTER TABLE ati.relationship_observation"
        " DROP CONSTRAINT IF EXISTS relationship_observation_evidence_fk"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.soft_delete_relationship(uuid, uuid, bigint)"
    )
    # Restore the archived v0001 upsert_entity definition, which is the
    # immediately previous definition of that function: v0008/v0009 evolved
    # it, and no intermediate revision exists.
    v0001 = (
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0001/write_functions.sql")
        .read_text()
    )
    marker = "CREATE OR REPLACE FUNCTION"
    upsert_start = v0001.index(marker)
    upsert_end = v0001.index(marker, upsert_start + 1)
    op.execute(v0001[upsert_start:upsert_end])
