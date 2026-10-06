# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0033: mandatory GEOINT enrichment coordinator state (PR 35-4).

Redefines ``ati.update_investigation_coordinator_state`` with three
append-only, budget-neutral transition kinds for the mandatory-enrichment
execution class (``schedule_mandatory_enrichment``,
``select_mandatory_enrichment``, ``record_mandatory_enrichment_outcome``).
The stored function independently enforces:

- ``provider_calls_used``, ``replans_used``, and ``llm_calls_used`` are
  unchanged by every mandatory transition, while ordinary
  ``record_provider_outcome`` still increments the provider counter by
  exactly one;
- scheduled work identities are unique ``(provider, entity_id)`` values
  naming existing durable Investigation members;
- selection is exactly the durable pending-queue head;
- completion matches the selected work item, is append-only, and references
  only admitted Evidence/Relationship IDs;
- a non-fatal stop cannot finalize while mandatory work is queued or current.

Legacy operational documents are normalized in the function itself so no
data migration, version bump, or empty history row is created merely to add
the new keys. The Python repository binds parameters and maps results only.

The downgrade restores the previous (v0026) coordinator function definition.
"""

from pathlib import Path

from alembic import op

revision = "0038_mandatory_enrichment"
down_revision = "0037_datasource_checkpoint"


def _read(name: str) -> str:
    """Read one immutable SQL API v0033 file."""
    return Path(__file__).parents[1].joinpath(f"sql/ati/v0033/{name}").read_text()


def _previous_coordinator_function() -> str:
    """Return the archived v0026 coordinator function definition.

    Only the coordinator function is restored on downgrade; every other
    function from the v0026 API remains installed and unchanged.
    """
    text = (
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0026/repointed_write_functions.sql")
        .read_text()
    )
    start = text.index(
        "CREATE OR REPLACE FUNCTION ati.update_investigation_coordinator_state"
    )
    end = text.index("\nEND $$;", start) + len("\nEND $$;")
    return text[start:end]


def upgrade() -> None:
    """Install the mandatory-enrichment coordinator transition contract."""
    op.execute(_read("mandatory_enrichment.sql"))


def downgrade() -> None:
    """Restore the pre-35-4 coordinator transition contract."""
    op.execute(_previous_coordinator_function())
