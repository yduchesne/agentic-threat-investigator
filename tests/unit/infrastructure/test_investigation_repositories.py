# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the investigation row-to-domain mapper precedence."""

# The mapper under test is the repository module's private row mapper; the
# mapper-level precedence contract is the point of these tests.

from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.domain.investigation import (
    InvestigationStatus,
    InvestigationTriggerType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql import (
    investigation_repositories,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.models import (
    InvestigationRow,
)

_ROW_ID = uuid4()
_ROW_VERSION = 7
_ROW_STARTED_AT = datetime(2026, 1, 1, tzinfo=UTC)
_ROW_COMPLETED_AT = datetime(2026, 1, 2, tzinfo=UTC)


def _row(operational_state: dict[str, object]) -> InvestigationRow:
    """Build a valid investigation row with the supplied JSONB document."""
    return InvestigationRow(
        id=_ROW_ID,
        status="pending",
        trigger_type="manual",
        objective="real objective",
        budget={
            "max_depth": 2,
            "max_entities": 10,
            "max_provider_calls": 40,
            "max_replans": 3,
            "provider_calls_used": 5,
            "replans_used": 1,
        },
        operational_state=operational_state,
        version=_ROW_VERSION,
        created_at=datetime(2025, 12, 31, tzinfo=UTC),
        updated_at=datetime(2025, 12, 31, 12, 0, 0, tzinfo=UTC),
        started_at=_ROW_STARTED_AT,
        completed_at=_ROW_COMPLETED_AT,
        deleted_at=None,
        deleted_by_actor_id=None,
    )


def _spoofed_operational_state() -> dict[str, object]:
    """Return a JSONB document whose keys collide with dedicated columns."""
    return {
        # Colliding keys carry valid but contradictory values.
        "investigation_id": str(uuid4()),
        "status": "failed",
        "trigger_type": "api",
        "objective": "spoofed objective",
        "budget": {
            "max_depth": 9,
            "max_entities": 99,
            "max_provider_calls": 999,
            "max_replans": 9,
            "provider_calls_used": 99,
            "replans_used": 9,
        },
        "started_at": "2020-01-01T00:00:00Z",
        "completed_at": "2020-01-01T00:00:00Z",
        "version": 42,
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2020-01-01T00:00:00Z",
        "deleted_at": "2020-01-01T00:00:00Z",
        "deleted_by_actor_id": str(uuid4()),
        # Legitimate operational keys survive alongside the collisions.
        "trigger_id": str(uuid4()),
        "root_entity_ids": [],
        "stop_reason": "sufficient_evidence",
        "errors": [],
    }


def test_dedicated_columns_win_over_colliding_operational_state() -> None:
    """Colliding JSONB keys can never replace a dedicated database column."""
    state = investigation_repositories._to_domain(_row(_spoofed_operational_state()))

    assert state.investigation_id == _ROW_ID
    assert state.status is InvestigationStatus.PENDING
    assert state.trigger_type is InvestigationTriggerType.MANUAL
    assert state.objective == "real objective"
    assert state.budget.provider_calls_used == 5
    assert state.budget.replans_used == 1
    assert state.started_at == _ROW_STARTED_AT
    assert state.completed_at == _ROW_COMPLETED_AT
    assert state.version == _ROW_VERSION
    assert state.created_at == datetime(2025, 12, 31, tzinfo=UTC)
    assert state.updated_at == datetime(2025, 12, 31, 12, 0, 0, tzinfo=UTC)
    assert state.deleted_at is None
    assert state.deleted_by_actor_id is None


def test_legitimate_operational_fields_still_deserialize() -> None:
    """Non-colliding operational keys come from the JSONB document."""
    operational = _spoofed_operational_state()
    trigger_id = operational["trigger_id"]
    assert isinstance(trigger_id, str)

    state = investigation_repositories._to_domain(_row(operational))

    assert state.trigger_id == UUID(trigger_id)
    assert state.stop_reason == "sufficient_evidence"
    assert state.root_entity_ids == []
    assert state.errors == []


def test_mapper_tolerates_minimal_operational_state() -> None:
    """A row with only the required operational keys still maps completely."""
    state = investigation_repositories._to_domain(
        _row(
            {
                "root_entity_ids": [str(uuid4())],
                "errors": [],
            }
        )
    )

    assert state.investigation_id == _ROW_ID
    assert state.status is InvestigationStatus.PENDING
    assert state.version == _ROW_VERSION
    assert state.trigger_id is None
    assert state.stop_reason is None
