# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for investigation state, budgets, and pivot classification."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.investigation import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_ENTITIES,
    DEFAULT_MAX_PROVIDER_CALLS,
    DEFAULT_MAX_REPLANS,
    InvalidInvestigationStatusTransitionError,
    InvestigationBudget,
    InvestigationError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    PivotClass,
    PivotRequest,
    PivotStatus,
    can_transition_status,
    default_investigation_budget,
    is_terminal_status,
    pivot_class,
    require_status_transition,
)

_STARTED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_default_budget_constants() -> None:
    """Initial configurable budget defaults match the domain model."""

    assert DEFAULT_MAX_DEPTH == 2
    assert DEFAULT_MAX_ENTITIES == 10
    assert DEFAULT_MAX_PROVIDER_CALLS == 40
    assert DEFAULT_MAX_REPLANS == 3


def test_default_budget_uses_constants_and_fresh_counters() -> None:
    """The default factory returns fresh instances with zeroed counters."""

    budget = default_investigation_budget()

    assert budget.max_depth == DEFAULT_MAX_DEPTH
    assert budget.max_entities == DEFAULT_MAX_ENTITIES
    assert budget.max_provider_calls == DEFAULT_MAX_PROVIDER_CALLS
    assert budget.max_replans == DEFAULT_MAX_REPLANS
    assert budget.provider_calls_used == 0
    assert budget.replans_used == 0


def test_default_budget_instances_are_independent() -> None:
    """Mutating one default budget does not affect later instances."""

    first = default_investigation_budget()
    first.provider_calls_used = 40

    second = default_investigation_budget()

    assert second.provider_calls_used == 0


def test_budget_requires_all_maxima() -> None:
    """Budgets require every maximum to be provided."""

    with pytest.raises(ValidationError):
        InvestigationBudget(max_depth=2)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("entity_type", "expected"),
    [
        (EntityType.DOMAIN, PivotClass.PIVOTABLE),
        (EntityType.IP_ADDRESS, PivotClass.PIVOTABLE),
        (EntityType.URL, PivotClass.PIVOTABLE),
        (EntityType.NETWORK_PREFIX, PivotClass.ENRICHABLE),
        (EntityType.ASN, PivotClass.ENRICHABLE),
        (EntityType.ORGANIZATION, PivotClass.ENRICHABLE),
        (EntityType.MALWARE, PivotClass.RESEARCHABLE),
        (EntityType.ATTACK_TECHNIQUE, PivotClass.RESEARCHABLE),
        (EntityType.VULNERABILITY, PivotClass.RESEARCHABLE),
    ],
)
def test_pivot_class_covers_every_entity_type(
    entity_type: EntityType, expected: PivotClass
) -> None:
    """Every entity type has its confirmed pivot classification."""

    assert pivot_class(entity_type) == expected


def test_pivot_request_defaults_to_pending() -> None:
    """Pivot requests start in the PENDING status."""

    request = PivotRequest(
        entity_id=uuid4(), reason="domain resolves to new IP", depth=1
    )

    assert request.status == PivotStatus.PENDING


def test_investigation_state_requires_core_workflow_fields() -> None:
    """States require identifiers, status, trigger, objective, and budget."""

    budget = default_investigation_budget()

    state = InvestigationState(
        investigation_id=uuid4(),
        status=InvestigationStatus.PENDING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[uuid4()],
        objective="Assess the root indicator.",
        budget=budget,
        started_at=_STARTED_AT,
    )

    assert state.discovered_entity_ids == []
    assert state.pending_pivots == []
    assert state.errors == []
    assert state.stop_reason is None
    assert state.completed_at is None


def test_investigation_state_rejects_missing_budget() -> None:
    """A state without a budget is invalid."""

    with pytest.raises(ValidationError):
        InvestigationState(
            investigation_id=uuid4(),
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.API,
            root_entity_ids=[],
            objective="Assess the root indicator.",
            started_at=_STARTED_AT,
        )  # type: ignore[call-arg]


def test_investigation_error_records_source_and_recoverability() -> None:
    """Errors carry their source, code, message, and recoverability."""

    error = InvestigationError(
        source="urn:ati:source:rdap",
        code="timeout",
        message="RDAP query timed out.",
        recoverable=True,
    )

    assert error.recoverable is True


def test_confirmed_status_transitions_are_deterministic() -> None:
    """Every status exposes exactly its confirmed lifecycle targets."""

    assert can_transition_status(
        InvestigationStatus.PENDING, InvestigationStatus.RUNNING
    )
    assert can_transition_status(
        InvestigationStatus.PENDING, InvestigationStatus.FAILED
    )
    assert not can_transition_status(
        InvestigationStatus.PENDING, InvestigationStatus.COMPLETED
    )
    assert can_transition_status(
        InvestigationStatus.RUNNING, InvestigationStatus.COMPLETED
    )
    assert can_transition_status(
        InvestigationStatus.RUNNING, InvestigationStatus.PARTIAL
    )
    assert can_transition_status(
        InvestigationStatus.RUNNING, InvestigationStatus.FAILED
    )
    assert not can_transition_status(
        InvestigationStatus.RUNNING, InvestigationStatus.PENDING
    )


@pytest.mark.parametrize(
    "terminal",
    [
        InvestigationStatus.COMPLETED,
        InvestigationStatus.PARTIAL,
        InvestigationStatus.FAILED,
    ],
)
def test_terminal_statuses_admit_no_transitions(
    terminal: InvestigationStatus,
) -> None:
    """Terminal statuses admit no further transitions and are recognized."""

    assert is_terminal_status(terminal)
    for target in InvestigationStatus:
        if target is terminal:
            continue  # identical statuses are not transitions
        assert not can_transition_status(terminal, target)


def test_identical_status_is_not_a_transition() -> None:
    """An identical target status is not treated as a lifecycle transition."""

    assert can_transition_status(
        InvestigationStatus.RUNNING, InvestigationStatus.RUNNING
    )


def test_invalid_status_transition_raises_typed_error() -> None:
    """Lifecycle violations raise the typed domain error before persistence."""

    with pytest.raises(InvalidInvestigationStatusTransitionError, match="running"):
        require_status_transition(
            InvestigationStatus.RUNNING, InvestigationStatus.PENDING
        )


def test_valid_status_transition_passes_domain_validation() -> None:
    """Confirmed transitions pass domain validation without raising."""

    require_status_transition(InvestigationStatus.PENDING, InvestigationStatus.RUNNING)
    require_status_transition(
        InvestigationStatus.RUNNING, InvestigationStatus.COMPLETED
    )
    require_status_transition(InvestigationStatus.FAILED, InvestigationStatus.FAILED)
