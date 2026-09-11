# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for durable Investigation LLM-call accounting (PR 20B)."""

# Fixture arguments intentionally reuse fixture names.

from datetime import UTC, datetime
from typing import Self
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.evidence_analyst import LlmAccountingService
from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    InvestigationNotFoundError,
    InvestigationRepository,
    InvestigationVersionConflictError,
    InvestigationWriteResult,
    UnitOfWork,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationBudget,
    InvestigationBudgetExhaustedError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class _FakeRepository(InvestigationRepository):  # pragma: no cover
    """In-memory investigation repository for the accounting boundary."""

    def __init__(self, state: InvestigationState) -> None:
        self.state = state
        self.budget_writes: list[InvestigationBudget] = []

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        return self.state

    async def update_budget(
        self,
        investigation_id: UUID,
        budget: InvestigationBudget,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        if expected_version is not None and self.state.version != expected_version:
            raise InvestigationVersionConflictError(investigation_id, expected_version)
        self.budget_writes.append(budget)
        self.state.budget = budget
        self.state.version = (self.state.version or 0) + 1
        return InvestigationWriteResult(
            investigation_id, self.state.version, BatchOutcome.UPDATED
        )

    async def create(self, *args: object, **_: object) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_status(
        self, *args: object, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def update_coordinator_state(
        self,
        investigation_id: UUID,
        transition_kind: object,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        consumes_replan: bool = False,
    ) -> InvestigationWriteResult:
        """Test fake: accept the transition and report a new version."""
        return InvestigationWriteResult(investigation_id, 7, BatchOutcome.UPDATED)

    async def set_analysis_result(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        analyzed_evidence_ids: list[UUID],
        disposition: object,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationWriteResult:
        """Test fake: accept and report a new version."""
        del (
            assessment_id,
            analyzed_evidence_ids,
            disposition,
            actor_id,
            request_id,
            expected_version,
        )
        return InvestigationWriteResult(investigation_id, 8, BatchOutcome.UPDATED)

    async def update_assessment_reference(
        self, *args: object, **_: object
    ) -> InvestigationWriteResult:
        raise NotImplementedError

    async def soft_delete(self, *args: object, **_: object) -> InvestigationWriteResult:
        raise NotImplementedError


class _UnitOfWork(UnitOfWork):
    """In-memory transaction boundary for accounting reservations."""

    def __init__(self, repository: _FakeRepository) -> None:
        self.investigations: InvestigationRepository = repository
        self.commits = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        if exc_type is None:
            self.commits += 1

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        return None


def _state(
    *, budget: InvestigationBudget | None = None, version: int | None = 5
) -> InvestigationState:
    """Build a running Investigation with an explicit budget/version."""
    return InvestigationState(
        investigation_id=uuid4(),
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[uuid4()],
        objective="Assess the root indicator.",
        budget=budget or default_investigation_budget(),
        started_at=_RETRIEVED_AT,
        version=version,
    )


@pytest.mark.asyncio
async def test_reserve_call_increments_and_returns_new_version() -> None:
    """One reservation increments the counter and the Investigation version."""
    state = _state()
    repository = _FakeRepository(state)
    unit = _UnitOfWork(repository)
    accounting = LlmAccountingService(lambda: unit)

    new_version = await accounting.reserve_call(state.investigation_id)

    assert new_version == 6
    assert state.version == 6
    assert state.budget.llm_calls_used == 1
    assert len(repository.budget_writes) == 1


@pytest.mark.asyncio
async def test_exhausted_budget_raises_typed_error() -> None:
    """An exhausted budget rejects the reservation before any write."""
    budget = default_investigation_budget()
    budget.llm_calls_used = budget.max_llm_calls
    state = _state(budget=budget)
    repository = _FakeRepository(state)
    accounting = LlmAccountingService(lambda: _UnitOfWork(repository))

    with pytest.raises(InvestigationBudgetExhaustedError):
        await accounting.reserve_call(state.investigation_id)

    assert not repository.budget_writes
    assert state.version == 5


@pytest.mark.asyncio
async def test_stale_expected_version_conflicts() -> None:
    """A stale caller snapshot fails without reserving."""
    state = _state(version=8)
    repository = _FakeRepository(state)
    accounting = LlmAccountingService(lambda: _UnitOfWork(repository))

    with pytest.raises(InvestigationVersionConflictError):
        await accounting.reserve_call(state.investigation_id, expected_version=3)

    assert not repository.budget_writes


@pytest.mark.asyncio
async def test_missing_investigation_raises() -> None:
    """A missing/deleted Investigation cannot reserve a call."""

    class _MissingRepository(_FakeRepository):
        async def get_by_id(
            self, investigation_id: UUID, *, include_deleted: bool = False
        ) -> InvestigationState | None:
            return None

    state = _state()
    accounting = LlmAccountingService(lambda: _UnitOfWork(_MissingRepository(state)))

    with pytest.raises(InvestigationNotFoundError):
        await accounting.reserve_call(state.investigation_id)


@pytest.mark.asyncio
async def test_reservations_chain_through_versions() -> None:
    """Consecutive reservations chain expected versions linearly."""
    state = _state()
    repository = _FakeRepository(state)
    accounting = LlmAccountingService(lambda: _UnitOfWork(repository))

    version_1 = await accounting.reserve_call(state.investigation_id)
    version_2 = await accounting.reserve_call(
        state.investigation_id, expected_version=version_1
    )

    assert (version_1, version_2) == (6, 7)
    assert state.budget.llm_calls_used == 2
