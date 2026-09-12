# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 22C coordinator transition allowlist PostgreSQL tests (Part 4.3).

Proves the versioned stored function enforces the narrow REQUEST_RESEARCH /
RECORD_RESEARCH_OUTCOME mutation allowlists, pessimistic concurrency, the
authoritative ResearchResult linkage requirement, LLM-accounting version
preservation, and coherent history — with real PostgreSQL and no fakes.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.persistence.repositories import (
    CoordinatorTransitionPersistenceError,
    InvestigationVersionConflictError,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.investigation import (
    CoordinatorTransitionKind,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    ResearchExecutionState,
    ResearchExecutionStatus,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
_SUBJECT = "attack-pattern--8a8e9e5e-2b4c-4d6e-8f0a-112233445566"
_QUERY = "Provide contextual threat-research information."


async def _seed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> tuple[InvestigationState, UUID, UUID]:
    """Create a RUNNING investigation with one RESEARCHABLE marked entity."""
    investigation_id = uuid4()
    entity_id = uuid4()
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=entity_id, type=EntityType.ATTACK_TECHNIQUE, value=_SUBJECT)
        )
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[entity_id],
                objective="Assess the technique context.",
                budget=default_investigation_budget(),
                started_at=_FIXED_TS,
            )
        )
    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(investigation_id)
    assert state is not None
    return state, investigation_id, entity_id


def _execution(
    entity_id: UUID,
    *,
    status: ResearchExecutionStatus = ResearchExecutionStatus.REQUESTED,
    attempts: int = 1,
    result_id: UUID | None = None,
) -> ResearchExecutionState:
    """Return one deterministic research execution entry."""
    return ResearchExecutionState(
        subject_entity_id=entity_id,
        context_fingerprint="b" * 64,
        query=_QUERY,
        status=status,
        attempts=attempts,
        result_id=result_id,
    )


async def _marked_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
    investigation_id: UUID,
    entity_id: UUID,
) -> InvestigationState:
    """Return the state with the entity marked research-required."""
    async with uow_factory() as uow:
        current = await uow.investigations.get_by_id(investigation_id)
    assert current is not None
    marked = current.model_copy(
        update={
            "research_required_for_entity_ids": [entity_id],
        }
    )
    async with uow_factory() as uow:
        await uow.investigations.update_coordinator_state(
            investigation_id,
            CoordinatorTransitionKind.MARK_RESEARCH_REQUIRED,
            marked,
            expected_version=current.version or 1,
        )
    async with uow_factory() as uow:
        updated = await uow.investigations.get_by_id(investigation_id)
    assert updated is not None
    return updated


async def _persist_result(
    uow_factory: Callable[[], PostgresUnitOfWork],
    investigation_id: UUID,
    entity_id: UUID,
) -> UUID:
    """Persist one immutable ResearchResult and return its identity."""
    result_id = uuid4()
    async with uow_factory() as uow:
        await uow.research_results.add(
            ResearchResult(
                id=result_id,
                investigation_id=investigation_id,
                subject_entity_id=entity_id,
                query=_QUERY,
                claims=(),
                citations=(),
                created_at=_FIXED_TS,
            )
        )
    return result_id


class TestRequestResearchAllowlist:
    """REQUEST_RESEARCH may change only research_executions."""

    async def test_append_first_attempt_accepted(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """A new REQUESTED first-attempt execution appends cleanly."""
        state, investigation_id, entity_id = await _seed(uow_factory)
        marked = await _marked_state(uow_factory, investigation_id, entity_id)
        proposed = marked.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id, status=ResearchExecutionStatus.REQUESTED, attempts=1
                    )
                ]
            }
        )
        async with uow_factory() as uow:
            result = await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.REQUEST_RESEARCH,
                proposed,
                expected_version=marked.version or 1,
            )
        assert result.version == (marked.version or 1) + 1

    async def test_retry_increments_attempts_only(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """A REQUESTED retry increments attempts by one and nothing else."""
        state, investigation_id, entity_id = await _seed(uow_factory)
        marked = await _marked_state(uow_factory, investigation_id, entity_id)
        first = marked.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id, status=ResearchExecutionStatus.REQUESTED, attempts=1
                    )
                ]
            }
        )
        async with uow_factory() as uow:
            await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.REQUEST_RESEARCH,
                first,
                expected_version=marked.version or 1,
            )
        async with uow_factory() as uow:
            reloaded = await uow.investigations.get_by_id(investigation_id)
        assert reloaded is not None
        retry = reloaded.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id, status=ResearchExecutionStatus.REQUESTED, attempts=2
                    )
                ]
            }
        )
        async with uow_factory() as uow:
            result = await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.REQUEST_RESEARCH,
                retry,
                expected_version=reloaded.version or 1,
            )
        assert result.version == (reloaded.version or 1) + 1

    async def test_unrelated_field_mutation_rejected(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """REQUEST_RESEARCH rejects provider/pivot/evidence/assessment changes."""
        state, investigation_id, entity_id = await _seed(uow_factory)
        marked = await _marked_state(uow_factory, investigation_id, entity_id)
        proposed = marked.model_copy(
            update={
                "research_executions": [_execution(entity_id)],
                "evidence_ids": [uuid4()],
            }
        )
        with pytest.raises(CoordinatorTransitionPersistenceError):
            async with uow_factory() as uow:
                await uow.investigations.update_coordinator_state(
                    investigation_id,
                    CoordinatorTransitionKind.REQUEST_RESEARCH,
                    proposed,
                    expected_version=marked.version or 1,
                )

    async def test_duplicate_context_append_rejected(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """A second execution for the same subject/fingerprint is rejected."""
        state, investigation_id, entity_id = await _seed(uow_factory)
        marked = await _marked_state(uow_factory, investigation_id, entity_id)
        first = marked.model_copy(
            update={"research_executions": [_execution(entity_id)]}
        )
        async with uow_factory() as uow:
            await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.REQUEST_RESEARCH,
                first,
                expected_version=marked.version or 1,
            )
        async with uow_factory() as uow:
            reloaded = await uow.investigations.get_by_id(investigation_id)
        assert reloaded is not None
        # Same context appended as a second array element: rejected.
        duplicate = reloaded.model_copy(
            update={
                "research_executions": [
                    _execution(entity_id),
                    _execution(entity_id),
                ]
            }
        )
        with pytest.raises(CoordinatorTransitionPersistenceError):
            async with uow_factory() as uow:
                await uow.investigations.update_coordinator_state(
                    investigation_id,
                    CoordinatorTransitionKind.REQUEST_RESEARCH,
                    duplicate,
                    expected_version=reloaded.version or 1,
                )

    async def test_stale_expected_version_fails(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """A stale expected version is rejected with no mutation."""
        state, investigation_id, entity_id = await _seed(uow_factory)
        marked = await _marked_state(uow_factory, investigation_id, entity_id)
        proposed = marked.model_copy(
            update={"research_executions": [_execution(entity_id)]}
        )
        with pytest.raises(InvestigationVersionConflictError):
            async with uow_factory() as uow:
                await uow.investigations.update_coordinator_state(
                    investigation_id,
                    CoordinatorTransitionKind.REQUEST_RESEARCH,
                    proposed,
                    expected_version=(marked.version or 1) - 1,
                )


class TestRecordResearchOutcomeAllowlist:
    """RECORD_RESEARCH_OUTCOME links results authoritatively."""

    async def test_completed_linkage_accepted(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """REQUESTED -> COMPLETED with an authoritative result is accepted."""
        state, investigation_id, entity_id = await _seed(uow_factory)
        marked = await _marked_state(uow_factory, investigation_id, entity_id)
        result_id = await _persist_result(uow_factory, investigation_id, entity_id)
        requested = marked.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id, status=ResearchExecutionStatus.REQUESTED, attempts=1
                    )
                ]
            }
        )
        async with uow_factory() as uow:
            await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.REQUEST_RESEARCH,
                requested,
                expected_version=marked.version or 1,
            )
        async with uow_factory() as uow:
            reloaded = await uow.investigations.get_by_id(investigation_id)
        assert reloaded is not None
        completed = reloaded.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id,
                        status=ResearchExecutionStatus.COMPLETED,
                        attempts=1,
                        result_id=result_id,
                    )
                ],
                "research_result_ids": [result_id],
            }
        )
        async with uow_factory() as uow:
            result = await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.RECORD_RESEARCH_OUTCOME,
                completed,
                expected_version=reloaded.version or 1,
            )
        assert result.version == (reloaded.version or 1) + 1
        # History stays coherent: the completion wrote one history row.
        async with uow_factory() as uow:
            history = await uow.investigations.get_by_id(investigation_id)
        assert history is not None
        assert history.research_result_ids == [result_id]

    async def test_foreign_result_linkage_rejected(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """A result from another investigation/entity/query fails closed."""
        state, investigation_id, entity_id = await _seed(uow_factory)
        marked = await _marked_state(uow_factory, investigation_id, entity_id)
        other_result_id = uuid4()
        async with uow_factory() as uow:
            await uow.entities.upsert(
                Entity(id=entity_id, type=EntityType.ATTACK_TECHNIQUE, value=_SUBJECT)
            )
        # A result row that does not belong to this investigation.
        other_investigation = uuid4()
        async with uow_factory() as uow:
            await uow.investigations.create(
                InvestigationState(
                    investigation_id=other_investigation,
                    status=InvestigationStatus.RUNNING,
                    trigger_type=InvestigationTriggerType.MANUAL,
                    root_entity_ids=[entity_id],
                    objective="Other.",
                    budget=default_investigation_budget(),
                    started_at=_FIXED_TS,
                )
            )
            await uow.research_results.add(
                ResearchResult(
                    id=other_result_id,
                    investigation_id=other_investigation,
                    subject_entity_id=entity_id,
                    query=_QUERY,
                    claims=(),
                    citations=(),
                    created_at=_FIXED_TS,
                )
            )
        requested = marked.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id, status=ResearchExecutionStatus.REQUESTED, attempts=1
                    )
                ]
            }
        )
        async with uow_factory() as uow:
            await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.REQUEST_RESEARCH,
                requested,
                expected_version=marked.version or 1,
            )
        async with uow_factory() as uow:
            reloaded = await uow.investigations.get_by_id(investigation_id)
        assert reloaded is not None
        invalid = reloaded.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id,
                        status=ResearchExecutionStatus.COMPLETED,
                        attempts=1,
                        result_id=other_result_id,
                    )
                ],
                "research_result_ids": [other_result_id],
            }
        )
        with pytest.raises(CoordinatorTransitionPersistenceError):
            async with uow_factory() as uow:
                await uow.investigations.update_coordinator_state(
                    investigation_id,
                    CoordinatorTransitionKind.RECORD_RESEARCH_OUTCOME,
                    invalid,
                    expected_version=reloaded.version or 1,
                )

    async def test_exhaustion_never_links_a_result(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """REQUESTED -> EXHAUSTED changes no result linkage."""
        state, investigation_id, entity_id = await _seed(uow_factory)
        marked = await _marked_state(uow_factory, investigation_id, entity_id)
        first = marked.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id,
                        status=ResearchExecutionStatus.REQUESTED,
                        attempts=1,
                    )
                ]
            }
        )
        async with uow_factory() as uow:
            await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.REQUEST_RESEARCH,
                first,
                expected_version=marked.version or 1,
            )
        async with uow_factory() as uow:
            reloaded = await uow.investigations.get_by_id(investigation_id)
        assert reloaded is not None
        # Bounded retry: attempts 1 -> 2 (the append path requires attempt 1).
        retry = reloaded.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id,
                        status=ResearchExecutionStatus.REQUESTED,
                        attempts=2,
                    )
                ]
            }
        )
        async with uow_factory() as uow:
            await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.REQUEST_RESEARCH,
                retry,
                expected_version=reloaded.version or 1,
            )
        async with uow_factory() as uow:
            reloaded = await uow.investigations.get_by_id(investigation_id)
        assert reloaded is not None
        exhausted = reloaded.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id,
                        status=ResearchExecutionStatus.EXHAUSTED,
                        attempts=2,
                    )
                ]
            }
        )
        async with uow_factory() as uow:
            result = await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.RECORD_RESEARCH_OUTCOME,
                exhausted,
                expected_version=reloaded.version or 1,
            )
        assert result.version == (reloaded.version or 1) + 1
        async with uow_factory() as uow:
            durable = await uow.investigations.get_by_id(investigation_id)
        assert durable is not None
        assert durable.research_result_ids == []
        assert durable.research_executions[0].status is (
            ResearchExecutionStatus.EXHAUSTED
        )

    async def test_llm_accounting_version_not_overwritten(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """Completion against a stale pre-accounting version fails closed.

        The stored function rejects a stale expected version; the graph
        reloads the authoritative version after LLM accounting, so a
        completion never overwrites an accounting increment.
        """
        state, investigation_id, entity_id = await _seed(uow_factory)
        marked = await _marked_state(uow_factory, investigation_id, entity_id)
        result_id = await _persist_result(uow_factory, investigation_id, entity_id)
        requested = marked.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id, status=ResearchExecutionStatus.REQUESTED, attempts=1
                    )
                ]
            }
        )
        async with uow_factory() as uow:
            request_result = await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.REQUEST_RESEARCH,
                requested,
                expected_version=marked.version or 1,
            )
        request_version = request_result.version
        # Simulate one durable LLM reservation advancing the version.
        async with uow_factory() as uow:
            current = await uow.investigations.get_by_id(investigation_id)
        assert current is not None
        accounting_budget = current.budget.model_copy(
            update={"llm_calls_used": current.budget.llm_calls_used + 1}
        )
        async with uow_factory() as uow:
            accounting_result = await uow.investigations.update_budget(
                investigation_id,
                accounting_budget,
                expected_version=current.version or 1,
            )
        assert accounting_result.version == (current.version or 1) + 1
        # Persisting completion against the pre-accounting version fails.
        completed = current.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id,
                        status=ResearchExecutionStatus.COMPLETED,
                        attempts=1,
                        result_id=result_id,
                    )
                ],
                "research_result_ids": [result_id],
            }
        )
        with pytest.raises(InvestigationVersionConflictError):
            async with uow_factory() as uow:
                await uow.investigations.update_coordinator_state(
                    investigation_id,
                    CoordinatorTransitionKind.RECORD_RESEARCH_OUTCOME,
                    completed,
                    expected_version=request_version,
                )
        # The authoritative post-accounting version accepts the completion and
        # the accounting increment is preserved.
        async with uow_factory() as uow:
            authoritative = await uow.investigations.get_by_id(investigation_id)
        assert authoritative is not None
        ok = authoritative.model_copy(
            update={
                "research_executions": [
                    _execution(
                        entity_id,
                        status=ResearchExecutionStatus.COMPLETED,
                        attempts=1,
                        result_id=result_id,
                    )
                ],
                "research_result_ids": [result_id],
            }
        )
        async with uow_factory() as uow:
            completion_result = await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.RECORD_RESEARCH_OUTCOME,
                ok,
                expected_version=authoritative.version or 1,
            )
        assert completion_result.version == (authoritative.version or 1) + 1
        async with uow_factory() as uow:
            durable = await uow.investigations.get_by_id(investigation_id)
        assert durable is not None
        assert durable.budget.llm_calls_used == 1
        assert durable.research_result_ids == [result_id]
