# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL integration coverage for investigation persistence."""

# pylint: disable=redefined-outer-name

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.investigation_persistence import (
    InvestigationPersistenceService,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationDuplicateIdentityError,
    InvestigationNotFoundError,
    InvestigationVersionConflictError,
    InvestigationWriteResult,
)
from agentic_threat_investigator.domain.audit import AuditAction, AuditEvent
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
    InvalidInvestigationStatusTransitionError,
    InvestigationBudget,
    InvestigationError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    PivotRequest,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.audit_repositories import (
    PostgresAuditEventRepository,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.errors import (
    SQLSTATE_INVALID_TRANSITION,
    sqlstate,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.investigation_repositories import (
    PostgresInvestigationRepository,
)

_STARTED_AT = datetime(2026, 1, 1, tzinfo=UTC)


class _ExplodingAuditRepository(PostgresAuditEventRepository):
    """Audit repository that deterministically fails after the mutation."""

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Always fail the audit dependency in the caller's transaction."""
        raise RuntimeError("audit dependency failed")


class _ExplodingAuditUow(PostgresUnitOfWork):
    """Unit of work whose audit repository fails inside the transaction."""

    async def __aenter__(self) -> _ExplodingAuditUow:
        unit = await super().__aenter__()
        assert unit.session is not None
        unit.audit_events = _ExplodingAuditRepository(unit.session)
        return unit


def investigation_state(
    *,
    status: InvestigationStatus = InvestigationStatus.PENDING,
    investigation_id: UUID | None = None,
) -> InvestigationState:
    """Build a complete valid investigation state for integration tests."""
    return InvestigationState(
        investigation_id=investigation_id or uuid4(),
        status=status,
        trigger_type=InvestigationTriggerType.MANUAL,
        trigger_id=uuid4(),
        root_entity_ids=[uuid4()],
        objective="Assess the root indicator.",
        pending_pivots=[
            PivotRequest(entity_id=uuid4(), reason="evidence-backed probe", depth=1)
        ],
        errors=[
            InvestigationError(
                code="synthetic", message="synthetic probe", recoverable=True
            )
        ],
        budget=InvestigationBudget(
            max_depth=2,
            max_entities=10,
            max_provider_calls=40,
            max_replans=3,
            provider_calls_used=5,
            replans_used=1,
        ),
        started_at=_STARTED_AT,
    )


async def history_rows(
    uow: PostgresUnitOfWork, object_type: str, object_id: UUID
) -> list[tuple[int, str, str | None]]:
    """Return bounded (version, operation, diff) history rows for an object."""
    assert uow.session is not None
    result = await uow.session.execute(
        text("""
            SELECT version, operation, diff::text FROM ati.domain_object_history
            WHERE object_type = :object_type AND object_id = :object_id
            ORDER BY version
        """),
        {"object_type": object_type, "object_id": object_id},
    )
    return [(row[0], row[1], row[2]) for row in result.fetchall()]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_create_read_round_trip(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Creation persists the resource with a database-assigned version."""
    state = investigation_state()
    async with uow_factory() as uow:
        result = await uow.investigations.create(
            state, actor_id=uuid4(), request_id=uuid4()
        )
        assert result.investigation_id == state.investigation_id
        assert result.version >= 1
        created_version = result.version

        round_tripped = await uow.investigations.get_by_id(state.investigation_id)
        assert round_tripped is not None
        assert round_tripped.investigation_id == state.investigation_id
        assert round_tripped.status is InvestigationStatus.PENDING
        assert round_tripped.objective == state.objective
        assert round_tripped.trigger_id == state.trigger_id
        assert round_tripped.root_entity_ids == state.root_entity_ids
        assert round_tripped.pending_pivots == state.pending_pivots
        assert round_tripped.errors == state.errors
        assert round_tripped.budget.provider_calls_used == 5
        assert round_tripped.budget.replans_used == 1
        assert round_tripped.started_at == _STARTED_AT
        assert round_tripped.completed_at is None
        # The fresh read returns the exact database-assigned version from the
        # write result plus authoritative tz-aware metadata.
        assert round_tripped.version == created_version
        assert round_tripped.created_at is not None
        assert round_tripped.created_at.tzinfo is not None
        assert round_tripped.updated_at is not None
        assert round_tripped.updated_at.tzinfo is not None
        assert round_tripped.deleted_at is None
        assert round_tripped.deleted_by_actor_id is None

        # Persistence metadata is never serialized into the stored documents.
        assert uow.session is not None
        stored_documents = (
            await uow.session.execute(
                text("""
                    SELECT budget, operational_state FROM ati.investigation
                    WHERE id = :id
                """),
                {"id": state.investigation_id},
            )
        ).one()
        metadata_keys = {
            "version",
            "created_at",
            "updated_at",
            "deleted_at",
            "deleted_by_actor_id",
        }
        assert metadata_keys.isdisjoint(stored_documents[0])
        assert metadata_keys.isdisjoint(stored_documents[1])

    async with uow_factory() as uow:
        assert (await uow.investigations.get_by_id(state.investigation_id)) is not None
        # CREATE history carries the complete state and an empty diff.
        assert await history_rows(uow, "investigation", state.investigation_id) == [
            (created_version, "CREATE", "{}")
        ]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_status_update_allocates_version_and_diff(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A real transition allocates a new version and writes a status diff."""
    state = investigation_state()
    async with uow_factory() as uow:
        created = await uow.investigations.create(state)
        first_version = created.version

        result = await uow.investigations.update_status(
            state.investigation_id,
            InvestigationStatus.RUNNING,
            actor_id=uuid4(),
            request_id=uuid4(),
            expected_version=first_version,
        )
        assert result.version > first_version

        round_tripped = await uow.investigations.get_by_id(state.investigation_id)
        assert round_tripped is not None
        assert round_tripped.status is InvestigationStatus.RUNNING
        assert round_tripped.completed_at is None

    async with uow_factory() as uow:
        rows = await history_rows(uow, "investigation", state.investigation_id)
        assert [(version, operation) for version, operation, _ in rows] == [
            (first_version, "CREATE"),
            (result.version, "UPDATE"),
        ]
        diff = rows[-1][2]
        assert diff is not None
        assert '"status"' in diff
        assert '"old": "pending"' in diff
        assert '"new": "running"' in diff
        assert '"version"' not in diff


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_terminal_transition_stamps_completed_at(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A terminal transition stamps completed_at when absent."""
    state = investigation_state()
    async with uow_factory() as uow:
        await uow.investigations.create(state)
        running = await uow.investigations.update_status(
            state.investigation_id, InvestigationStatus.RUNNING
        )
        await uow.investigations.update_status(
            state.investigation_id,
            InvestigationStatus.COMPLETED,
            expected_version=running.version,
        )
        round_tripped = await uow.investigations.get_by_id(state.investigation_id)
        assert round_tripped is not None
        assert round_tripped.status is InvestigationStatus.COMPLETED
        assert round_tripped.completed_at is not None
        assert round_tripped.completed_at.tzinfo is not None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_unchanged_status_allocates_no_version(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A same-status request is an unchanged no-op without version or history."""
    state = investigation_state()
    async with uow_factory() as uow:
        created = await uow.investigations.create(state)
        first_version = created.version

        result = await uow.investigations.update_status(
            state.investigation_id,
            InvestigationStatus.PENDING,
            expected_version=first_version,
        )
        assert result.version == first_version

    async with uow_factory() as uow:
        assert (
            len(await history_rows(uow, "investigation", state.investigation_id)) == 1
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_invalid_transition_rejected_before_mutation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An invalid lifecycle transition is rejected before database mutation."""
    state = investigation_state()
    async with uow_factory() as uow:
        await uow.investigations.create(state)
        running = await uow.investigations.update_status(
            state.investigation_id, InvestigationStatus.RUNNING
        )
        current_version = running.version

        with pytest.raises(InvalidInvestigationStatusTransitionError):
            await uow.investigations.update_status(
                state.investigation_id,
                InvestigationStatus.PENDING,
                expected_version=current_version,
            )
        round_tripped = await uow.investigations.get_by_id(state.investigation_id)
        assert round_tripped is not None
        assert round_tripped.status is InvestigationStatus.RUNNING

    async with uow_factory() as uow:
        rows = await history_rows(uow, "investigation", state.investigation_id)
        assert [operation for _, operation, _ in rows] == ["CREATE", "UPDATE"]
        assert rows[-1][0] == current_version


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_stale_version_conflicts_without_mutation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A stale expected version conflicts without mutating target state."""
    state = investigation_state()
    async with uow_factory() as uow:
        created = await uow.investigations.create(state)
        first_version = created.version
        running = await uow.investigations.update_status(
            state.investigation_id, InvestigationStatus.RUNNING
        )
        current_version = running.version

    async with uow_factory() as uow:
        # The stored function raises a typed conflict; the caller rolls back
        # the surrounding unit of work.
        with pytest.raises(InvestigationVersionConflictError):
            await uow.investigations.update_status(
                state.investigation_id,
                InvestigationStatus.FAILED,
                expected_version=first_version,  # stale expectation
            )

    async with uow_factory() as uow:
        round_tripped = await uow.investigations.get_by_id(state.investigation_id)
        assert round_tripped is not None
        assert round_tripped.status is InvestigationStatus.RUNNING
        assert round_tripped.budget.provider_calls_used == 5

    async with uow_factory() as uow:
        rows = await history_rows(uow, "investigation", state.investigation_id)
        assert [operation for _, operation, _ in rows] == ["CREATE", "UPDATE"]
        assert current_version == rows[-1][0]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_duplicate_identity_conflicts(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A duplicate caller-supplied identity is a conflict, never an overwrite."""
    state = investigation_state()
    async with uow_factory() as uow:
        await uow.investigations.create(state)
    async with uow_factory() as uow:
        with pytest.raises(InvestigationDuplicateIdentityError):
            await uow.investigations.create(
                investigation_state(investigation_id=state.investigation_id)
            )
    async with uow_factory() as uow:
        assert (
            len(await history_rows(uow, "investigation", state.investigation_id)) == 1
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_not_found_error(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Mutating an absent investigation raises the typed not-found error."""
    async with uow_factory() as uow:
        with pytest.raises(InvestigationNotFoundError):
            await uow.investigations.update_status(uuid4(), InvestigationStatus.RUNNING)
        with pytest.raises(InvestigationNotFoundError):
            await uow.investigations.soft_delete(uuid4())


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_soft_delete_hides_normal_reads(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Soft deletion follows the standard visibility conventions."""
    state = investigation_state()
    actor_id = uuid4()
    async with uow_factory() as uow:
        created = await uow.investigations.create(state)
        deleted = await uow.investigations.soft_delete(
            state.investigation_id,
            actor_id=actor_id,
            expected_version=created.version,
        )
        assert deleted.version > created.version
        assert await uow.investigations.get_by_id(state.investigation_id) is None
        hidden = await uow.investigations.get_by_id(
            state.investigation_id, include_deleted=True
        )
        assert hidden is not None
        assert hidden.investigation_id == state.investigation_id

    async with uow_factory() as uow:
        rows = await history_rows(uow, "investigation", state.investigation_id)
        assert [operation for _, operation, _ in rows] == ["CREATE", "DELETE"]
        assert rows[-1][0] == deleted.version


@pytest.mark.asyncio
@pytest.mark.integration
async def test_investigation_rollback_removes_uncommitted_work(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An uncommitted mutation disappears after the unit of work rolls back."""
    state = investigation_state()
    with pytest.raises(RuntimeError, match="injected failure"):
        async with uow_factory() as uow:
            await uow.investigations.create(state)
            raise RuntimeError("injected failure")

    async with uow_factory() as uow:
        assert await uow.investigations.get_by_id(state.investigation_id) is None
        assert await history_rows(uow, "investigation", state.investigation_id) == []


@pytest.mark.asyncio
@pytest.mark.integration
async def test_service_commits_investigation_with_audit_atomically(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The service commits resource mutation, history, and audit together."""
    service = InvestigationPersistenceService(uow_factory)
    state = investigation_state()

    result = await service.create_investigation(
        state, actor_id=uuid4(), request_id=uuid4()
    )
    running = await service.update_investigation_status(
        state.investigation_id,
        InvestigationStatus.RUNNING,
        actor_id=uuid4(),
        expected_version=result.version,
    )
    assert running.version > result.version

    async with uow_factory() as uow:
        assert uow.session is not None
        events = (
            (
                await uow.session.execute(
                    text("""
                        SELECT action FROM ati.audit_event
                        WHERE object_type = 'investigation'
                          AND object_id = :object_id
                        ORDER BY occurred_at, version
                    """),
                    {"object_id": state.investigation_id},
                )
            )
            .scalars()
            .all()
        )
        assert list(events) == [
            AuditAction.INVESTIGATION_CREATE.value,
            AuditAction.INVESTIGATION_UPDATE_STATUS.value,
        ]
        rows = await history_rows(uow, "investigation", state.investigation_id)
        assert [operation for _, operation, _ in rows] == ["CREATE", "UPDATE"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_service_audit_failure_rolls_back_everything(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A failure after the first mutation rolls back every PR 18A mutation."""
    service = InvestigationPersistenceService(
        lambda: _ExplodingAuditUow(session_factory)
    )
    state = investigation_state()

    with pytest.raises(RuntimeError, match="audit dependency failed"):
        await service.create_investigation(state, actor_id=uuid4())

    async with uow_factory() as uow:
        assert await uow.investigations.get_by_id(state.investigation_id) is None
        assert await history_rows(uow, "investigation", state.investigation_id) == []
        assert uow.session is not None
        count = (
            await uow.session.execute(
                text("SELECT count(*) FROM ati.audit_event WHERE object_id = :id"),
                {"id": state.investigation_id},
            )
        ).scalar_one()
        assert count == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_service_evidence_audit_failure_rolls_back_evidence(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A failed evidence audit dependency leaves no evidence row behind."""
    service = InvestigationPersistenceService(
        lambda: _ExplodingAuditUow(session_factory)
    )
    state = investigation_state()
    async with uow_factory() as uow:
        entity = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="example.com")
        )
        entity_id = entity.id
        await uow.investigations.create(state)

    evidence = Evidence(
        investigation_id=state.investigation_id,
        type=EvidenceType.DNS,
        subject=EntityRef(id=entity_id, type=EntityType.DOMAIN, value="example.com"),
        source="urn:ati:source:google_public_dns",
        retrieved_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        facts={"answers": ["192.0.2.1"]},
    )

    with pytest.raises(RuntimeError, match="audit dependency failed"):
        await service.record_evidence(evidence, actor_id=uuid4())

    async with uow_factory() as uow:
        assert uow.session is not None
        count = (
            await uow.session.execute(
                text("SELECT count(*) FROM ati.evidence WHERE investigation_id = :id"),
                {"id": state.investigation_id},
            )
        ).scalar_one()
        assert count == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_status_update_changes_version_and_updated_at(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A transition returns a new version and refreshed authoritative times."""
    state = investigation_state()
    async with uow_factory() as uow:
        created = await uow.investigations.create(state)
    async with uow_factory() as uow:
        updated = await uow.investigations.update_status(
            state.investigation_id, InvestigationStatus.RUNNING
        )
    async with uow_factory() as uow:
        round_tripped = await uow.investigations.get_by_id(state.investigation_id)
        assert round_tripped is not None
        assert round_tripped.version == updated.version > created.version
        assert round_tripped.created_at is not None
        assert round_tripped.updated_at is not None
        assert round_tripped.updated_at >= round_tripped.created_at
        assert round_tripped.updated_at.tzinfo is not None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_soft_deleted_read_returns_deletion_metadata(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An administrative read reveals deletion state, actor, and version."""
    state = investigation_state()
    actor_id = uuid4()
    async with uow_factory() as uow:
        created = await uow.investigations.create(state)
        deleted = await uow.investigations.soft_delete(
            state.investigation_id, actor_id=actor_id
        )
    async with uow_factory() as uow:
        assert await uow.investigations.get_by_id(state.investigation_id) is None
        hidden = await uow.investigations.get_by_id(
            state.investigation_id, include_deleted=True
        )
        assert hidden is not None
        assert hidden.deleted_at is not None
        assert hidden.deleted_at.tzinfo is not None
        assert hidden.deleted_by_actor_id == actor_id
        assert hidden.version == deleted.version > created.version


@pytest.mark.asyncio
@pytest.mark.integration
async def test_fresh_read_version_supports_optimistic_update(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A version obtained by a fresh read drives a later optimistic update."""
    state = investigation_state()
    async with uow_factory() as uow:
        await uow.investigations.create(state)
    async with uow_factory() as uow:
        read = await uow.investigations.get_by_id(state.investigation_id)
        assert read is not None and read.version is not None
    async with uow_factory() as uow:
        result = await uow.investigations.update_status(
            state.investigation_id,
            InvestigationStatus.RUNNING,
            expected_version=read.version,
        )
        assert result.version is not None and result.version > read.version


@pytest.mark.asyncio
@pytest.mark.integration
async def test_started_at_column_is_not_nullable(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The schema requires a non-null started_at."""
    async with uow_factory() as uow:
        assert uow.session is not None
        nullable = (await uow.session.execute(text("""
                    SELECT is_nullable FROM information_schema.columns
                    WHERE table_schema = 'ati'
                      AND table_name = 'investigation'
                      AND column_name = 'started_at'
                """))).scalar_one()
        assert nullable == "NO"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_locked_row_rejects_disallowed_transitions(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The locked SQL function rejects every disallowed transition."""
    disallowed = [
        (InvestigationStatus.PENDING, InvestigationStatus.COMPLETED),
        (InvestigationStatus.PENDING, InvestigationStatus.PARTIAL),
        (InvestigationStatus.RUNNING, InvestigationStatus.PENDING),
        (InvestigationStatus.COMPLETED, InvestigationStatus.RUNNING),
        (InvestigationStatus.COMPLETED, InvestigationStatus.FAILED),
        (InvestigationStatus.PARTIAL, InvestigationStatus.PENDING),
        (InvestigationStatus.FAILED, InvestigationStatus.RUNNING),
    ]
    for current, target in disallowed:
        state = investigation_state(status=current)
        async with uow_factory() as uow:
            await uow.investigations.create(state)
        async with uow_factory() as uow:
            assert uow.session is not None
            with pytest.raises(DBAPIError) as error_info:
                await uow.session.execute(
                    text("SELECT * FROM ati.update_investigation_status(:id, :status)"),
                    {"id": state.investigation_id, "status": target.value},
                )
            assert sqlstate(error_info.value) == SQLSTATE_INVALID_TRANSITION
        async with uow_factory() as uow:
            round_tripped = await uow.investigations.get_by_id(state.investigation_id)
            assert round_tripped is not None
            assert round_tripped.status is current
            rows = await history_rows(uow, "investigation", state.investigation_id)
            assert [operation for _, operation, _ in rows] == ["CREATE"]


class _SnapshotGatedRepository(PostgresInvestigationRepository):
    """Test-only repository exposing the stale pre-lock snapshot interval.

    The subclass records the pre-lock status snapshot and then pauses until a
    gate opens, so a second writer can commit a lifecycle-invalidating
    transition inside the window the SQL function must defend.
    """

    def __init__(
        self, session: AsyncSession, ready: asyncio.Event, gate: asyncio.Event
    ) -> None:
        super().__init__(session)
        self._ready = ready
        self._gate = gate
        self.observed: InvestigationStatus | None = None

    async def update_status(
        self,
        investigation_id: UUID,
        status: InvestigationStatus,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Snapshot, wait for the gate, then reach the locked SQL function."""
        current = await self.get_by_id(investigation_id)
        assert current is not None
        self.observed = current.status
        self._ready.set()
        await self._gate.wait()
        return await super().update_status(
            investigation_id,
            status,
            actor_id=actor_id,
            request_id=request_id,
            expected_version=expected_version,
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_invalid_transition_is_rejected_on_locked_row(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A transition invalidated between check and write cannot be persisted."""
    state = investigation_state()
    async with uow_factory() as uow:
        await uow.investigations.create(state)

    failed_ready, failed_gate = asyncio.Event(), asyncio.Event()
    running_ready, running_gate = asyncio.Event(), asyncio.Event()
    repos: dict[str, _SnapshotGatedRepository] = {}

    async def failed_writer() -> object:
        async with uow_factory() as uow:
            assert uow.session is not None
            gated = _SnapshotGatedRepository(uow.session, failed_ready, failed_gate)
            uow.investigations = gated
            repos["failed"] = gated
            try:
                return await gated.update_status(
                    state.investigation_id, InvestigationStatus.FAILED
                )
            except InvalidInvestigationStatusTransitionError as error:
                return error

    async def running_writer() -> object:
        async with uow_factory() as uow:
            assert uow.session is not None
            gated = _SnapshotGatedRepository(uow.session, running_ready, running_gate)
            uow.investigations = gated
            repos["running"] = gated
            try:
                return await gated.update_status(
                    state.investigation_id, InvestigationStatus.RUNNING
                )
            except InvalidInvestigationStatusTransitionError as error:
                return error

    failed_task = asyncio.create_task(failed_writer())
    running_task = asyncio.create_task(running_writer())
    # Both writers complete their pre-lock snapshots before either mutation;
    # each observed PENDING.
    await asyncio.wait_for(failed_ready.wait(), 5)
    await asyncio.wait_for(running_ready.wait(), 5)

    # The FAILED writer completes its locked-row transition first.
    failed_gate.set()
    failed_outcome = await asyncio.wait_for(failed_task, 5)
    assert isinstance(failed_outcome, InvestigationWriteResult)
    assert failed_outcome.outcome is not None

    # The RUNNING writer reaches the SQL function with its stale PENDING
    # snapshot; the locked row is now FAILED and the transition must be
    # rejected with the typed domain error.
    running_gate.set()
    running_outcome = await asyncio.wait_for(running_task, 5)
    assert isinstance(running_outcome, InvalidInvestigationStatusTransitionError)
    # Both pre-lock snapshots observed PENDING, proving the stale snapshot
    # window the locked-row validation defends.
    assert repos["failed"].observed is InvestigationStatus.PENDING
    assert repos["running"].observed is InvestigationStatus.PENDING

    async with uow_factory() as uow:
        round_tripped = await uow.investigations.get_by_id(state.investigation_id)
        assert round_tripped is not None
        assert round_tripped.status is InvestigationStatus.FAILED
        rows = await history_rows(uow, "investigation", state.investigation_id)
        assert [operation for _, operation, _ in rows] == ["CREATE", "UPDATE"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_duplicate_investigation_identity_is_typed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A concurrent duplicate identity produces the typed error, never 23505."""
    state = investigation_state()

    async def create_writer() -> object:
        async with uow_factory() as uow:
            try:
                return await uow.investigations.create(state)
            except InvestigationDuplicateIdentityError as error:
                return error

    outcomes = await asyncio.gather(
        asyncio.wait_for(create_writer(), 10),
        asyncio.wait_for(create_writer(), 10),
    )
    winners = [o for o in outcomes if isinstance(o, InvestigationWriteResult)]
    losers = [o for o in outcomes if isinstance(o, InvestigationDuplicateIdentityError)]
    assert len(winners) == 1 and len(losers) == 1
    assert winners[0].investigation_id == state.investigation_id

    async with uow_factory() as uow:
        stored = await uow.investigations.get_by_id(state.investigation_id)
        assert stored is not None
        assert stored.status is state.status
        assert stored.objective == state.objective
        rows = await history_rows(uow, "investigation", state.investigation_id)
        assert [operation for _, operation, _ in rows] == ["CREATE"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_colliding_operational_state_cannot_spoof_columns(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Dedicated columns win even when operational_state collides with them."""
    state = investigation_state()
    async with uow_factory() as uow:
        created = await uow.investigations.create(state)
        created_version = created.version

    # Test-only corruption: replace the stored JSONB document with values
    # Pydantic would otherwise accept, colliding with every dedicated column.
    # The autouse fixture truncates the table afterwards.
    spoofed_actor_id = uuid4()
    spoofed_operational_state = {
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
        "deleted_by_actor_id": str(spoofed_actor_id),
        # A legitimate operational field survives alongside the collisions.
        "trigger_id": str(state.trigger_id),
        "root_entity_ids": [str(entity) for entity in state.root_entity_ids],
        "stop_reason": "sufficient_evidence",
        "errors": [],
    }
    async with uow_factory() as uow:
        assert uow.session is not None
        await uow.session.execute(
            text("""
                UPDATE ati.investigation
                SET operational_state = CAST(:document AS jsonb)
                WHERE id = :id
            """),
            {
                "document": json.dumps(spoofed_operational_state),
                "id": state.investigation_id,
            },
        )

    async with uow_factory() as uow:
        round_tripped = await uow.investigations.get_by_id(state.investigation_id)
        assert round_tripped is not None
        # Every dedicated column keeps its authoritative value.
        assert round_tripped.investigation_id == state.investigation_id
        assert round_tripped.status is InvestigationStatus.PENDING
        assert round_tripped.trigger_type is InvestigationTriggerType.MANUAL
        assert round_tripped.objective == state.objective
        assert round_tripped.budget.max_depth == 2
        assert round_tripped.budget.provider_calls_used == 5
        assert round_tripped.started_at == _STARTED_AT
        assert round_tripped.completed_at is None
        assert round_tripped.version == created_version
        assert round_tripped.created_at is not None
        assert round_tripped.created_at.year == 2026
        assert round_tripped.updated_at is not None
        assert round_tripped.updated_at.tzinfo is not None
        assert round_tripped.deleted_at is None
        assert round_tripped.deleted_by_actor_id is None
        # Legitimate operational fields still come from operational_state.
        assert round_tripped.trigger_id == state.trigger_id
        assert round_tripped.root_entity_ids == state.root_entity_ids
        assert round_tripped.stop_reason == "sufficient_evidence"
