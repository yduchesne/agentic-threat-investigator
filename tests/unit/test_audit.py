"""Tests for audit domain rules and transaction emitters."""

# Test doubles intentionally expose narrow async seams.
# pylint: disable=missing-function-docstring,missing-class-docstring,too-few-public-methods,unnecessary-lambda

from types import TracebackType
from typing import Any, cast
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.audit import (
    InMemoryAuditEmitter,
    StandaloneAuditEmitter,
    TransactionalAuditEmitter,
)
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.domain.identity import ActorContext, UserRole


class AuditRepository:
    """Minimal append-only repository fake."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> AuditEvent:
        self.events.append(event)
        return event


class UnitOfWork:
    """Minimal async unit-of-work fake."""

    def __init__(self) -> None:
        self.audit_events = AuditRepository()

    async def __aenter__(self) -> "UnitOfWork":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


@pytest.mark.asyncio
async def test_emitters_record_transactional_and_standalone_events() -> None:
    actor = ActorContext(actor_id=uuid4(), username="alice", role=UserRole.ADMIN)
    memory = InMemoryAuditEmitter()
    await memory.emit(AuditAction.AUTH_LOGIN, AuditOutcome.SUCCESS, actor)
    assert memory.events[0].actor_username == "alice"

    uow = UnitOfWork()
    await TransactionalAuditEmitter(cast(Any, uow)).emit(
        AuditAction.USER_UPDATE, AuditOutcome.SUCCESS, actor, object_type="user"
    )
    assert len(uow.audit_events.events) == 1

    created = []

    def factory() -> UnitOfWork:
        result = UnitOfWork()
        created.append(result)
        return result

    await StandaloneAuditEmitter(cast(Any, factory)).emit(
        AuditAction.AUTH_LOGIN,
        AuditOutcome.FAILURE,
        metadata={"attempted_username": "unknown"},
    )
    assert len(created[0].audit_events.events) == 1


@pytest.mark.asyncio
async def test_standalone_emitter_does_not_propagate_sink_failure() -> None:
    class Broken:
        async def __aenter__(self) -> "Broken":
            raise RuntimeError("database unavailable")

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            return None

    await StandaloneAuditEmitter(cast(Any, lambda: Broken())).emit(
        AuditAction.AUTH_LOGIN, AuditOutcome.FAILURE
    )


def test_audit_validation_and_minimization() -> None:
    with pytest.raises(ValueError, match="ATI action URN"):
        AuditEvent(action="not-an-urn", outcome=AuditOutcome.SUCCESS)
    with pytest.raises(ValueError, match="forbidden"):
        AuditEvent(
            action=AuditAction.AUTH_LOGIN,
            outcome=AuditOutcome.FAILURE,
            metadata={"session_token": "secret"},
        )
    with pytest.raises(ValueError, match="forbidden"):
        AuditEvent(
            action=AuditAction.AUTH_LOGIN,
            outcome=AuditOutcome.FAILURE,
            metadata={"request": {"authorization": "secret"}},
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        AuditEvent(
            action=AuditAction.AUTH_LOGIN,
            outcome=AuditOutcome.SUCCESS,
            occurred_at=__import__("datetime").datetime(2020, 1, 1),
        )


def test_audit_metadata_is_deeply_immutable() -> None:
    """Nested audit metadata cannot be changed after validation."""
    original = {"request": {"attempt": 1}}
    event = AuditEvent(
        action=AuditAction.AUTH_LOGIN,
        outcome=AuditOutcome.FAILURE,
        metadata=original,
    )
    original["request"]["attempt"] = 2

    with pytest.raises(TypeError, match="immutable"):
        event.metadata["request"]["attempt"] = 3

    assert event.metadata["request"]["attempt"] == 1
