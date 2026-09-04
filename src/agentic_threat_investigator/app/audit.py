# SPDX-License-Identifier: AGPL-3.0-only
"""Application audit emitters and transaction-aware audit wiring."""

# The structured event contract intentionally has optional context fields.
# pylint: disable=too-few-public-methods,too-many-arguments,broad-exception-caught
from abc import ABC, abstractmethod
from typing import Any, Callable
from uuid import UUID

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.domain.identity import ActorContext


class AuditEmitter(ABC):
    """Port for emitting minimized audit events."""

    @abstractmethod
    async def emit(
        self,
        action: str | AuditAction,
        outcome: str | AuditOutcome,
        actor: ActorContext | None = None,
        *,
        object_type: str | None = None,
        object_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
        request_id: UUID | None = None,
    ) -> None:
        """Emit one event."""


class InMemoryAuditEmitter(AuditEmitter):
    """Deterministic audit fake for unit tests."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def emit(
        self,
        action: str | AuditAction,
        outcome: str | AuditOutcome,
        actor: ActorContext | None = None,
        *,
        object_type: str | None = None,
        object_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
        request_id: UUID | None = None,
    ) -> None:
        """Record the event in memory."""
        self.events.append(
            AuditEvent(
                action=action,
                outcome=AuditOutcome(outcome),
                actor_id=actor.actor_id if actor else None,
                actor_username=actor.username if actor else None,
                object_type=object_type,
                object_id=object_id,
                metadata=metadata or {},
                request_id=request_id,
            )
        )


class TransactionalAuditEmitter(AuditEmitter):
    """Append events to an already active unit of work."""

    def __init__(self, unit_of_work: UnitOfWork) -> None:
        self._uow = unit_of_work

    async def emit(
        self,
        action: str | AuditAction,
        outcome: str | AuditOutcome,
        actor: ActorContext | None = None,
        *,
        object_type: str | None = None,
        object_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
        request_id: UUID | None = None,
    ) -> None:
        """Append to the active UoW, leaving commit ownership with its caller."""
        await self._uow.audit_events.append(
            AuditEvent(
                action=action,
                outcome=AuditOutcome(outcome),
                actor_id=actor.actor_id if actor else None,
                actor_username=actor.username if actor else None,
                object_type=object_type,
                object_id=object_id,
                metadata=metadata or {},
                request_id=request_id,
            )
        )


class StandaloneAuditEmitter(AuditEmitter):
    """Persist events in an independent transaction and fail open."""

    def __init__(self, unit_of_work_factory: Callable[[], UnitOfWork]) -> None:
        self._factory = unit_of_work_factory

    async def emit(
        self,
        action: str | AuditAction,
        outcome: str | AuditOutcome,
        actor: ActorContext | None = None,
        *,
        object_type: str | None = None,
        object_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
        request_id: UUID | None = None,
    ) -> None:
        """Write independently; audit availability never changes the result."""
        try:
            async with self._factory() as uow:
                await TransactionalAuditEmitter(uow).emit(
                    action,
                    outcome,
                    actor,
                    object_type=object_type,
                    object_id=object_id,
                    metadata=metadata,
                    request_id=request_id,
                )
        except Exception:  # pragma: no cover - logging policy belongs to deployment
            return
