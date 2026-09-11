# SPDX-License-Identifier: AGPL-3.0-only
"""Application orchestration for investigation and evidence persistence.

This service owns the explicit UnitOfWork boundary for the narrow PR 18A
persistence seam. Provider/LLM calls stay outside transactions; each operation
performs its repository mutations and required audit work in one short
transaction that commits exactly once.

Operations deliberately carry one explicit argument per supported
correlation/concurrency dimension (actor, request, expected version) instead
of an untyped criteria map.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from uuid import UUID

from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    InvestigationWriteResult,
    UnitOfWork,
)
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    require_status_transition,
)

# Explicit actor/request/expected-version arguments are intentional.


LOGGER = logging.getLogger(__name__)

INVESTIGATION_OBJECT_TYPE = "investigation"
EVIDENCE_OBJECT_TYPE = "evidence"


class InvestigationPersistenceService:
    """Persist investigation resources and evidence in short atomic transactions.

    Every operation enters one UnitOfWork, mutates through repositories,
    records the required audit event in the same transaction, and commits
    exactly once. On any failure the unit of work rolls back and the typed
    persistence error propagates.
    """

    def __init__(self, uow_factory: Callable[[], UnitOfWork]) -> None:
        self._uow_factory = uow_factory

    async def create_investigation(
        self,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> InvestigationWriteResult:
        """Create the investigation resource with its audit event."""
        async with self._uow_factory() as uow:
            result = await uow.investigations.create(
                state, actor_id=actor_id, request_id=request_id
            )
            await uow.audit_events.append(
                self._investigation_event(
                    AuditAction.INVESTIGATION_CREATE,
                    state.investigation_id,
                    actor_id,
                    request_id,
                    result.version,
                )
            )
        LOGGER.debug(
            "created investigation %s at version %d",
            result.investigation_id,
            result.version,
        )
        return result

    async def update_investigation_status(
        self,
        investigation_id: UUID,
        status: InvestigationStatus,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Change the investigation status with its audit event.

        The confirmed lifecycle is validated before any database mutation; a
        stale expected version produces a typed conflict without silently
        overwriting current state.
        """
        async with self._uow_factory() as uow:
            current = await uow.investigations.get_by_id(investigation_id)
            if current is None:
                raise InvestigationNotFoundError(str(investigation_id))
            if status is not current.status:
                require_status_transition(current.status, status)
            result = await uow.investigations.update_status(
                investigation_id,
                status,
                actor_id=actor_id,
                request_id=request_id,
                expected_version=expected_version,
            )
            await uow.audit_events.append(
                self._investigation_event(
                    AuditAction.INVESTIGATION_UPDATE_STATUS,
                    investigation_id,
                    actor_id,
                    request_id,
                    result.version,
                )
            )
        LOGGER.debug(
            "updated investigation %s status to %s (version %d, %s)",
            investigation_id,
            status.value,
            result.version,
            result.outcome.value,
        )
        return result

    async def record_evidence(
        self,
        evidence: Evidence,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Evidence:
        """Record one immutable evidence observation with its audit event.

        The observation is appended for an existing, visible investigation;
        the investigation reference and audit event commit together with the
        evidence row.
        """
        async with self._uow_factory() as uow:
            if await uow.investigations.get_by_id(evidence.investigation_id) is None:
                raise InvestigationNotFoundError(str(evidence.investigation_id))
            recorded = await uow.evidence.insert(
                evidence, actor_id=actor_id, request_id=request_id
            )
            await uow.audit_events.append(
                AuditEvent(
                    action=AuditAction.EVIDENCE_RECORD,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_id,
                    object_type=EVIDENCE_OBJECT_TYPE,
                    object_id=recorded.id,
                    request_id=request_id,
                    metadata={
                        "investigation_id": str(evidence.investigation_id),
                    },
                )
            )
        LOGGER.debug("recorded evidence %s", recorded.id)
        return recorded

    async def delete_investigation(
        self,
        investigation_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Soft-delete the investigation resource with its audit event."""
        async with self._uow_factory() as uow:
            result = await uow.investigations.soft_delete(
                investigation_id,
                actor_id=actor_id,
                request_id=request_id,
                expected_version=expected_version,
            )
            await uow.audit_events.append(
                self._investigation_event(
                    AuditAction.INVESTIGATION_DELETE,
                    investigation_id,
                    actor_id,
                    request_id,
                    result.version,
                )
            )
        LOGGER.debug("soft-deleted investigation %s", investigation_id)
        return result

    @staticmethod
    def _investigation_event(
        action: AuditAction,
        investigation_id: UUID,
        actor_id: UUID | None,
        request_id: UUID | None,
        version: int,
    ) -> AuditEvent:
        """Build the minimized audit event for one investigation mutation."""
        return AuditEvent(
            action=action,
            outcome=AuditOutcome.SUCCESS,
            actor_id=actor_id,
            object_type=INVESTIGATION_OBJECT_TYPE,
            object_id=investigation_id,
            request_id=request_id,
            metadata={"version": version},
        )
