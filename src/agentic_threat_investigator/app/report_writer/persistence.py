# SPDX-License-Identifier: AGPL-3.0-only
"""Validated, atomic persistence of one versioned InvestigationReport (PR 23B).

This is the narrow application seam between a fully validated
:class:`InvestigationReport` candidate (assembled and provenance-validated by
the Report Writer) and durable versioned state. One short UnitOfWork
transaction appends the report through its repository, advances the mutable
Investigation ``report_id`` pointer through its repository, and appends the
``REPORT_CREATE`` audit event — all together or not at all.

The pointer is updated only after the report row itself has been durably
inserted in the same transaction; any failure rolls back both, so
``InvestigationState.report_id`` never reflects a partial report. The report
append revalidates under the locked Investigation row that the report's
Assessment is still the current Assessment; a stale input fails atomically.

This service never calls the LLM. The Report Writer service calls it only
after model execution and provenance validation, keeping model execution
separate from transactional persistence.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from uuid import UUID

from agentic_threat_investigator.app.persistence.repositories import (
    UnitOfWork,
    enforce_report_collection_bounds,
)
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.domain.report import InvestigationReport

LOGGER = logging.getLogger(__name__)

REPORT_OBJECT_TYPE = "investigation_report"


class InvestigationReportPersistenceService:
    """Persist one validated report atomically with its Investigation pointer.

    No provider, network, dispatcher, or LLM call is performed; the service
    only validates collection bounds, writes through the repository seam, and
    reloads the authoritative persisted report. ``batch_size`` is the
    configurable application limit applied to every bounded report candidate
    collection before any UnitOfWork entry.
    """

    def __init__(
        self, uow_factory: Callable[[], UnitOfWork], batch_size: int = 100
    ) -> None:
        """Bind the service to a UnitOfWork factory and the batch limit."""
        if batch_size < 1:
            raise ValueError("report batch size must be positive")
        self._uow_factory = uow_factory
        self._batch_size = batch_size

    async def persist(
        self,
        report: InvestigationReport,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_investigation_version: int | None = None,
    ) -> InvestigationReport:
        """Persist the validated report or fail without side effects.

        On a stale Assessment (revalidated under lock), a stale Investigation
        version, a duplicate identity, or any persistence failure, the
        UnitOfWork rolls back and the typed error propagates;
        ``InvestigationState.report_id`` is never updated in memory and the
        durable pointer is only advanced once the report row itself has been
        durably inserted. Oversized candidate collections are rejected before
        the UnitOfWork is entered.
        """
        # Reject oversized candidate collections before the UnitOfWork is
        # entered and before any SQL serialization; only the collection name,
        # count, and limit are reported.
        enforce_report_collection_bounds(report, self._batch_size)
        async with self._uow_factory() as uow:
            persisted = await uow.investigation_reports.append(
                report, actor_id=actor_id, request_id=request_id
            )
            if persisted.id is None:  # pragma: no cover - append assigns an id
                raise RuntimeError("report persistence returned no identity")
            await uow.investigations.update_report_reference(
                report.investigation_id,
                persisted.id,
                actor_id=actor_id,
                request_id=request_id,
                expected_version=expected_investigation_version,
            )
            await uow.audit_events.append(
                AuditEvent(
                    action=AuditAction.REPORT_CREATE,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_id,
                    object_type=REPORT_OBJECT_TYPE,
                    object_id=persisted.id,
                    request_id=request_id,
                    metadata={
                        "investigation_id": str(report.investigation_id),
                        "version": persisted.version or 1,
                    },
                )
            )
        LOGGER.debug(
            "persisted report %s for investigation %s (version %s)",
            persisted.id,
            report.investigation_id,
            persisted.version,
        )
        return await self.reload(persisted.id)

    async def soft_delete(
        self,
        report_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationReport:
        """Soft-delete a superseded report and emit its audit event atomically.

        Deletion and the ``REPORT_DELETE`` audit event commit in one
        UnitOfWork transaction: a rolled-back deletion emits no success audit
        event. Deleting the current report of a visible Investigation is a
        typed conflict (mirroring the approved Assessment deletion policy), so
        a visible Investigation can never retain an invalid pointer.
        """
        async with self._uow_factory() as uow:
            deleted = await uow.investigation_reports.soft_delete(
                report_id,
                actor_id=actor_id,
                request_id=request_id,
                expected_version=expected_version,
            )
            if deleted.id is None:  # pragma: no cover - delete returns identity
                raise RuntimeError("report deletion returned no identity")
            await uow.audit_events.append(
                AuditEvent(
                    action=AuditAction.REPORT_DELETE,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_id,
                    object_type=REPORT_OBJECT_TYPE,
                    object_id=deleted.id,
                    request_id=request_id,
                    metadata={
                        "investigation_id": str(deleted.investigation_id),
                        "version": deleted.version or 1,
                    },
                )
            )
        LOGGER.debug("soft-deleted report %s", deleted.id)
        return deleted

    async def reload(self, report_id: UUID) -> InvestigationReport:
        """Return the authoritative persisted report in a fresh read scope.

        The caller receives the database round-trip, so the returned report
        reflects exactly what durable state holds.
        """
        async with self._uow_factory() as uow:
            reloaded = await uow.investigation_reports.get_by_id(report_id)
        if reloaded is None:
            raise LookupError(f"report not found after persistence: {report_id}")
        return reloaded
