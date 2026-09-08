# SPDX-License-Identifier: AGPL-3.0-only
"""Thin PostgreSQL repository adapter for the investigation resource.

The database owns version allocation, authoritative timestamps, conflict
detection, and immutable history. This adapter serializes the domain model,
invokes the versioned stored functions, and deserializes authoritative rows.

Persistence operations deliberately carry one explicit argument per supported
correlation/concurrency dimension (actor, request, expected version) instead
of an untyped criteria map.
"""

# Explicit actor/request/expected-version arguments are intentional.
# pylint: disable=too-many-arguments

import json
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    InvestigationDuplicateIdentityError,
    InvestigationNotFoundError,
    InvestigationRepository,
    InvestigationVersionConflictError,
    InvestigationWriteResult,
)
from agentic_threat_investigator.domain.investigation import (
    InvalidInvestigationStatusTransitionError,
    InvestigationState,
    InvestigationStatus,
    require_status_transition,
)

from .errors import (
    SQLSTATE_INVALID_TRANSITION,
    SQLSTATE_INVESTIGATION_DUPLICATE,
    SQLSTATE_INVESTIGATION_NOT_FOUND,
    SQLSTATE_VERSION_CONFLICT,
    sqlstate,
)
from .models import InvestigationRow

# InvestigationState fields stored inside the operational_state JSONB document.
# The remaining domain fields map to dedicated ati.investigation columns.
_OPERATIONAL_FIELDS = (
    "trigger_id",
    "root_entity_ids",
    "discovered_entity_ids",
    "evidence_ids",
    "relationship_ids",
    "pending_pivots",
    "investigated_entity_ids",
    "research_required_for_entity_ids",
    "research_result_ids",
    "assessment_id",
    "report_id",
    "stop_reason",
    "errors",
)


def _to_domain(row: InvestigationRow) -> InvestigationState:
    """Rebuild the domain resource with its authoritative persistence metadata.

    Database-owned columns are applied after the operational-state JSONB
    document so stored values can never override authoritative columns.
    """
    payload: dict[str, object] = {
        "investigation_id": row.id,
        "status": row.status,
        "trigger_type": row.trigger_type,
        "objective": row.objective,
        "budget": row.budget,
        **(row.operational_state or {}),
        "started_at": row.started_at,
        "completed_at": row.completed_at,
        "version": row.version,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "deleted_at": row.deleted_at,
        "deleted_by_actor_id": row.deleted_by_actor_id,
    }
    return InvestigationState.model_validate(payload)


def _serialized(state: InvestigationState) -> tuple[str, str]:
    """Return the JSON budget and operational-state documents for persistence.

    Database-owned persistence metadata is never serialized into the stored
    documents; callers cannot override database-owned values.
    """
    payload = state.model_dump(
        mode="json",
        exclude={
            "investigation_id",
            "version",
            "created_at",
            "updated_at",
            "deleted_at",
            "deleted_by_actor_id",
        },
    )
    budget = json.dumps(payload["budget"])
    operational = json.dumps({field: payload[field] for field in _OPERATIONAL_FIELDS})
    return budget, operational


class PostgresInvestigationRepository(InvestigationRepository):
    """Persist investigation resources through the caller's transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        """Return the visible resource, hiding soft-deleted rows by default."""
        query = select(InvestigationRow).where(InvestigationRow.id == investigation_id)
        if not include_deleted:
            query = query.where(InvestigationRow.deleted_at.is_(None))
        row = (await self.session.execute(query)).scalar_one_or_none()
        return None if row is None else _to_domain(row)

    async def create(
        self,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> InvestigationWriteResult:
        """Create the resource and return its database-assigned version."""
        budget, operational = _serialized(state)
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, created FROM ati.create_investigation(
                        :id, :status, :trigger_type, :objective,
                        CAST(:budget AS jsonb), CAST(:operational_state AS jsonb),
                        :started_at, :completed_at, :actor_id, :request_id)
                """),
                {
                    "id": state.investigation_id,
                    "status": state.status.value,
                    "trigger_type": state.trigger_type.value,
                    "objective": state.objective,
                    "budget": budget,
                    "operational_state": operational,
                    "started_at": state.started_at,
                    "completed_at": state.completed_at,
                    "actor_id": actor_id,
                    "request_id": request_id,
                },
            )
        except DBAPIError as error:
            if sqlstate(error) == SQLSTATE_INVESTIGATION_DUPLICATE:
                raise InvestigationDuplicateIdentityError(
                    state.investigation_id
                ) from error
            raise
        written_id, version, _created = result.one()
        return InvestigationWriteResult(written_id, int(version), BatchOutcome.INSERTED)

    async def update_status(
        self,
        investigation_id: UUID,
        status: InvestigationStatus,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Change the status with database-owned version/history semantics.

        The confirmed lifecycle is validated before the database mutation and
        again against the locked row inside the SQL function, so a concurrent
        writer cannot invalidate a transition after the pre-lock check. A
        stale expected version produces a typed conflict and no mutation.
        """
        current = await self.get_by_id(investigation_id)
        if current is None:
            raise InvestigationNotFoundError(str(investigation_id))
        if status is not current.status:
            require_status_transition(current.status, status)
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, outcome FROM ati.update_investigation_status(
                        :id, :status, :actor_id, :request_id, :expected_version)
                """),
                {
                    "id": investigation_id,
                    "status": status.value,
                    "actor_id": actor_id,
                    "request_id": request_id,
                    "expected_version": expected_version,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_INVESTIGATION_NOT_FOUND:
                raise InvestigationNotFoundError(str(investigation_id)) from error
            if state == SQLSTATE_INVALID_TRANSITION:
                # The locked row moved between the pre-lock check and the
                # mutation; surface the domain error rather than a raw DBAPI
                # exception.
                raise InvalidInvestigationStatusTransitionError(
                    f"investigation {investigation_id} no longer permits "
                    f"transition to {status.value}"
                ) from error
            if state == SQLSTATE_VERSION_CONFLICT:
                raise InvestigationVersionConflictError(
                    investigation_id, expected_version or 0
                ) from error
            raise
        written_id, version, outcome = result.one()
        return InvestigationWriteResult(
            written_id,
            int(version),
            BatchOutcome.UPDATED if outcome == "UPDATED" else BatchOutcome.UNCHANGED,
        )

    async def soft_delete(
        self,
        investigation_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Soft-delete the resource and return its post-deletion version."""
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version FROM ati.soft_delete_investigation(
                        :id, :actor_id, :request_id, :expected_version)
                """),
                {
                    "id": investigation_id,
                    "actor_id": actor_id,
                    "request_id": request_id,
                    "expected_version": expected_version,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_INVESTIGATION_NOT_FOUND:
                raise InvestigationNotFoundError(str(investigation_id)) from error
            if state == SQLSTATE_VERSION_CONFLICT:
                raise InvestigationVersionConflictError(
                    investigation_id, expected_version or 0
                ) from error
            raise
        written_id, version = result.one()
        return InvestigationWriteResult(written_id, int(version), BatchOutcome.UPDATED)
