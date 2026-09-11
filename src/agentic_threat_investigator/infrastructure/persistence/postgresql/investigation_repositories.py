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

import json
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.assessment_provenance import (
    AssessmentProvenanceMismatchError,
)
from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    CoordinatorTransitionPersistenceError,
    InvestigationDuplicateIdentityError,
    InvestigationNotFoundError,
    InvestigationRepository,
    InvestigationVersionConflictError,
    InvestigationWriteResult,
)
from agentic_threat_investigator.domain.investigation import (
    CoordinatorTransitionKind,
    InvalidInvestigationStatusTransitionError,
    InvestigationBudget,
    InvestigationBudgetExhaustedError,
    InvestigationState,
    InvestigationStatus,
    require_status_transition,
)

from .errors import (
    SQLSTATE_ASSESSMENT_REFERENCE_INVALID,
    SQLSTATE_BUDGET_COUNTERS_INVALID,
    SQLSTATE_COORDINATOR_STATE_INVALID,
    SQLSTATE_INVALID_TRANSITION,
    SQLSTATE_INVESTIGATION_DUPLICATE,
    SQLSTATE_INVESTIGATION_NOT_FOUND,
    SQLSTATE_LLM_BUDGET_EXHAUSTED,
    SQLSTATE_OPTIMISTIC_VERSION_REQUIRED,
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
    "pending_provider_work",
    "completed_provider_work",
    "current_provider_work",
    "last_provider_outcome",
    "investigated_entity_ids",
    "research_required_for_entity_ids",
    "research_result_ids",
    "assessment_id",
    "report_id",
    "stop_reason",
    "errors",
    "analyzed_evidence_ids",
    "analysis_disposition",
    "traversal",
)


def _to_domain(row: InvestigationRow) -> InvestigationState:
    """Rebuild the domain resource with its authoritative persistence metadata.

    The payload starts from the operational-state JSONB document, then every
    dedicated database column is applied after the expansion so the
    authoritative value always wins: colliding ``operational_state`` keys
    cannot replace the identity, lifecycle state, trigger type, objective,
    budget, timestamps, version, or deletion metadata. The JSONB document is
    never mutated in place.
    """
    payload: dict[str, object] = {
        **(row.operational_state or {}),
        "investigation_id": row.id,
        "status": row.status,
        "trigger_type": row.trigger_type,
        "objective": row.objective,
        "budget": row.budget,
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

    async def update_budget(
        self,
        investigation_id: UUID,
        budget: InvestigationBudget,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Replace the budget under Investigation version/history semantics.

        The database revalidates the counters and performs the versioned
        UPDATE and immutable history write; a stale expected version surfaces
        as ``InvestigationVersionConflictError``, an exhausted or malformed
        budget as the typed budget errors, all with no partial mutation. An
        identical budget is an UNCHANGED no-op.
        """
        serialized = json.dumps(budget.model_dump(mode="json"))
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, outcome FROM ati.update_investigation_budget(
                        :id, CAST(:budget AS jsonb), :actor_id, :request_id,
                        :expected_version)
                """),
                {
                    "id": investigation_id,
                    "budget": serialized,
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
            if state == SQLSTATE_LLM_BUDGET_EXHAUSTED:
                raise InvestigationBudgetExhaustedError(
                    "investigation LLM budget exhausted"
                ) from error
            if state == SQLSTATE_BUDGET_COUNTERS_INVALID:
                raise ValueError("invalid investigation budget counters") from error
            raise
        written_id, version, outcome = result.one()
        return InvestigationWriteResult(
            written_id,
            int(version),
            BatchOutcome.UPDATED if outcome == "UPDATED" else BatchOutcome.UNCHANGED,
        )

    async def update_assessment_reference(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Point the investigation at its current Assessment through the SQL API.

        The database owns the operational-state mutation, version allocation,
        and UPDATE history; the pointer only advances after the Assessment
        row itself has been durably inserted in the same transaction.
        """
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, outcome FROM ati.set_investigation_assessment(
                        :id, :assessment_id, :actor_id, :request_id, :expected_version)
                """),
                {
                    "id": investigation_id,
                    "assessment_id": assessment_id,
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
            if state == SQLSTATE_ASSESSMENT_REFERENCE_INVALID:
                # The target Assessment is missing, does not belong to this
                # Investigation, or was soft-deleted (possibly concurrently).
                raise AssessmentProvenanceMismatchError(
                    f"assessment reference is invalid for investigation "
                    f"{investigation_id}: {assessment_id}"
                ) from error
            raise
        written_result_id, written_version, outcome = result.one()
        return InvestigationWriteResult(
            written_result_id,
            int(written_version),
            BatchOutcome.UPDATED if outcome == "UPDATED" else BatchOutcome.UNCHANGED,
        )

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
        """Atomically record one coherent analysis result (PR 21).

        The stored function locks the Investigation and target Assessment,
        verifies ownership and exact analyzed Evidence identity equality,
        fails on stale/missing versions, and writes the pointer, the analyzed
        set, and the disposition in ONE version/history row.
        """
        disposition_value = (
            disposition.value if hasattr(disposition, "value") else disposition
        )
        serialized_ids = json.dumps(analyzed_evidence_ids, default=str)
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, outcome
                    FROM ati.set_investigation_analysis_result(
                        :id, :assessment_id, CAST(:analyzed_ids AS jsonb),
                        :disposition, :actor_id, :request_id,
                        :expected_version)
                """),
                {
                    "id": investigation_id,
                    "assessment_id": assessment_id,
                    "analyzed_ids": serialized_ids,
                    "disposition": disposition_value,
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
                    investigation_id, expected_version
                ) from error
            if state == SQLSTATE_ASSESSMENT_REFERENCE_INVALID:
                raise AssessmentProvenanceMismatchError(
                    f"assessment reference is invalid for investigation "
                    f"{investigation_id}: {assessment_id}"
                ) from error
            if state == SQLSTATE_COORDINATOR_STATE_INVALID:
                raise ValueError(
                    f"invalid analysis result for investigation {investigation_id}"
                ) from error
            raise
        written_id, version, outcome = result.one()
        return InvestigationWriteResult(
            written_id,
            int(version),
            BatchOutcome.UPDATED if outcome == "UPDATED" else BatchOutcome.UNCHANGED,
        )

    async def update_coordinator_state(
        self,
        investigation_id: UUID,
        transition_kind: CoordinatorTransitionKind,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        consumes_replan: bool = False,
    ) -> InvestigationWriteResult:
        """Atomically persist coordinator operational state (PR 21).

        The transition kind bounds the allowed field/counter changes, the
        optimistic ``expected_version`` is mandatory, and the supplied state
        must belong to the target investigation. The stored function locks the
        row, revalidates budget monotonicity/maxima and the status lifecycle,
        replaces the operational JSON document and budget, allocates the
        version, writes immutable history, and sets ``completed_at`` when the
        transition is terminal. A semantically identical state is an
        UNCHANGED no-op.
        """
        if state.investigation_id != investigation_id:
            raise ValueError(
                "coordinator transition state investigation does not match "
                "the target investigation"
            )
        kind_value = (
            transition_kind.value
            if hasattr(transition_kind, "value")
            else str(transition_kind)
        )
        budget, operational = _serialized(state)
        status = state.status.value
        try:
            result = await self.session.execute(
                text("""
                    SELECT id, version, outcome
                    FROM ati.update_investigation_coordinator_state(
                        :id, :transition_kind, :status, CAST(:budget AS jsonb),
                        CAST(:operational_state AS jsonb), :consumes_replan, :actor_id,
                        :request_id, :expected_version)
                """),
                {
                    "id": investigation_id,
                    "transition_kind": kind_value,
                    "status": status,
                    "budget": budget,
                    "operational_state": operational,
                    "consumes_replan": consumes_replan,
                    "actor_id": actor_id,
                    "request_id": request_id,
                    "expected_version": expected_version,
                },
            )
        except DBAPIError as error:
            state_code = sqlstate(error)
            if state_code == SQLSTATE_INVESTIGATION_NOT_FOUND:
                raise InvestigationNotFoundError(str(investigation_id)) from error
            if state_code == SQLSTATE_VERSION_CONFLICT:
                raise InvestigationVersionConflictError(
                    investigation_id, expected_version
                ) from error
            if state_code == SQLSTATE_INVALID_TRANSITION:
                raise InvalidInvestigationStatusTransitionError(
                    f"investigation {investigation_id} no longer permits "
                    f"transition to {status}"
                ) from error
            if state_code in (
                SQLSTATE_COORDINATOR_STATE_INVALID,
                SQLSTATE_OPTIMISTIC_VERSION_REQUIRED,
            ):
                raise CoordinatorTransitionPersistenceError(
                    f"invalid coordinator {kind_value} transition for "
                    f"investigation {investigation_id}"
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
