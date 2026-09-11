# SPDX-License-Identifier: AGPL-3.0-only
"""Validated, atomic persistence of one versioned Assessment.

This is the narrow PR 20A application seam between a candidate Assessment
(produced by the Evidence Analyst in PR 20B) and durable versioned state.
One short UnitOfWork transaction loads the provenance context, runs the
deterministic validator, persists the Assessment through its repository,
advances the mutable Investigation assessment pointer through its repository,
and appends the required audit event — all together or not at all.

The pointer is updated only after the Assessment row itself has been durably
inserted in the same transaction; any failure rolls back both, so
``InvestigationState.assessment_id`` never reflects a partial Assessment.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from uuid import UUID

from agentic_threat_investigator.app.analysis_result import EvidenceAnalysisResult
from agentic_threat_investigator.app.assessment_provenance import (
    AssessmentProvenanceContext,
    AssessmentProvenanceValidator,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    UnitOfWork,
    enforce_assessment_collection_bounds,
)
from agentic_threat_investigator.domain.assessment import Assessment, EvidenceSupport
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)

LOGGER = logging.getLogger(__name__)

ASSESSMENT_OBJECT_TYPE = "assessment"


class AssessmentPersistenceService:
    """Persist one validated Assessment atomically with its Investigation pointer.

    No provider, network, dispatcher, or LLM call is performed; the service
    only assembles the provenance snapshot, validates it deterministically,
    and writes through the repository seam. ``batch_size`` is the
    configurable application limit applied to every bounded Assessment
    candidate collection before any UnitOfWork entry or provenance read.
    """

    def __init__(
        self, uow_factory: Callable[[], UnitOfWork], batch_size: int = 100
    ) -> None:
        """Bind the service to a UnitOfWork factory and the batch limit."""
        if batch_size < 1:
            raise ValueError("assessment batch size must be positive")
        self._uow_factory = uow_factory
        self._batch_size = batch_size

    async def persist_assessment(
        self,
        assessment: Assessment,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_investigation_version: int | None = None,
    ) -> Assessment:
        """Validate and persist the Assessment or fail without side effects.

        On validation failure, persistence failure, or a stale Investigation
        version, the UnitOfWork rolls back and the typed error propagates;
        ``InvestigationState.assessment_id`` is never updated in memory and
        the durable pointer is only advanced once the Assessment row itself
        has been durably inserted. Oversized candidate collections are
        rejected before the UnitOfWork is entered.
        """
        result = await self._persist(
            assessment,
            actor_id=actor_id,
            request_id=request_id,
            expected_investigation_version=expected_investigation_version,
        )
        return result.assessment

    async def persist_assessment_with_result(
        self,
        assessment: Assessment,
        disposition: AnalysisDisposition,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_investigation_version: int | None = None,
    ) -> EvidenceAnalysisResult:
        """Persist one Assessment atomically with its analysis metadata (PR 21).

        One short transaction writes the new immutable Assessment, the
        Investigation current Assessment pointer, the exact analyzed Evidence
        identities, the typed disposition, and the Investigation version/
        history update. The returned result carries the authoritative
        Investigation version after the transaction so the caller never
        persists coordinator state against a stale version.
        """
        return await self._persist(
            assessment,
            disposition=disposition,
            actor_id=actor_id,
            request_id=request_id,
            expected_investigation_version=expected_investigation_version,
        )

    async def _persist(
        self,
        assessment: Assessment,
        *,
        disposition: AnalysisDisposition | None = None,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_investigation_version: int | None = None,
    ) -> EvidenceAnalysisResult:
        """Validate and persist the Assessment atomically with metadata."""
        # Reject oversized candidate collections before the UnitOfWork is
        # entered and before any provenance read; only the collection name,
        # count, and limit are reported.
        enforce_assessment_collection_bounds(assessment, self._batch_size)
        async with self._uow_factory() as uow:
            context = await self._load_provenance_context(uow, assessment)
            AssessmentProvenanceValidator().validate(assessment, context)
            persisted = await uow.assessments.insert(
                assessment, actor_id=actor_id, request_id=request_id
            )
            if persisted.id is None:  # pragma: no cover - insert assigns an id
                raise RuntimeError("assessment persistence returned no identity")
            if disposition is not None:
                # The analysis write requires the exact pre-write Investigation
                # version. The analyst flow supplies it from the durable LLM
                # reservation chain; the no-evidence path reads it fresh.
                expected_version = expected_investigation_version
                if expected_version is None:
                    current_state = await uow.investigations.get_by_id(
                        assessment.investigation_id
                    )
                    if current_state is None or current_state.version is None:
                        raise InvestigationNotFoundError(
                            str(assessment.investigation_id)
                        )
                    expected_version = current_state.version
                # One coherent Investigation transition records the pointer,
                # the exact analyzed Evidence identities, and the disposition
                # in a single version/history row.
                analysis_result = await uow.investigations.set_analysis_result(
                    assessment.investigation_id,
                    persisted.id,
                    list(assessment.analyzed_evidence_ids),
                    disposition,
                    actor_id=actor_id,
                    request_id=request_id,
                    expected_version=expected_version,
                )
                latest_version = analysis_result.version
            else:
                pointer_result = await uow.investigations.update_assessment_reference(
                    assessment.investigation_id,
                    persisted.id,
                    actor_id=actor_id,
                    request_id=request_id,
                    expected_version=expected_investigation_version,
                )
                latest_version = pointer_result.version
            await uow.audit_events.append(
                AuditEvent(
                    action=AuditAction.ASSESSMENT_CREATE,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_id,
                    object_type=ASSESSMENT_OBJECT_TYPE,
                    object_id=persisted.id,
                    request_id=request_id,
                    metadata={
                        "investigation_id": str(assessment.investigation_id),
                        "version": persisted.version or 1,
                    },
                )
            )
        LOGGER.debug(
            "persisted assessment %s for investigation %s (version %s)",
            persisted.id,
            assessment.investigation_id,
            persisted.version,
        )
        return EvidenceAnalysisResult(
            assessment=persisted,
            disposition=disposition or AnalysisDisposition.EXHAUSTED,
            investigation_version=latest_version,
        )

    async def delete_assessment(
        self,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Assessment:
        """Soft-delete the Assessment and emit its audit event atomically.

        Deletion and the ``ASSESSMENT_DELETE`` audit event commit in one
        UnitOfWork transaction: a rolled-back deletion emits no success
        audit event. Deleting the current Assessment of a visible
        Investigation is a typed conflict (the approved PR 20A policy), so a
        visible Investigation can never retain an invalid pointer.
        """
        async with self._uow_factory() as uow:
            deleted = await uow.assessments.soft_delete(
                assessment_id,
                actor_id=actor_id,
                request_id=request_id,
                expected_version=expected_version,
            )
            if deleted.id is None:  # pragma: no cover - delete returns identity
                raise RuntimeError("assessment deletion returned no identity")
            await uow.audit_events.append(
                AuditEvent(
                    action=AuditAction.ASSESSMENT_DELETE,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_id,
                    object_type=ASSESSMENT_OBJECT_TYPE,
                    object_id=deleted.id,
                    request_id=request_id,
                    metadata={
                        "investigation_id": str(deleted.investigation_id),
                        "version": deleted.version or 1,
                    },
                )
            )
        LOGGER.debug("soft-deleted assessment %s", deleted.id)
        return deleted

    @staticmethod
    async def _load_provenance_context(
        uow: UnitOfWork, assessment: Assessment
    ) -> AssessmentProvenanceContext:
        """Assemble the immutable snapshot the validator may consult.

        Reads stay inside the same short transaction as the write; the
        stored function revalidates the critical integrity (parent visibility
        under lock and every support resolution) as defense in depth.
        """
        # Loading several correlated resource maps in one loop per resource is
        # intrinsic; the branch/local counts reflect that shape.
        investigation = await uow.investigations.get_by_id(assessment.investigation_id)
        evidence_ids = set(assessment.analyzed_evidence_ids)
        observation_ids: set[UUID] = set()
        for finding in assessment.findings:
            for support in finding.support:
                if isinstance(support, EvidenceSupport):
                    evidence_ids.add(support.evidence_id)
                else:
                    observation_ids.add(support.relationship_observation_id)

        evidence: dict[UUID, Evidence] = {}
        for evidence_id in list(evidence_ids):
            evidence_row = await uow.evidence.get_by_id(evidence_id)
            if evidence_row is not None:
                evidence[evidence_id] = evidence_row

        observations: dict[UUID, RelationshipObservation] = {}
        for observation_id in observation_ids:
            observation_row = await uow.relationship_observations.get_by_id(
                observation_id
            )
            if observation_row is not None:
                observations[observation_id] = observation_row
                pending = observation_row.evidence_id
                if pending not in evidence:
                    pending_row = await uow.evidence.get_by_id(pending)
                    if pending_row is not None:
                        evidence[pending] = pending_row

        relationships: dict[UUID, Relationship] = {}
        pending_relationships = {
            observation.relationship_id for observation in observations.values()
        }
        for relationship_id in pending_relationships:
            relationship_row = await uow.relationships.get_by_id(relationship_id)
            if relationship_row is not None:
                relationships[relationship_id] = relationship_row

        entities: dict[UUID, Entity] = {}
        pending_entities = {
            endpoint
            for relationship in relationships.values()
            for endpoint in (
                relationship.source_entity_id,
                relationship.target_entity_id,
            )
        }
        for entity_id in pending_entities:
            entity_row = await uow.entities.get_by_id(entity_id)
            if entity_row is not None:
                entities[entity_id] = entity_row

        return AssessmentProvenanceContext(
            investigation=investigation,
            evidence=evidence,
            relationship_observations=observations,
            relationships=relationships,
            entities=entities,
        )
