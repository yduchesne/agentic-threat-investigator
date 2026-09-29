# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL support presentation resolution (PR 31F-5).

One bounded set-oriented read per resource kind: the Investigation scope
is exclusively the ``ati.investigation_evidence`` admission, so
cross-Investigation support IDs fail closed (absent) and unadmitted global
observations never appear. Raw provider payloads and observation URLs are
never selected.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from agentic_threat_investigator.app.query.support_presentations import (
    EvidenceSupportPresentation,
    RelationshipObservationSupportPresentation,
    SupportPresentationQuery,
    SupportPresentationQueryService,
    SupportPresentationResult,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType
from agentic_threat_investigator.infrastructure.persistence.postgresql.models import (
    EntityRow,
    EvidenceObservationEntityRow,
    EvidenceObservationRow,
    EvidenceRow,
    InvestigationEvidenceRow,
    RelationshipObservationRow,
    RelationshipRow,
)


class PostgresSupportPresentationQueryService(SupportPresentationQueryService):
    """Resolve support presentations through one bounded read session."""

    def __init__(self, session: AsyncSession) -> None:
        """Bind the read session (one short-lived request scope)."""
        self._session = session

    async def resolve(
        self, query: SupportPresentationQuery
    ) -> SupportPresentationResult:
        """Resolve the requested support-ID sets in Investigation scope.

        Evidence subjects use the same deterministic association semantics
        as the Evidence read projection (first associated Entity by id) and
        the same admission scope; relationship observations join their
        stable edge and endpoint Entities exactly once in Investigation
        scope. Both reads bound the ``IN`` list to the validated per-kind
        request cap.
        """
        return SupportPresentationResult(
            evidence=await self._resolve_evidence(query),
            relationship_observations=await self._resolve_observations(query),
        )

    async def _resolve_evidence(
        self, query: SupportPresentationQuery
    ) -> tuple[EvidenceSupportPresentation, ...]:
        """Resolve one bounded set of Evidence support identities."""
        requested = query.evidence_observation_ids
        if not requested:
            return ()
        # The first associated Entity in deterministic Entity-id order
        # matches the Evidence read subject semantics exactly (PR 28B);
        # outer joins keep an observation resolvable without an Entity.
        subject_entity = aliased(EntityRow)
        first_association = (
            select(EvidenceObservationEntityRow.entity_id)
            .join(
                EntityRow,
                EntityRow.id == EvidenceObservationEntityRow.entity_id,
            )
            .where(
                EvidenceObservationEntityRow.evidence_observation_id
                == EvidenceObservationRow.id,
                EntityRow.deleted_at.is_(None),
            )
            .order_by(EntityRow.id)
            .limit(1)
            .correlate(EvidenceObservationRow)
            .scalar_subquery()
        )
        rows = (
            await self._session.execute(
                select(
                    EvidenceObservationRow.id,
                    EvidenceRow.evidence_type,
                    EvidenceRow.source,
                    subject_entity.id,
                    subject_entity.entity_type,
                    subject_entity.canonical_value,
                )
                .join(
                    EvidenceRow,
                    EvidenceRow.id == EvidenceObservationRow.evidence_id,
                )
                .join(
                    InvestigationEvidenceRow,
                    InvestigationEvidenceRow.evidence_observation_id
                    == EvidenceObservationRow.id,
                )
                .join(
                    subject_entity,
                    subject_entity.id == first_association,
                    isouter=True,
                )
                .where(
                    EvidenceObservationRow.id.in_(requested),
                    InvestigationEvidenceRow.investigation_id == query.investigation_id,
                )
                .order_by(EvidenceObservationRow.id)
            )
        ).fetchall()
        return tuple(
            EvidenceSupportPresentation(
                evidence_observation_id=observation_id,
                evidence_type=EvidenceType(evidence_type),
                source=source,
                subject_entity_id=subject_entity_id,
                subject_entity_type=(
                    None
                    if subject_entity_type is None
                    else EntityType(subject_entity_type)
                ),
                subject_entity_value=subject_entity_value,
            )
            for (
                observation_id,
                evidence_type,
                source,
                subject_entity_id,
                subject_entity_type,
                subject_entity_value,
            ) in rows
        )

    async def _resolve_observations(
        self,
        query: SupportPresentationQuery,
    ) -> tuple[RelationshipObservationSupportPresentation, ...]:
        """Resolve one bounded set of RelationshipObservation support IDs."""
        requested = query.relationship_observation_ids
        if not requested:
            return ()
        # Resolve the target Entity row through a distinct alias so the
        # source/target presentation columns stay independent in one query.
        target_entity_row = aliased(EntityRow)
        rows = (
            await self._session.execute(
                select(
                    RelationshipObservationRow.id,
                    RelationshipObservationRow.relationship_id,
                    RelationshipObservationRow.observed_at,
                    RelationshipRow.relationship_type_urn,
                    RelationshipRow.source_entity_id,
                    EntityRow.entity_type,
                    EntityRow.canonical_value,
                    RelationshipRow.target_entity_id,
                    target_entity_row.entity_type,
                    target_entity_row.canonical_value,
                )
                .join(
                    RelationshipRow,
                    RelationshipRow.id == RelationshipObservationRow.relationship_id,
                )
                .join(
                    InvestigationEvidenceRow,
                    InvestigationEvidenceRow.evidence_observation_id
                    == RelationshipObservationRow.evidence_observation_id,
                )
                .join(
                    EntityRow,
                    EntityRow.id == RelationshipRow.source_entity_id,
                    isouter=True,
                )
                .join(
                    target_entity_row,
                    target_entity_row.id == RelationshipRow.target_entity_id,
                    isouter=True,
                )
                .where(
                    RelationshipObservationRow.id.in_(requested),
                    InvestigationEvidenceRow.investigation_id == query.investigation_id,
                )
                .order_by(RelationshipObservationRow.id)
            )
        ).fetchall()
        return tuple(
            RelationshipObservationSupportPresentation(
                relationship_observation_id=observation_id,
                relationship_id=relationship_id,
                observed_at=observed_at,
                relationship_type=RelationshipType(relationship_type_urn),
                source_entity_id=source_entity_id,
                source_entity_type=(
                    None
                    if source_entity_type is None
                    else EntityType(source_entity_type)
                ),
                source_entity_value=source_entity_value,
                target_entity_id=target_entity_id,
                target_entity_type=(
                    None
                    if target_entity_type is None
                    else EntityType(target_entity_type)
                ),
                target_entity_value=target_entity_value,
            )
            for (
                observation_id,
                relationship_id,
                observed_at,
                relationship_type_urn,
                source_entity_id,
                source_entity_type,
                source_entity_value,
                target_entity_id,
                target_entity_type,
                target_entity_value,
            ) in rows
        )
