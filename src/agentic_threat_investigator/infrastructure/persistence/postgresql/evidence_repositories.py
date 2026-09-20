# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapters for the PR 28B global Evidence persistence boundary.

PostgreSQL owns every authoritative invariant through SQL API v0026:
stable Evidence metadata validation, atomic Evidence + observation v1
creation, race-safe per-Evidence version allocation, material no-op
detection, canonical diffs, idempotent observation/Entity association, and
exact Investigation admission. These adapters only serialize the domain
contracts, invoke the versioned stored functions, and deserialize the
authoritative rows; they never allocate versions and never self-commit.
"""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceMetadataConflictError,
    EvidenceObservationEntityRepository,
    EvidenceObservationInputError,
    EvidenceObservationNotFoundError,
    EvidencePersistenceOutcome,
    EvidencePersistenceResult,
    EvidenceRepository,
    InvalidDiscoveredFromProvenanceError,
    InvestigationEvidenceAdmissionConflictError,
    InvestigationEvidenceRepository,
)
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservation,
    EvidenceObservationEntity,
    EvidenceType,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.telemetry.decorators import (
    postgres_repository_operation,
)

from .errors import (
    SQLSTATE_EVIDENCE_METADATA_CONFLICT,
    SQLSTATE_EVIDENCE_OBSERVATION_INPUT_INVALID,
    SQLSTATE_EVIDENCE_OBSERVATION_MISSING,
    SQLSTATE_INVESTIGATION_ADDITION_INVALID_DISCOVERED_FROM,
    SQLSTATE_INVESTIGATION_ADMISSION_CONFLICT,
    SQLSTATE_INVESTIGATION_NOT_FOUND,
    sqlstate,
)
from .models import (
    EvidenceObservationEntityRow,
    EvidenceObservationRow,
    EvidenceRow,
    InvestigationEvidenceRow,
)

_PROBE_LIMIT_CEILING = 1001
"""One above the Evidence Analyst's accepted observation maximum (1000)."""


def _evidence(row: EvidenceRow) -> Evidence:
    """Map a stable Evidence row to its domain model."""
    return Evidence(
        id=row.id,
        type=EvidenceType(row.evidence_type),
        source=row.source,
        source_record_id=row.source_record_id,
    )


def observation_from_row(row: EvidenceObservationRow) -> EvidenceObservation:
    """Map an EvidenceObservation row to its immutable domain model."""
    return EvidenceObservation(
        id=row.id,
        evidence_id=row.evidence_id,
        version=row.version,
        source_url=row.source_url,
        observed_at=row.observed_at,
        retrieved_at=row.retrieved_at,
        facts=row.facts,
        raw_payload=row.raw_payload,
        diff=row.diff,
    )


class PostgresEvidenceRepository(EvidenceRepository):
    """Persist and read global Evidence through the active transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @postgres_repository_operation(
        repository="PostgresEvidenceRepository", operation="persist"
    )
    async def persist(
        self, converted: ConvertedEvidence, *, observation_id: UUID | None = None
    ) -> EvidencePersistenceResult:
        """Persist or reuse the exact observation of one ConvertedEvidence.

        EvidenceObservation is authoritative intelligence history and never
        writes generic ``domain_object_history`` rows.
        """
        candidate = converted.observation
        try:
            result = await self._session.execute(
                text("""
                    SELECT evidence_id, evidence_observation_id, version, outcome
                    FROM ati.persist_evidence_observation(
                        :evidence_id, :evidence_type, :source, :source_record_id,
                        :source_url, :observed_at, :retrieved_at,
                        CAST(:facts AS jsonb), CAST(:raw_payload AS jsonb),
                        NULL, :observation_id)
                """),
                {
                    "evidence_id": converted.evidence.id,
                    "evidence_type": converted.evidence.type.value,
                    "source": converted.evidence.source,
                    "source_record_id": converted.evidence.source_record_id,
                    "source_url": candidate.source_url,
                    "observed_at": candidate.observed_at,
                    "retrieved_at": candidate.retrieved_at,
                    "facts": json.dumps(thaw_json(candidate.facts)),
                    "raw_payload": (
                        None
                        if candidate.raw_payload is None
                        else json.dumps(thaw_json(candidate.raw_payload))
                    ),
                    "observation_id": observation_id,
                },
            )
            row = result.one()
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_EVIDENCE_METADATA_CONFLICT:
                raise EvidenceMetadataConflictError(converted.evidence.id) from error
            if state == SQLSTATE_EVIDENCE_OBSERVATION_MISSING:
                raise EvidenceObservationNotFoundError(converted.evidence.id) from error
            if state == SQLSTATE_EVIDENCE_OBSERVATION_INPUT_INVALID:
                raise EvidenceObservationInputError(str(error.orig)) from error
            raise
        evidence_id, observation_id, version, outcome = row
        observation = await self.get_observation(observation_id)
        if observation is None:  # pragma: no cover - atomic function + transaction
            raise RuntimeError("evidence observation persist returned no row")
        return EvidencePersistenceResult(
            evidence=converted.evidence,
            observation=observation,
            outcome=EvidencePersistenceOutcome(outcome),
            version=version,
        )

    @postgres_repository_operation(
        repository="PostgresEvidenceRepository", operation="get_stable_evidence"
    )
    async def get_stable_evidence(self, evidence_id: UUID) -> Evidence | None:
        """Return the stable global Evidence with the given identity, if any."""
        row = await self._session.get(EvidenceRow, evidence_id)
        return None if row is None else _evidence(row)

    @postgres_repository_operation(
        repository="PostgresEvidenceRepository", operation="get_observation"
    )
    async def get_observation(self, observation_id: UUID) -> EvidenceObservation | None:
        """Return one exact EvidenceObservation by its immutable identity."""
        row = await self._session.get(EvidenceObservationRow, observation_id)
        return None if row is None else observation_from_row(row)

    @postgres_repository_operation(
        repository="PostgresEvidenceRepository", operation="list_observations"
    )
    async def list_observations(
        self,
        evidence_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceObservation]:
        """Return bounded observations of one stable Evidence, oldest first."""
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        limit = min(limit, 1000)
        result = await self._session.execute(
            select(EvidenceObservationRow)
            .where(EvidenceObservationRow.evidence_id == evidence_id)
            .order_by(EvidenceObservationRow.version.asc())
            .limit(limit)
            .offset(offset)
        )
        return [observation_from_row(row) for row in result.scalars().all()]

    @postgres_repository_operation(
        repository="PostgresEvidenceRepository", operation="list_for_investigation"
    )
    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceObservation]:
        """Return the exact admitted observations of one Investigation.

        Scope comes exclusively from ``ati.investigation_evidence``
        admission; unadmitted global observations never appear. Ordering is
        deterministic newest-first (``retrieved_at DESC, id ASC``).
        """
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        if limit > _PROBE_LIMIT_CEILING:
            raise ValueError(f"limit must not exceed {_PROBE_LIMIT_CEILING}")
        result = await self._session.execute(
            select(EvidenceObservationRow)
            .join(
                InvestigationEvidenceRow,
                InvestigationEvidenceRow.evidence_observation_id
                == EvidenceObservationRow.id,
            )
            .where(InvestigationEvidenceRow.investigation_id == investigation_id)
            .order_by(
                EvidenceObservationRow.retrieved_at.desc(),
                EvidenceObservationRow.id.asc(),
            )
            .limit(limit)
            .offset(offset)
        )
        return [observation_from_row(row) for row in result.scalars().all()]


class PostgresEvidenceObservationEntityRepository(EvidenceObservationEntityRepository):
    """Idempotent observation/Entity association persistence."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @postgres_repository_operation(
        repository="PostgresEvidenceObservationEntityRepository", operation="associate"
    )
    async def associate(
        self, observation_id: UUID, entity_id: UUID
    ) -> EvidenceObservationEntity:
        """Associate one canonical Entity with one exact observation."""
        await self._session.execute(
            text(
                "SELECT evidence_observation_id, entity_id "
                "FROM ati.associate_evidence_observation_entity(:obs, :ent)"
            ),
            {"obs": observation_id, "ent": entity_id},
        )
        return EvidenceObservationEntity(
            evidence_observation_id=observation_id, entity_id=entity_id
        )

    @postgres_repository_operation(
        repository="PostgresEvidenceObservationEntityRepository",
        operation="list_for_observation",
    )
    async def list_for_observation(
        self, observation_id: UUID
    ) -> list[EvidenceObservationEntity]:
        """Return the exact associated Entities of one observation."""
        result = await self._session.execute(
            select(EvidenceObservationEntityRow).where(
                EvidenceObservationEntityRow.evidence_observation_id == observation_id
            )
        )
        return [
            EvidenceObservationEntity(
                evidence_observation_id=row.evidence_observation_id,
                entity_id=row.entity_id,
            )
            for row in result.scalars().all()
        ]


class PostgresInvestigationEvidenceRepository(InvestigationEvidenceRepository):
    """Exact append-only/idempotent admission persistence."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @postgres_repository_operation(
        repository="PostgresInvestigationEvidenceRepository", operation="admit"
    )
    async def admit(self, admission: InvestigationEvidence) -> InvestigationEvidence:
        """Admit one exact observation into one Investigation."""
        try:
            await self._session.execute(
                text("""
                    SELECT investigation_id, evidence_observation_id, admitted
                    FROM ati.admit_investigation_evidence(
                        :investigation_id, :evidence_observation_id,
                        :inclusion_reason, :discovered_from, :added_at, :added_by)
                """),
                {
                    "investigation_id": admission.investigation_id,
                    "evidence_observation_id": admission.evidence_observation_id,
                    "inclusion_reason": admission.inclusion_reason.value,
                    "discovered_from": admission.discovered_from_evidence_observation_id,
                    "added_at": admission.added_at,
                    "added_by": admission.added_by.value,
                },
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_INVESTIGATION_NOT_FOUND:
                from agentic_threat_investigator.app.persistence.repositories import (
                    InvestigationNotFoundError,
                )

                raise InvestigationNotFoundError(
                    str(admission.investigation_id)
                ) from error
            if state == SQLSTATE_EVIDENCE_OBSERVATION_MISSING:
                raise EvidenceObservationNotFoundError(
                    admission.evidence_observation_id
                ) from error
            if state == SQLSTATE_INVESTIGATION_ADDITION_INVALID_DISCOVERED_FROM:
                raise InvalidDiscoveredFromProvenanceError(
                    admission.discovered_from_evidence_observation_id or UUID(int=0)
                ) from error
            if state == SQLSTATE_INVESTIGATION_ADMISSION_CONFLICT:
                raise InvestigationEvidenceAdmissionConflictError(
                    admission.investigation_id, admission.evidence_observation_id
                ) from error
            raise
        return admission

    @postgres_repository_operation(
        repository="PostgresInvestigationEvidenceRepository",
        operation="list_for_investigation",
    )
    async def list_for_investigation(
        self, investigation_id: UUID
    ) -> list[InvestigationEvidence]:
        """Return the exact admissions of one Investigation."""
        result = await self._session.execute(
            select(InvestigationEvidenceRow).where(
                InvestigationEvidenceRow.investigation_id == investigation_id
            )
        )
        return [
            InvestigationEvidence(
                investigation_id=row.investigation_id,
                evidence_observation_id=row.evidence_observation_id,
                inclusion_reason=InvestigationEvidenceReason(row.inclusion_reason),
                discovered_from_evidence_observation_id=(
                    row.discovered_from_evidence_observation_id
                ),
                added_at=row.added_at,
                added_by=InvestigationEvidenceActor(row.added_by),
            )
            for row in result.scalars().all()
        ]
