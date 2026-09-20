# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapter for the PR 28E bounded Evidence batch persistence boundary.

The adapter serializes one prepared batch (already-validated,
already-extracted work) into the versioned SQL API v0027 JSONB contract and
makes exactly one top-level ``ati.persist_evidence_batch`` call inside the
caller's UnitOfWork transaction. It never commits, never allocates
versions, and never reimplements the Evidence transition: PostgreSQL owns
bounded input validation, the durable message-receipt idempotency, the
authoritative CREATED/UNCHANGED/APPENDED transition (reused from SQL API
v0026), Entity/Relationship resolution, and exact-observation provenance.

SQLSTATE mapping (see ``errors.py``): SQL API v0027 raises the typed inner
states (U28B1/U28B2/U28B3, U18C2, U18C1) with the failing bounded identity
attached to exception DETAIL so the same typed application errors as the
single-record repositories are surfaced; the batch-specific states U28E1
(shape) and U28E2 (too large) map to the dedicated batch errors. Raw
PostgreSQL text and payload content are never exposed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.extraction.models import (
    ExtractedEntity,
    assertion_order_key,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceBatchInputError,
    EvidenceBatchPersistenceItemResult,
    EvidenceBatchPersistenceResult,
    EvidenceBatchRepository,
    EvidenceBatchSizeLimitExceededError,
    EvidenceMetadataConflictError,
    EvidenceObservationInputError,
    EvidenceObservationNotFoundError,
    EvidencePersistenceOutcome,
    PreparedEvidenceBatch,
    PreparedEvidenceRecord,
    SoftDeletedIdentityError,
    validate_evidence_batch_size,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.telemetry.decorators import (
    postgres_repository_operation,
)

from .errors import (
    SQLSTATE_ENTITY_SOFT_DELETED,
    SQLSTATE_EVIDENCE_BATCH_INPUT_INVALID,
    SQLSTATE_EVIDENCE_BATCH_TOO_LARGE,
    SQLSTATE_EVIDENCE_METADATA_CONFLICT,
    SQLSTATE_EVIDENCE_OBSERVATION_INPUT_INVALID,
    SQLSTATE_EVIDENCE_OBSERVATION_MISSING,
    SQLSTATE_RELATIONSHIP_SOFT_DELETED,
    sqlstate,
    sqlstate_detail,
)

EntityIdentityKey = tuple[EntityType, str]


def _encode_timestamp(value: datetime) -> str:
    """Encode one aware UTC timestamp as canonical ``...Z`` ISO-8601."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _detail_uuid(detail: str | None) -> UUID | None:
    """Parse a bounded identity carried by the stored function DETAIL."""
    if not detail:
        return None
    try:
        return UUID(detail)
    except ValueError:
        return None


class PostgresEvidenceBatchRepository(EvidenceBatchRepository):
    """Persist one complete prepared Evidence batch in the active transaction."""

    def __init__(self, session: AsyncSession, batch_size: int = 500) -> None:
        """Bind the repository to a session and the SQL-side hard bound."""
        self._session = session
        self._batch_size = batch_size

    @postgres_repository_operation(
        repository="PostgresEvidenceBatchRepository", operation="persist_batch"
    )
    async def persist_batch(
        self, batch: PreparedEvidenceBatch
    ) -> EvidenceBatchPersistenceResult:
        """Serialize and submit the whole prepared batch in one SQL call.

        The size bound is enforced here (before any SQL serialization) and
        independently by the SQL function; the caller's UnitOfWork remains
        the commit boundary.
        """
        validate_evidence_batch_size(batch, self._batch_size)
        items = [_serialize_record(record) for record in batch.records]
        try:
            result = await self._session.execute(
                text("""
                    SELECT batch_ordinal, out_message_id, out_evidence_id,
                           out_evidence_observation_id, out_version, out_outcome
                    FROM ati.persist_evidence_batch(CAST(:items AS jsonb))
                    ORDER BY batch_ordinal
                """),
                {"items": json.dumps(items, sort_keys=True, separators=(",", ":"))},
            )
        except DBAPIError as error:
            state = sqlstate(error)
            if state == SQLSTATE_EVIDENCE_BATCH_INPUT_INVALID:
                raise EvidenceBatchInputError(
                    "the database rejected the prepared batch shape"
                ) from error
            if state == SQLSTATE_EVIDENCE_BATCH_TOO_LARGE:
                raise EvidenceBatchSizeLimitExceededError(
                    len(batch.records), self._batch_size
                ) from error
            if state == SQLSTATE_EVIDENCE_METADATA_CONFLICT:
                detail = _detail_uuid(sqlstate_detail(error))
                if detail is not None:
                    raise EvidenceMetadataConflictError(detail) from error
                raise EvidenceBatchInputError(
                    "stable evidence metadata conflict in batch record"
                ) from error
            if state == SQLSTATE_EVIDENCE_OBSERVATION_MISSING:
                detail = _detail_uuid(sqlstate_detail(error))
                if detail is not None:
                    raise EvidenceObservationNotFoundError(detail) from error
                raise EvidenceBatchInputError(
                    "evidence observation missing in batch record"
                ) from error
            if state == SQLSTATE_EVIDENCE_OBSERVATION_INPUT_INVALID:
                raise EvidenceObservationInputError("batch record") from error
            if state == SQLSTATE_ENTITY_SOFT_DELETED:
                detail = _detail_uuid(sqlstate_detail(error))
                if detail is not None:
                    raise SoftDeletedIdentityError("entity", detail) from error
                raise EvidenceBatchInputError(
                    "soft-deleted entity in batch record"
                ) from error
            if state == SQLSTATE_RELATIONSHIP_SOFT_DELETED:
                detail = _detail_uuid(sqlstate_detail(error))
                if detail is not None:
                    raise SoftDeletedIdentityError("relationship", detail) from error
                raise EvidenceBatchInputError(
                    "soft-deleted relationship in batch record"
                ) from error
            raise
        rows = result.fetchall()
        persisted_items = tuple(
            EvidenceBatchPersistenceItemResult(
                message_id=row[1],
                evidence_id=row[2],
                evidence_observation_id=row[3],
                outcome=EvidencePersistenceOutcome(row[5]),
                version=row[4],
            )
            for row in rows
        )
        if len(persisted_items) != len(
            batch.records
        ):  # pragma: no cover - atomic function
            raise RuntimeError(
                "evidence batch persistence returned a mismatched result count"
            )
        return EvidenceBatchPersistenceResult(items=persisted_items)


def _serialize_record(record: PreparedEvidenceRecord) -> dict[str, Any]:
    """Map one prepared record to the versioned JSONB batch contract.

    The payload is the already-validated normalized persistence input:
    canonical values, thawed facts, deterministic entity/relationship order.
    No Investigation identity, transport position, or broker metadata is
    serialized.
    """
    converted = record.converted
    candidate = converted.observation
    return {
        "message_id": str(record.message_id),
        "observation_candidate_id": str(record.observation_candidate_id),
        "evidence": {
            "id": str(converted.evidence.id),
            "type": converted.evidence.type.value,
            "source": converted.evidence.source,
            "source_record_id": converted.evidence.source_record_id,
        },
        "observation": {
            "source_url": candidate.source_url,
            "observed_at": (
                None
                if candidate.observed_at is None
                else _encode_timestamp(candidate.observed_at)
            ),
            "retrieved_at": _encode_timestamp(candidate.retrieved_at),
            "facts": thaw_json(candidate.facts),
            "raw_payload": (
                None
                if candidate.raw_payload is None
                else thaw_json(candidate.raw_payload)
            ),
        },
        "entities": [
            {
                "type": entity.type.value,
                "value": entity.value,
                "display_name": entity.display_name,
            }
            for entity in _ordered_entities(record)
        ],
        "relationships": [
            {
                "source_type": assertion.source.type.value,
                "source_value": assertion.source.value,
                "type": assertion.type.value,
                "target_type": assertion.target.type.value,
                "target_value": assertion.target.value,
            }
            for assertion in sorted(
                record.extraction.relationships, key=assertion_order_key
            )
        ],
    }


def _ordered_entities(record: PreparedEvidenceRecord) -> list[ExtractedEntity]:
    """Return invocation target and discoveries in stable identity order.

    Mirrors the Investigation-scoped persistence path: the invocation target
    contributes no display metadata of its own; a discovery of the same
    identity wins so its display metadata is never lost. Ordering is by
    ``(entity type value, canonical value)`` for deterministic writes.
    """
    by_identity: dict[EntityIdentityKey, ExtractedEntity] = {
        (entity.type, entity.value): entity for entity in record.extraction.entities
    }
    by_identity.setdefault(
        (record.invocation_entity.type, record.invocation_entity.value),
        ExtractedEntity(
            type=record.invocation_entity.type, value=record.invocation_entity.value
        ),
    )
    return [
        by_identity[key]
        for key in sorted(by_identity, key=lambda item: (item[0].value, item[1]))
    ]
