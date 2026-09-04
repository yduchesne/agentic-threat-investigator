# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapters for source records and ingestion checkpoints."""

from collections.abc import Sequence
from uuid import UUID

from psycopg.types.json import Jsonb
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    BatchSizeLimitExceededError,
    IngestionCheckpoint,
    IngestionCheckpointRepository,
    SourceRecordBatchItem,
    SourceRecordBatchResult,
    SourceRecordRepository,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.domain.source import (
    SourceRecord,
    source_record_content_hash,
)


class PostgresSourceRecordRepository(SourceRecordRepository):
    """Submit source records to the authoritative PostgreSQL batch function."""

    def __init__(self, session: AsyncSession, batch_size: int = 100) -> None:
        self._session, self._batch_size = session, batch_size

    async def upsert_batch(
        self, items: Sequence[SourceRecordBatchItem]
    ) -> list[SourceRecordBatchResult]:
        """Validate hashes and invoke the database-owned reconciliation function."""
        if len(items) > self._batch_size:
            raise BatchSizeLimitExceededError(
                "source-record batch exceeds configured limit"
            )
        composite = []
        for ordinal, item in enumerate(items, 1):
            record = item.record
            if record.content_hash != source_record_content_hash(record):
                raise ValueError(
                    "source record content_hash does not match semantic content"
                )
            composite.append(
                (
                    ordinal,
                    record.source_id,
                    record.source_record_id,
                    record.record_type,
                    record.normalization_version,
                    record.observed_at,
                    record.published_at,
                    record.retrieved_at,
                    Jsonb(thaw_json(record.canonical_payload)),
                    (
                        None
                        if record.raw_payload is None
                        else Jsonb(thaw_json(record.raw_payload))
                    ),
                    bytes.fromhex(record.content_hash),
                    Jsonb(thaw_json(record.metadata)),
                    item.expected_version,
                )
            )
        result = await self._session.execute(
            text(
                "SELECT ordinal,id,version,outcome FROM ati.upsert_source_records(:items)"
            ),
            {"items": composite},
        )
        return [
            SourceRecordBatchResult(row[0], row[1], row[2], BatchOutcome(row[3]))
            for row in result.fetchall()
        ]

    async def get_by_id(self, record_id: UUID) -> SourceRecord | None:
        """Look up a current normalized record by internal UUID."""
        result = await self._session.execute(
            text(
                """
            SELECT id, source_id, source_record_id, record_type,
                   normalization_version, observed_at, published_at, retrieved_at,
                   canonical_payload, raw_payload, content_hash, metadata
            FROM ati.source_record WHERE id=:id
        """
            ),
            {"id": record_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
        values = dict(row)
        values["content_hash"] = bytes(row["content_hash"]).hex()
        return SourceRecord(**values)

    async def get_by_identity(
        self, source_id: str, source_record_id: str
    ) -> SourceRecord | None:
        """Look up a current normalized record."""
        result = await self._session.execute(
            text(
                """
                SELECT id, source_id, source_record_id, record_type,
                       normalization_version, observed_at, published_at,
                       retrieved_at, canonical_payload, raw_payload,
                       content_hash, metadata
                FROM ati.source_record
                WHERE source_id=:source_id AND source_record_id=:record_id
                """
            ),
            {"source_id": source_id, "record_id": source_record_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
        values = dict(row)
        values["content_hash"] = bytes(row["content_hash"]).hex()
        return SourceRecord(**values)


class PostgresIngestionCheckpointRepository(IngestionCheckpointRepository):
    """Persist operational checkpoint state in the caller transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(
        self, source_id: str, artifact_uri: str, normalization_version: int
    ) -> IngestionCheckpoint | None:
        result = await self._session.execute(
            text(
                """
                SELECT source_id, artifact_uri, normalization_version,
                       checkpoint, complete
                FROM ati.ingestion_checkpoint
                WHERE source_id=:s AND artifact_uri=:u
                  AND normalization_version=:v
                """
            ),
            {"s": source_id, "u": artifact_uri, "v": normalization_version},
        )
        row = result.mappings().first()
        return (
            None
            if row is None
            else IngestionCheckpoint(
                row["source_id"],
                row["artifact_uri"],
                row["normalization_version"],
                row["checkpoint"],
                row["complete"],
            )
        )

    async def put(self, checkpoint: IngestionCheckpoint) -> None:
        await self._session.execute(
            text(
                """
                INSERT INTO ati.ingestion_checkpoint(
                    source_id, artifact_uri, normalization_version,
                    checkpoint, complete
                ) VALUES (:s, :u, :v, :c, :done)
                ON CONFLICT (source_id, artifact_uri, normalization_version)
                DO UPDATE SET checkpoint=:c, complete=:done, updated_at=now()
                """
            ),
            {
                "s": checkpoint.source_id,
                "u": checkpoint.artifact_uri,
                "v": checkpoint.normalization_version,
                "c": checkpoint.checkpoint,
                "done": checkpoint.complete,
            },
        )

    async def reset(
        self, source_id: str, artifact_uri: str, normalization_version: int
    ) -> None:
        await self._session.execute(
            text(
                """
                DELETE FROM ati.ingestion_checkpoint
                WHERE source_id=:s AND artifact_uri=:u
                  AND normalization_version=:v
                """
            ),
            {"s": source_id, "u": artifact_uri, "v": normalization_version},
        )
