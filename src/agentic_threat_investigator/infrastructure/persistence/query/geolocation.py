# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL Investigation geolocation read query (PR 25A).

The projection is one bounded SQL read: PostgreSQL selects the single latest
``GEOLOCATION`` Evidence row per subject entity with ``row_number() OVER
(PARTITION BY subject_entity_id ORDER BY retrieved_at DESC, id ASC)``,
restricts the driving scope to one Investigation and to IP-address subjects,
then applies the canonical deterministic transport ordering and a
``max_items + 1`` bound so truncation is detected without a second query.
No per-item Evidence reads occur; the application never loads every
historical geolocation row.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.geolocation import (
    InvestigationGeolocationItem,
    InvestigationGeolocationQueryService,
    InvestigationGeolocationResult,
    geolocation_item_from_persisted_facts,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType

from ..postgresql.models import EntityRow, EvidenceRow


class PostgresInvestigationGeolocationQueryService(
    InvestigationGeolocationQueryService
):
    """Latest-per-IP geolocation projection over one active read session.

    The service reads persisted Evidence only; it never opens MMDB
    artifacts, invokes providers, performs network I/O, or runs
    orchestration.
    """

    def __init__(self, session: AsyncSession, max_items: int) -> None:
        """Bind the read session and the server-owned projection bound."""
        if max_items < 1:
            raise ValueError("geolocation projection max_items must be positive")
        self._session = session
        self._max_items = max_items

    async def list_for_investigation(
        self, investigation_id: UUID
    ) -> InvestigationGeolocationResult:
        """Return the bounded current geolocation projection.

        Exactly one latest persisted ``GEOLOCATION`` Evidence row per IP
        subject is selected deterministically (``retrieved_at DESC, id
        ASC``) and ordered ``ip_address ASC, entity_id ASC``; at most
        ``max_items + 1`` rows are fetched so truncation is explicit.
        """
        max_items = self._max_items
        ranked = (
            select(
                EvidenceRow.id.label("evidence_id"),
                EvidenceRow.investigation_id.label("investigation_id"),
                EvidenceRow.evidence_type.label("evidence_type"),
                EvidenceRow.subject_entity_id.label("subject_entity_id"),
                EvidenceRow.source.label("source"),
                EvidenceRow.source_record_id.label("source_record_id"),
                EvidenceRow.source_url.label("source_url"),
                EvidenceRow.observed_at.label("observed_at"),
                EvidenceRow.retrieved_at.label("retrieved_at"),
                EvidenceRow.facts.label("facts"),
                EntityRow.id.label("entity_id"),
                EntityRow.canonical_value.label("canonical_value"),
                func.row_number()
                .over(
                    partition_by=EvidenceRow.subject_entity_id,
                    order_by=(
                        EvidenceRow.retrieved_at.desc(),
                        EvidenceRow.id.asc(),
                    ),
                )
                .label("_rank"),
            )
            .join(EntityRow, EntityRow.id == EvidenceRow.subject_entity_id)
            .where(
                EvidenceRow.investigation_id == investigation_id,
                EvidenceRow.evidence_type == EvidenceType.GEOLOCATION.value,
                EntityRow.entity_type == EntityType.IP_ADDRESS.value,
            )
            .subquery()
        )
        statement = (
            select(ranked)
            .where(ranked.c._rank == 1)
            .order_by(
                ranked.c.canonical_value.asc(),
                ranked.c.entity_id.asc(),
            )
            .limit(max_items + 1)
        )
        rows = list((await self._session.execute(statement)).mappings().all())
        projected = rows[:max_items]
        items = tuple(self._item_from_row(row) for row in projected)
        return InvestigationGeolocationResult(
            items=items, truncated=len(rows) > max_items
        )

    @staticmethod
    def _item_from_row(row: Any) -> InvestigationGeolocationItem:
        """Map one projected row to the typed read item via the pure mapper.

        The geolocation semantics (approved facts only, fail-closed
        malformed persistence) live in the framework-independent pure
        mapper; this wrapper only supplies the row's persisted values.
        """
        return geolocation_item_from_persisted_facts(
            evidence_id=row["evidence_id"],
            entity_id=row["entity_id"],
            ip_address=row["canonical_value"],
            facts=row["facts"],
            observed_at=row["observed_at"],
            retrieved_at=row["retrieved_at"],
        )
