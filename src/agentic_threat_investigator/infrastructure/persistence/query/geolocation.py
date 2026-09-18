# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL Investigation geolocation read query (PR 25A + PR 28B).

The projection is one bounded SQL read: PostgreSQL selects the single latest
admitted ``GEOLOCATION`` observation per associated IP Entity with
``row_number() OVER (PARTITION BY entity_id ORDER BY retrieved_at DESC, id
ASC)``. The driving scope is exclusively the ``ati.investigation_evidence``
admission, the stable Evidence type, and IP-address associated Entities;
then the canonical deterministic transport ordering and a ``max_items + 1``
bound so truncation is detected without a second query. No per-item
Evidence reads occur; the application never loads every historical
geolocation row. The projection's ``evidence_id`` is the exact
EvidenceObservation identity (PR 28B) while the public field spelling is
retained for wire compatibility.
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

from ..postgresql.models import (
    EntityRow,
    EvidenceObservationEntityRow,
    EvidenceObservationRow,
    EvidenceRow,
    InvestigationEvidenceRow,
)


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
                EvidenceObservationRow.id.label("observation_id"),
                EvidenceObservationRow.evidence_id.label("evidence_id"),
                EvidenceObservationRow.source_url.label("source_url"),
                EvidenceObservationRow.observed_at.label("observed_at"),
                EvidenceObservationRow.retrieved_at.label("retrieved_at"),
                EvidenceObservationRow.facts.label("facts"),
                EntityRow.id.label("entity_id"),
                EntityRow.canonical_value.label("canonical_value"),
                func.row_number()
                .over(
                    partition_by=EntityRow.id,
                    order_by=(
                        EvidenceObservationRow.retrieved_at.desc(),
                        EvidenceObservationRow.id.asc(),
                    ),
                )
                .label("_rank"),
            )
            .join(
                InvestigationEvidenceRow,
                InvestigationEvidenceRow.evidence_observation_id
                == EvidenceObservationRow.id,
            )
            .join(
                EvidenceRow,
                EvidenceRow.id == EvidenceObservationRow.evidence_id,
            )
            .join(
                EvidenceObservationEntityRow,
                EvidenceObservationEntityRow.evidence_observation_id
                == EvidenceObservationRow.id,
            )
            .join(EntityRow, EntityRow.id == EvidenceObservationEntityRow.entity_id)
            .where(
                InvestigationEvidenceRow.investigation_id == investigation_id,
                EvidenceRow.evidence_type == EvidenceType.GEOLOCATION.value,
                EntityRow.entity_type == EntityType.IP_ADDRESS.value,
                EntityRow.deleted_at.is_(None),
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
            evidence_id=row["observation_id"],
            entity_id=row["entity_id"],
            ip_address=row["canonical_value"],
            facts=row["facts"],
            observed_at=row["observed_at"],
            retrieved_at=row["retrieved_at"],
        )
