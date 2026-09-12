# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A integration: Evidence keyset listing/filtering (23A-I02)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.evidence import EvidenceListQuery
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import (
    FIXED_TIME,
    evidence_factory,
    seed_entity,
    seed_investigation,
)

_SOURCE_DNS = "urn:ati:source:google_public_dns"
_SOURCE_RDAP = "urn:ati:source:rdap"


async def _seed_mixed_evidence(
    uow: PostgresUnitOfWork,
) -> tuple[UUID, UUID, UUID, UUID]:
    """Seed one investigation with mixed sources, subjects, types, and times.

    Returns the investigation and the three evidence IDs in newest-first
    order.
    """
    investigation_id = await seed_investigation(uow)
    dns_entity = await seed_entity(uow, value="example.com")
    asn_entity = await seed_entity(uow, entity_type=EntityType.ASN, value="AS64512")
    newer = await uow.evidence.insert(
        evidence_factory(
            investigation_id,
            dns_entity,
            source=_SOURCE_RDAP,
            evidence_type=EvidenceType.REGISTRATION,
            retrieved_at=FIXED_TIME + timedelta(minutes=10),
        )
    )
    third = await uow.evidence.insert(
        evidence_factory(
            investigation_id,
            asn_entity,
            source=_SOURCE_DNS,
            evidence_type=EvidenceType.DNS,
            retrieved_at=FIXED_TIME + timedelta(minutes=5),
        )
    )
    older = await uow.evidence.insert(
        evidence_factory(
            investigation_id,
            dns_entity,
            source=_SOURCE_DNS,
            evidence_type=EvidenceType.DNS,
            retrieved_at=FIXED_TIME,
        )
    )
    assert older.id is not None and newer.id is not None and third.id is not None
    return investigation_id, newer.id, third.id, older.id


async def _collect_evidence_ids(
    services: PostgresQueryServices, query: EvidenceListQuery
) -> list[UUID]:
    """Follow cursors to completion, returning every evidence ID."""
    collected: list[UUID] = []
    cursor: str | None = None
    while True:
        page = await services.evidence.list(query.model_copy(update={"cursor": cursor}))
        collected.extend(item.id for item in page.items if item.id is not None)
        if page.next_cursor is None:
            return collected
        cursor = page.next_cursor


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_newest_first_and_pagination(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Evidence lists retrieved_at DESC, id ASC with stable pagination."""
    async with uow_factory() as uow:
        investigation_id, newer, third, older = await _seed_mixed_evidence(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_evidence_ids(
            services, EvidenceListQuery(investigation_id=investigation_id, limit=1)
        )
        assert collected == [newer, third, older]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_source_filter(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The bounded source filter isolates a single source."""
    async with uow_factory() as uow:
        investigation_id, newer, _, _ = await _seed_mixed_evidence(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_evidence_ids(
            services,
            EvidenceListQuery(
                investigation_id=investigation_id,
                source=_SOURCE_RDAP,
                limit=10,
            ),
        )
        assert collected == [newer]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_subject_filter(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The relational subject filter isolates one canonical entity."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        asn_entity = await seed_entity(uow, entity_type=EntityType.ASN, value="AS64512")
        dns_entity = await seed_entity(uow, value="example.com")
        asn_evidence = await uow.evidence.insert(
            evidence_factory(investigation_id, asn_entity, source=_SOURCE_DNS)
        )
        await uow.evidence.insert(
            evidence_factory(investigation_id, dns_entity, source=_SOURCE_RDAP)
        )
        assert asn_evidence.id is not None
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_evidence_ids(
            services,
            EvidenceListQuery(
                investigation_id=investigation_id,
                subject_entity_id=asn_entity,
                limit=10,
            ),
        )
        assert collected == [asn_evidence.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_type_filter(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The bounded type filter isolates one evidence type."""
    async with uow_factory() as uow:
        investigation_id, newer, _, _ = await _seed_mixed_evidence(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_evidence_ids(
            services,
            EvidenceListQuery(
                investigation_id=investigation_id,
                evidence_type=EvidenceType.REGISTRATION,
                limit=10,
            ),
        )
        assert collected == [newer]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_retrieved_range(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The retrieved-at half-open range isolates the correct observations."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(uow)
        inside = await uow.evidence.insert(
            evidence_factory(
                investigation_id,
                entity_id,
                source=_SOURCE_DNS,
                retrieved_at=FIXED_TIME + timedelta(minutes=5),
            )
        )
        await uow.evidence.insert(
            evidence_factory(
                investigation_id,
                entity_id,
                source=_SOURCE_RDAP,
                retrieved_at=FIXED_TIME,
            )
        )
        assert inside.id is not None
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_evidence_ids(
            services,
            EvidenceListQuery(
                investigation_id=investigation_id,
                retrieved_from=FIXED_TIME + timedelta(minutes=1),
                retrieved_to=FIXED_TIME + timedelta(minutes=10),
                limit=10,
            ),
        )
        assert collected == [inside.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_scope_isolation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Evidence of another investigation never appears."""
    async with uow_factory() as uow:
        investigation_id, _, _, _ = await _seed_mixed_evidence(uow)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.evidence.list(
            EvidenceListQuery(investigation_id=uuid4(), limit=10)
        )
        assert page.items == ()
        assert page.next_cursor is None
