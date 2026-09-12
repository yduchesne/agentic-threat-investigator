# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23B report query PostgreSQL integration tests (23B-I09..I10, current pointer)."""

from __future__ import annotations

import json
from collections.abc import Callable
from uuid import UUID

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.reports import ReportListQuery
from agentic_threat_investigator.domain.report import InvestigationReport
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.reports import (
    PostgresReportQueryService,
)
from tests.integration.test_report_persistence import (
    report_candidate,
    seed_report_context,
)

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

UOW_FACTORY = Callable[[], PostgresUnitOfWork]

_REPORT_LISTING_INDEX = "investigation_report_version_listing_idx"


def _index_names(node: object, found: set[str]) -> None:
    """Collect every index name present in an EXPLAIN plan tree."""
    if isinstance(node, dict):
        name = node.get("Index Name")
        if isinstance(name, str):
            found.add(name)
        for value in node.values():
            _index_names(value, found)
    elif isinstance(node, list):
        for item in node:
            _index_names(item, found)


async def _plan_indexes(
    uow: PostgresUnitOfWork,
    statement: str,
    params: dict[str, object],
) -> set[str]:
    """Return the indexes PostgreSQL chose for one representative query."""
    assert uow.session is not None
    await uow.session.execute(text("SET LOCAL enable_seqscan = off"))
    result = await uow.session.execute(
        text("EXPLAIN (FORMAT JSON) " + statement), params
    )
    payload = result.scalar_one()
    if isinstance(payload, str):
        payload = json.loads(payload)
    found: set[str] = set()
    _index_names(payload, found)
    return found


async def seed_reports(
    uow_factory: UOW_FACTORY, *, count: int = 3
) -> tuple[UUID, list[InvestigationReport]]:
    """Seed one investigation with ``count`` report versions."""
    from agentic_threat_investigator.app.report_writer.persistence import (
        InvestigationReportPersistenceService,
    )

    investigation_id, _evidence_id, assessment = await seed_report_context(uow_factory)
    service = InvestigationReportPersistenceService(uow_factory)
    persisted: list[InvestigationReport] = []
    for ordinal in range(1, count + 1):
        persisted.append(
            await service.persist(
                report_candidate(
                    investigation_id, assessment, title=f"Report {ordinal}"
                )
            )
        )
    return investigation_id, persisted


async def test_i09_report_listing_pagination(uow_factory: UOW_FACTORY) -> None:
    """23B-I09: version DESC, id ASC keyset pagination has no dupes/skips."""
    investigation_id, persisted = await seed_reports(uow_factory, count=4)
    versions = [report.version for report in persisted if report.version is not None]
    assert versions == sorted(versions)
    assert versions[-1] == max(versions)

    async with uow_factory() as uow:
        assert uow.session is not None
        services = PostgresReportQueryService(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        seen: list[UUID] = []
        cursor: str | None = None
        for _round in range(3):
            page = await services.list(
                ReportListQuery(
                    investigation_id=investigation_id, limit=2, cursor=cursor
                )
            )
            for report in page.items:
                assert report.id is not None
                assert report.id not in seen
                seen.append(report.id)
            cursor = page.next_cursor
            if cursor is None:
                break
        assert len(seen) == 4
        # Newest version first.
        assert seen[0] == persisted[-1].id
        assert seen[-1] == persisted[0].id


async def test_i10_report_listing_index_eligible(uow_factory: UOW_FACTORY) -> None:
    """23B-I10: EXPLAIN proves the report listing index is eligible."""
    investigation_id, _persisted = await seed_reports(uow_factory, count=2)
    async with uow_factory() as uow:
        found = await _plan_indexes(
            uow,
            """
            SELECT id FROM ati.investigation_report
            WHERE investigation_id = :investigation_id AND deleted_at IS NULL
            ORDER BY version DESC, id ASC
            LIMIT 50
            """,
            {"investigation_id": investigation_id},
        )
        assert _REPORT_LISTING_INDEX in found


async def test_current_report_follows_pointer(uow_factory: UOW_FACTORY) -> None:
    """The current report resolves through the durable report_id pointer."""
    investigation_id, persisted = await seed_reports(uow_factory, count=2)
    async with uow_factory() as uow:
        assert uow.session is not None
        services = PostgresReportQueryService(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        current = await services.current(investigation_id)
        assert current is not None
        assert current.id == persisted[-1].id

        other = await services.current(UUID(int=99))
        assert other is None


async def test_get_report_by_identity(uow_factory: UOW_FACTORY) -> None:
    """Exact report lookup returns the visible report with its snapshots."""
    investigation_id, persisted = await seed_reports(uow_factory, count=1)
    async with uow_factory() as uow:
        assert uow.session is not None
        services = PostgresReportQueryService(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        loaded = await services.get(persisted[0].id or UUID(int=0))
        assert loaded is not None
        assert loaded.title == "Report 1"
        assert loaded.findings == persisted[0].findings
        assert loaded.assessment_id == persisted[0].assessment_id
        assert loaded.investigation_id == investigation_id
