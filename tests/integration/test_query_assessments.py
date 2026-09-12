# SPDX-License-Identifier: AGPL-3.0-only
"""PR 23A integration: Assessment version listing and current pointer (23A-I08)."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.assessments import AssessmentListQuery
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import seed_investigation


def assessment_factory(investigation_id: UUID) -> Assessment:
    """Build one structurally valid INCONCLUSIVE Assessment version."""
    return Assessment(
        investigation_id=investigation_id,
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="synthetic inconclusive assessment",
        analyzed_evidence_ids=(),
    )


async def _collect_assessment_ids(
    services: PostgresQueryServices, query: AssessmentListQuery
) -> list[UUID]:
    """Follow cursors to completion, returning every assessment ID."""
    collected: list[UUID] = []
    cursor: str | None = None
    while True:
        page = await services.assessments.list(
            query.model_copy(update={"cursor": cursor})
        )
        collected.extend(item.id for item in page.items if item.id is not None)
        if page.next_cursor is None:
            return collected
        cursor = page.next_cursor


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_versions_newest_version_first(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Assessment versions list deterministically by version DESC."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        first = await uow.assessments.insert(assessment_factory(investigation_id))
        second = await uow.assessments.insert(assessment_factory(investigation_id))
        third = await uow.assessments.insert(assessment_factory(investigation_id))
        assert first.id is not None
        assert second.id is not None
        assert third.id is not None
        assert first.version is not None
        assert second.version is not None
        assert third.version is not None
        # Versions are database-allocated and monotonically increasing; only
        # the relative order is asserted (sequences are not reset by TRUNCATE).
        assert first.version < second.version < third.version

        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        collected = await _collect_assessment_ids(
            services,
            AssessmentListQuery(investigation_id=investigation_id, limit=2),
        )
        assert collected == [third.id, second.id, first.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_current_uses_investigation_pointer(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Current assessment resolution follows the durable Investigation pointer."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        older = await uow.assessments.insert(assessment_factory(investigation_id))
        newer = await uow.assessments.insert(assessment_factory(investigation_id))
        assert older.id is not None and newer.id is not None
        # The pointer stays on the older assessment: current() must follow it
        # and never infer MAX(version).
        await uow.investigations.update_assessment_reference(investigation_id, older.id)
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        current = await services.assessments.current(investigation_id)
        assert current is not None
        assert current.id == older.id
        assert current.version == older.version


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_current_without_pointer_is_none(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """No pointer means no current assessment, even with versions present."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await uow.assessments.insert(assessment_factory(investigation_id))
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        assert await services.assessments.current(investigation_id) is None
        assert (await services.assessments.current(uuid4())) is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_scope_isolation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Assessments of another investigation never appear."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        other = await seed_investigation(uow)
        await uow.assessments.insert(assessment_factory(other))
        assert uow.session is not None
        services = PostgresQueryServices(
            uow.session, QueryLimits(default_page_size=50, max_page_size=200)
        )
        page = await services.assessments.list(
            AssessmentListQuery(investigation_id=investigation_id, limit=10)
        )
        assert page.items == ()
        assert page.next_cursor is None
