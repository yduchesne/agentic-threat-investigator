# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E datasource-checkpoint persistence matrix over real PostgreSQL (T33E-DB01..DB10).

Exercises the production stored-function/repository path only:
``ati.get_datasource_checkpoint`` and ``ati.advance_datasource_checkpoint``
through ``PostgresDatasourceCheckpointRepository`` inside the real
``PostgresUnitOfWork``. The database owns one-row-per-identity, bounded
values, and deterministic compare-and-advance conflicts; Python only binds
parameters and maps returned rows. Backward-movement ordering policy is
deliberately NOT tested with arbitrary opaque tokens: TAXII ``added_after``
values are canonical fixed-width UTC timestamps, so DB05 advances through
the TAXII kind adapter (the PR 33E committer) and only ever moves forward.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.datasource_semantics import (
    CollectionAcquisitionProgress,
)
from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceCheckpoint,
    DatasourceCheckpointConflictError,
    validate_checkpoint_kind,
)
from agentic_threat_investigator.domain.datasource import DatasourceId
from agentic_threat_investigator.infrastructure.datasources.taxii21 import (
    format_taxii_timestamp,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.providers.composition import (
    build_taxii_checkpoint_committer,
)

pytestmark = pytest.mark.integration

_SOURCE = "opencti-collection"
_KIND = "taxii_added_after"
_TS1 = format_taxii_timestamp(datetime(2026, 7, 1, 0, 0, 0, tzinfo=UTC))
_TS2 = format_taxii_timestamp(datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC))
_TS3 = format_taxii_timestamp(datetime(2026, 7, 2, 0, 0, 0, tzinfo=UTC))


def _make(
    *,
    value: str = _TS1,
    datasource_id: str = _SOURCE,
    kind: str = _KIND,
    version: int = 1,
) -> DatasourceCheckpoint:
    """Build one deterministic checkpoint model value."""
    return DatasourceCheckpoint(
        datasource_id=datasource_id,
        checkpoint_kind=kind,
        checkpoint_value=value,
        updated_at=datetime(2026, 7, 1, tzinfo=UTC),
        version=version,
    )


async def _rows(engine: AsyncEngine, *, where: str = "") -> list[dict[str, Any]]:
    """Return the checkpoint rows of one identity as plain dicts."""
    stmt = "SELECT * FROM ati.datasource_checkpoint"
    if where:
        stmt += f" WHERE {where}"
    async with engine.begin() as connection:
        result = await connection.execute(text(stmt))
        return [dict(row) for row in result.mappings()]


class TestCheckpointRepository:
    """T33E-DB01..DB10 over the real stored functions."""

    @pytest.mark.asyncio
    async def test_db01_absent_checkpoint_reads_none(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """DB01: reading an absent checkpoint returns None."""
        async with uow_factory() as uow:
            row = await uow.datasource_checkpoints.get(
                datasource_id=_SOURCE, checkpoint_kind=_KIND
            )
            assert row is None

    @pytest.mark.asyncio
    async def test_db02_first_advance_creates_row(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """DB02: the first advance creates the row with version 1."""
        async with uow_factory() as uow:
            row = await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind=_KIND,
                expected_value=None,
                new_value=_TS1,
                updated_at=datetime(2026, 7, 1, tzinfo=UTC),
            )
            assert row.version == 1
            assert row.checkpoint_value == _TS1
            assert row.datasource_id == _SOURCE
            assert row.checkpoint_kind == _KIND

    @pytest.mark.asyncio
    async def test_db03_equal_idempotent_advance_is_noop(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """DB03: an advance to the current value is an idempotent no-op."""
        async with uow_factory() as uow:
            await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind=_KIND,
                expected_value=None,
                new_value=_TS1,
                updated_at=datetime(2026, 7, 1, tzinfo=UTC),
            )
            second = await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind=_KIND,
                expected_value=_TS1,
                new_value=_TS1,
                updated_at=datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC),
            )
            assert second.checkpoint_value == _TS1
            assert second.version == 1

    @pytest.mark.asyncio
    async def test_db04_later_advance_bumps_version(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """DB04: a later advance moves the value and increments the version."""
        async with uow_factory() as uow:
            await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind=_KIND,
                expected_value=None,
                new_value=_TS1,
                updated_at=datetime(2026, 7, 1, tzinfo=UTC),
            )
            row = await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind=_KIND,
                expected_value=_TS1,
                new_value=_TS2,
                updated_at=datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC),
            )
            assert row.checkpoint_value == _TS2
            assert row.version == 2

    @pytest.mark.asyncio
    async def test_db05_earlier_taxii_candidate_is_rejected(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """DB05: an earlier TAXII date-added candidate never moves backward."""
        # Seed the durable cursor at _TS2 through the production committer,
        # then attempt an older candidate. Ordering policy belongs to the TAXII
        # kind adapter (the PR 33E committer), not to arbitrary token compares.
        async with uow_factory() as uow:
            await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind=_KIND,
                expected_value=None,
                new_value=_TS2,
                updated_at=datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC),
            )
        committer = build_taxii_checkpoint_committer(uow_factory, checkpoint_kind=_KIND)
        with pytest.raises(DatasourceCheckpointConflictError):
            await committer(
                DatasourceId(_SOURCE),
                CollectionAcquisitionProgress(
                    kind=_KIND, previous=_TS1, candidate=_TS1
                ),
            )

    @pytest.mark.asyncio
    async def test_db06_stale_compare_and_advance_conflicts(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """DB06: a stale expected value deterministically conflicts."""
        # Seed the durable cursor in its own unit of work so the failed
        # compare-and-advance cannot roll it back (real-PG semantics).
        async with uow_factory() as uow:
            await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind=_KIND,
                expected_value=None,
                new_value=_TS2,
                updated_at=datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC),
            )
        with pytest.raises(DatasourceCheckpointConflictError):
            async with uow_factory() as uow:
                await uow.datasource_checkpoints.advance(
                    datasource_id=_SOURCE,
                    checkpoint_kind=_KIND,
                    expected_value=_TS1,
                    new_value=_TS3,
                    updated_at=datetime(2026, 7, 2, tzinfo=UTC),
                )
        rows = await _rows(integration_engine)
        assert len(rows) == 1
        assert rows[0]["checkpoint_value"] == _TS2
        assert rows[0]["version"] == 1

    @pytest.mark.asyncio
    async def test_db07_datasource_isolation(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """DB07: checkpoints of distinct datasource instances are independent."""
        async with uow_factory() as uow:
            await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind=_KIND,
                expected_value=None,
                new_value=_TS1,
                updated_at=datetime(2026, 7, 1, tzinfo=UTC),
            )
            other = await uow.datasource_checkpoints.advance(
                datasource_id="commercial-tip",
                checkpoint_kind=_KIND,
                expected_value=None,
                new_value=_TS2,
                updated_at=datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC),
            )
            assert other.checkpoint_value == _TS2
            assert other.version == 1
            first = await uow.datasource_checkpoints.get(
                datasource_id=_SOURCE, checkpoint_kind=_KIND
            )
            assert first is not None
            assert first.checkpoint_value == _TS1

    @pytest.mark.asyncio
    async def test_db08_kind_isolation(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """DB08: distinct checkpoint kinds of one datasource are independent."""
        async with uow_factory() as uow:
            taxii = await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind=_KIND,
                expected_value=None,
                new_value=_TS1,
                updated_at=datetime(2026, 7, 1, tzinfo=UTC),
            )
            other_kind = await uow.datasource_checkpoints.advance(
                datasource_id=_SOURCE,
                checkpoint_kind="other_cursor",
                expected_value=None,
                new_value=_TS3,
                updated_at=datetime(2026, 7, 2, tzinfo=UTC),
            )
            assert taxii.checkpoint_kind != other_kind.checkpoint_kind
            re_read = await uow.datasource_checkpoints.get(
                datasource_id=_SOURCE, checkpoint_kind=_KIND
            )
            assert re_read is not None and re_read.checkpoint_value == _TS1

    @pytest.mark.asyncio
    async def test_db09_oversized_value_is_rejected(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """DB09: an oversized checkpoint value is rejected by the database."""
        async with uow_factory() as uow:
            with pytest.raises((ValueError, DatasourceCheckpointConflictError)):
                await uow.datasource_checkpoints.advance(
                    datasource_id=_SOURCE,
                    checkpoint_kind=_KIND,
                    expected_value=None,
                    new_value="x" * 513,
                    updated_at=datetime(2026, 7, 1, tzinfo=UTC),
                )

    @pytest.mark.asyncio
    async def test_db10_schema_carries_only_bounded_checkpoint_state(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """DB10: the schema/API carries only bounded operational checkpoint state."""
        async with integration_engine.begin() as connection:
            result = await connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'ati' AND table_name = "
                    "'datasource_checkpoint' ORDER BY ordinal_position"
                )
            )
            columns = [row[0] for row in result]
        assert columns == [
            "datasource_id",
            "checkpoint_kind",
            "checkpoint_value",
            "updated_at",
            "version",
            "created_at",
        ]

    @pytest.mark.asyncio
    async def test_kind_grammar_is_validated(self) -> None:
        """The checkpoint-kind grammar rejects unsafe identifiers."""
        with pytest.raises(ValueError):
            validate_checkpoint_kind("Bad Kind")
        assert validate_checkpoint_kind("taxii_added_after") == "taxii_added_after"
