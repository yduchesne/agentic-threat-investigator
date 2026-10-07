# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 38-9 durable LLM usage ledger persistence matrix over real PostgreSQL.

Exercises the production stored-function/repository path only:
``ati.append_llm_usage`` through ``PostgresLlmUsageRepository`` inside the real
``PostgresUnitOfWork``. The database owns non-negative constraints, currency/
pricing requirements, invocation-identity idempotency, and append-only
semantics; Python only binds validated parameters and maps returned rows.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.persistence.repositories import (
    LlmUsageConflictError,
    LlmUsageRecord,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

pytestmark = pytest.mark.integration

_REPORT_SCOPE = "urn:ati:llm:usage:investigations:scope:report_analyst"
_EVIDENCE_SCOPE = "urn:ati:llm:usage:investigations:scope:evidence_analyst"
_OPERATION = "urn:ati:llm:report_writing"
_OCCURRED = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)


def _record(
    *,
    invocation_id: Any = None,
    scope_urn: str = _REPORT_SCOPE,
    input_tokens: int | None = 100,
    output_tokens: int | None = 50,
    total_tokens: int | None = 150,
    total_cost: Decimal | None = Decimal("0.000123"),
    currency: str | None = "USD",
    pricing_id: str | None = "openai-gpt-4o-mini",
    pricing_version: str | None = "2024-07-18",
) -> LlmUsageRecord:
    """Build one deterministic usage record."""
    return LlmUsageRecord(
        scope_urn=scope_urn,
        operation_name=_OPERATION,
        invocation_id=invocation_id or uuid4(),
        provider="openai",
        model="gpt-4o-mini",
        occurred_at=_OCCURRED,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        total_cost=total_cost,
        currency=currency,
        pricing_id=pricing_id,
        pricing_version=pricing_version,
    )


async def _columns(engine: AsyncEngine) -> set[str]:
    """Return the column names of the durable usage table."""
    async with engine.begin() as connection:
        rows = await connection.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'ati' AND table_name = 'llm_usage'"
            )
        )
        return {row[0] for row in rows}


class TestLlmUsageLedger:
    """LU-P01..P11 over the real stored function."""

    @pytest.mark.asyncio
    async def test_lu_p01_append_one_event(
        self,
        uow_factory: Callable[[], PostgresUnitOfWork],
        integration_engine: AsyncEngine,
    ) -> None:
        """LU-P01: one append stores exactly one row."""
        record = _record()
        async with uow_factory() as uow:
            stored = await uow.llm_usage.append(record)
        assert stored.llm_usage_id is not None
        async with integration_engine.begin() as connection:
            count = await connection.scalar(
                text(
                    "SELECT count(*) FROM ati.llm_usage WHERE invocation_id = "
                    ":invocation_id"
                ),
                {"invocation_id": record.invocation_id},
            )
        assert count == 1

    @pytest.mark.asyncio
    async def test_lu_p02_duplicate_invocation_is_idempotent(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """LU-P02: an exact replay returns the same row, not a duplicate."""
        record = _record()
        async with uow_factory() as uow:
            first = await uow.llm_usage.append(record)
        async with uow_factory() as uow:
            second = await uow.llm_usage.append(record)
        assert first.llm_usage_id == second.llm_usage_id

    @pytest.mark.asyncio
    async def test_lu_p02b_conflicting_replay_rejected(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """LU-P02: a replay with different accounting fails closed."""
        record = _record()
        conflicting = _record(
            invocation_id=record.invocation_id,
            total_tokens=999,
            total_cost=Decimal("9.99"),
        )
        async with uow_factory() as uow:
            await uow.llm_usage.append(record)
        with pytest.raises(LlmUsageConflictError):
            async with uow_factory() as uow:
                await uow.llm_usage.append(conflicting)

    @pytest.mark.asyncio
    async def test_lu_p04_multiple_scopes_remain_distinct(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """LU-P04: distinct scope URNs remain distinct rows."""
        async with uow_factory() as uow:
            await uow.llm_usage.append(_record(scope_urn=_REPORT_SCOPE))
            await uow.llm_usage.append(_record(scope_urn=_EVIDENCE_SCOPE))

    @pytest.mark.asyncio
    async def test_lu_p05_unknown_fields_remain_null(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """LU-P05: unknown token fields persist as NULL, never zero."""
        record = _record(
            input_tokens=None,
            output_tokens=None,
            total_tokens=None,
            total_cost=None,
            currency=None,
            pricing_id=None,
            pricing_version=None,
        )
        async with uow_factory() as uow:
            stored = await uow.llm_usage.append(record)
        assert stored.input_tokens is None
        assert stored.total_tokens is None
        assert stored.total_cost is None
        assert stored.currency is None

    @pytest.mark.asyncio
    async def test_lu_p07_cost_without_currency_rejected(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """LU-P07: a cost without currency is rejected."""
        with pytest.raises(ValueError, match="currency"):
            _record(currency=None)

    @pytest.mark.asyncio
    async def test_lu_p08_pricing_identity_retained(
        self, uow_factory: Callable[[], PostgresUnitOfWork]
    ) -> None:
        """LU-P08: the immutable pricing identity/version round-trips."""
        async with uow_factory() as uow:
            stored = await uow.llm_usage.append(_record())
        assert stored.pricing_id == "openai-gpt-4o-mini"
        assert stored.pricing_version == "2024-07-18"

    @pytest.mark.asyncio
    async def test_lu_p06_negative_tokens_rejected_database_side(
        self, integration_engine: AsyncEngine
    ) -> None:
        """LU-P06: the database rejects negative token values."""
        async with integration_engine.begin() as connection:
            with pytest.raises(DBAPIError):
                await connection.execute(
                    text(
                        "SELECT * FROM ati.append_llm_usage("
                        "NULL, :scope, :operation, :invocation, 'openai', "
                        "'gpt-4o-mini', -5, NULL, NULL, NULL, NULL, NULL, NULL, "
                        "NULL, NULL, NULL, NULL, NULL, NULL, :occurred)"
                    ),
                    {
                        "scope": _REPORT_SCOPE,
                        "operation": _OPERATION,
                        "invocation": uuid4(),
                        "occurred": _OCCURRED,
                    },
                )

    @pytest.mark.asyncio
    async def test_lu_p09_no_prompt_or_output_columns(
        self, integration_engine: AsyncEngine
    ) -> None:
        """LU-P09: the ledger has no prompt/output/content columns."""
        columns = await _columns(integration_engine)
        assert not {"prompt", "output", "response", "content", "raw"} & columns

    @pytest.mark.asyncio
    async def test_lu_p11_stored_function_only_no_mutation_api(
        self, integration_engine: AsyncEngine
    ) -> None:
        """LU-P11: only the append function exists; no update/delete function."""
        async with integration_engine.begin() as connection:
            functions = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT routine_name FROM information_schema.routines "
                        "WHERE routine_schema = 'ati' "
                        "AND routine_name LIKE '%llm_usage%'"
                    )
                )
            }
        assert functions == {"append_llm_usage"}
