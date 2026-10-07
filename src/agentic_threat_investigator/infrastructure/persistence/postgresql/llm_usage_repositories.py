# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Thin PostgreSQL adapter for durable LLM usage accounting (PR 38-9).

Every append routes through the versioned SQL API stored function
``ati.append_llm_usage`` (SQL API v0035), which owns all row invariants and
invocation-identity idempotency. This adapter never issues a direct
INSERT/UPDATE/DELETE against ``ati.llm_usage`` and never reproduces accounting
logic in Python. It only binds validated parameters and maps the returned row;
the caller's UnitOfWork remains the commit/rollback boundary. There is no
update or delete operation: the ledger is append-only.
"""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    LlmUsageAppendResult,
    LlmUsageConflictError,
    LlmUsageRecord,
    LlmUsageRepository,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.errors import (
    SQLSTATE_LLM_USAGE_CONFLICT,
    SQLSTATE_LLM_USAGE_INVALID_INPUT,
    sqlstate,
)
from agentic_threat_investigator.telemetry.decorators import (
    postgres_repository_operation,
)

_APPEND_SQL = (
    "SELECT llm_usage_id, investigation_id, scope_urn, operation_name, "
    "invocation_id, provider, model, input_tokens, output_tokens, "
    "cached_tokens, reasoning_tokens, total_tokens, input_cost, output_cost, "
    "cached_cost, reasoning_cost, total_cost, currency, pricing_id, "
    "pricing_version, occurred_at, created "
    "FROM ati.append_llm_usage("
    ":p_investigation_id, :p_scope_urn, :p_operation_name, :p_invocation_id, "
    ":p_provider, :p_model, :p_input_tokens, :p_output_tokens, "
    ":p_cached_tokens, :p_reasoning_tokens, :p_total_tokens, :p_input_cost, "
    ":p_output_cost, :p_cached_cost, :p_reasoning_cost, :p_total_cost, "
    ":p_currency, :p_pricing_id, :p_pricing_version, :p_occurred_at)"
)


class PostgresLlmUsageRepository(LlmUsageRepository):
    """Append-only LLM usage adapter over one active session."""

    def __init__(self, session: AsyncSession) -> None:
        """Bind the usage repository to the caller's transaction session."""
        self._session = session

    @postgres_repository_operation(
        repository="PostgresLlmUsageRepository", operation="append"
    )
    async def append(self, record: LlmUsageRecord) -> LlmUsageAppendResult:
        """Append one usage event and report whether it was newly created.

        The stored function atomically distinguishes a new invocation from an
        exact replay; the adapter maps that disposition without a second query.
        """
        try:
            result = await self._session.execute(
                text(_APPEND_SQL),
                {
                    "p_investigation_id": record.investigation_id,
                    "p_scope_urn": record.scope_urn,
                    "p_operation_name": record.operation_name,
                    "p_invocation_id": record.invocation_id,
                    "p_provider": record.provider,
                    "p_model": record.model,
                    "p_input_tokens": record.input_tokens,
                    "p_output_tokens": record.output_tokens,
                    "p_cached_tokens": record.cached_tokens,
                    "p_reasoning_tokens": record.reasoning_tokens,
                    "p_total_tokens": record.total_tokens,
                    "p_input_cost": record.input_cost,
                    "p_output_cost": record.output_cost,
                    "p_cached_cost": record.cached_cost,
                    "p_reasoning_cost": record.reasoning_cost,
                    "p_total_cost": record.total_cost,
                    "p_currency": record.currency,
                    "p_pricing_id": record.pricing_id,
                    "p_pricing_version": record.pricing_version,
                    "p_occurred_at": record.occurred_at,
                },
            )
        except DBAPIError as error:
            self._raise_from_dbapi(error, record.invocation_id)
            raise  # pragma: no cover - _raise_from_dbapi always raises
        row = result.mappings().first()
        if row is None:
            raise LlmUsageConflictError(record.invocation_id)
        stored = LlmUsageRecord(
            scope_urn=row["scope_urn"],
            operation_name=row["operation_name"],
            invocation_id=row["invocation_id"],
            provider=row["provider"],
            model=row["model"],
            occurred_at=row["occurred_at"],
            investigation_id=row["investigation_id"],
            input_tokens=row["input_tokens"],
            output_tokens=row["output_tokens"],
            cached_tokens=row["cached_tokens"],
            reasoning_tokens=row["reasoning_tokens"],
            total_tokens=row["total_tokens"],
            input_cost=row["input_cost"],
            output_cost=row["output_cost"],
            cached_cost=row["cached_cost"],
            reasoning_cost=row["reasoning_cost"],
            total_cost=row["total_cost"],
            currency=row["currency"],
            pricing_id=row["pricing_id"],
            pricing_version=row["pricing_version"],
            llm_usage_id=row["llm_usage_id"],
        )
        return LlmUsageAppendResult(record=stored, created=bool(row["created"]))

    @staticmethod
    def _raise_from_dbapi(error: BaseException, invocation_id: UUID) -> None:
        """Translate a typed usage SQLSTATE into the application error."""
        state = sqlstate(error)
        if state == SQLSTATE_LLM_USAGE_INVALID_INPUT:
            raise ValueError(
                "database rejected invalid llm usage accounting input"
            ) from error
        if state == SQLSTATE_LLM_USAGE_CONFLICT:
            raise LlmUsageConflictError(invocation_id) from error
