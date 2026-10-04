# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Thin PostgreSQL adapter for the operational datasource checkpoint.

Every checkpoint read/mutation routes through the versioned SQL API stored
functions ``ati.get_datasource_checkpoint`` / ``ati.advance_datasource_checkpoint``
(SQL API v0032), which own all row/concurrency invariants: one row per
``(datasource_id, checkpoint_kind)``, bounded canonical values, and
compare-and-advance under a transaction-scoped advisory lock. This adapter
never issues a direct INSERT/UPDATE/DELETE against ``ati.datasource_checkpoint``
and never reproduces checkpoint logic in Python. It only binds typed values
and translates the database's typed ``U32A*`` SQLSTATEs into application
errors; the caller's UnitOfWork remains the commit/rollback boundary.
"""

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceCheckpoint,
    DatasourceCheckpointConflictError,
    DatasourceCheckpointRepository,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.errors import (
    SQLSTATE_DATASOURCE_CHECKPOINT_INVALID_INPUT,
    SQLSTATE_DATASOURCE_CHECKPOINT_STALE,
    sqlstate,
)
from agentic_threat_investigator.telemetry.decorators import (
    postgres_repository_operation,
)


class PostgresDatasourceCheckpointRepository(DatasourceCheckpointRepository):
    """Datasource-checkpoint adapter over one active session."""

    def __init__(self, session: AsyncSession) -> None:
        """Bind the checkpoint repository to the caller's transaction session."""
        self._session = session

    @postgres_repository_operation(
        repository="PostgresDatasourceCheckpointRepository", operation="get"
    )
    async def get(
        self, *, datasource_id: str, checkpoint_kind: str
    ) -> DatasourceCheckpoint | None:
        """Read the current checkpoint row, or ``None`` when absent."""
        if not datasource_id or not checkpoint_kind:
            raise ValueError("checkpoint identifiers must not be blank")
        result = await self._session.execute(
            text(
                "SELECT * FROM ati.get_datasource_checkpoint("
                ":p_datasource_id, :p_checkpoint_kind)"
            ),
            {"p_datasource_id": datasource_id, "p_checkpoint_kind": checkpoint_kind},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return DatasourceCheckpoint(
            datasource_id=row["datasource_id"],
            checkpoint_kind=row["checkpoint_kind"],
            checkpoint_value=row["checkpoint_value"],
            updated_at=row["updated_at"],
            version=row["version"],
        )

    @postgres_repository_operation(
        repository="PostgresDatasourceCheckpointRepository", operation="advance"
    )
    async def advance(
        self,
        *,
        datasource_id: str,
        checkpoint_kind: str,
        expected_value: str | None,
        new_value: str,
        updated_at: datetime,
    ) -> DatasourceCheckpoint:
        """Compare-and-advance one checkpoint in the caller's transaction.

        The stored function rejects a stale expectation deterministically;
        an advance to the current value is an idempotent no-op returning the
        existing row unchanged. The caller's UnitOfWork remains the commit
        boundary.
        """
        try:
            result = await self._session.execute(
                text(
                    "SELECT * FROM ati.advance_datasource_checkpoint("
                    ":p_datasource_id, :p_checkpoint_kind, :p_expected_value, "
                    ":p_new_value, :p_updated_at)"
                ),
                {
                    "p_datasource_id": datasource_id,
                    "p_checkpoint_kind": checkpoint_kind,
                    "p_expected_value": expected_value,
                    "p_new_value": new_value,
                    "p_updated_at": updated_at,
                },
            )
        except DBAPIError as error:
            self._raise_from_dbapi(error)
            raise  # pragma: no cover - _raise_from_dbapi always raises
        row = result.mappings().first()
        if row is None:
            raise DatasourceCheckpointConflictError(
                "checkpoint advance returned no durable row"
            )
        return DatasourceCheckpoint(
            datasource_id=row["datasource_id"],
            checkpoint_kind=row["checkpoint_kind"],
            checkpoint_value=row["checkpoint_value"],
            updated_at=row["updated_at"],
            version=row["version"],
        )

    @staticmethod
    def _raise_from_dbapi(error: BaseException) -> None:
        """Translate a typed checkpoint SQLSTATE into the application error."""
        state = sqlstate(error)
        if state == SQLSTATE_DATASOURCE_CHECKPOINT_INVALID_INPUT:
            raise ValueError("database rejected invalid checkpoint input") from error
        if state == SQLSTATE_DATASOURCE_CHECKPOINT_STALE:
            raise DatasourceCheckpointConflictError(
                "checkpoint expectation is stale; another execution advanced it"
            ) from error
