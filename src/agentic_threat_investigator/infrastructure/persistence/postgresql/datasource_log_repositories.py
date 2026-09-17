# SPDX-License-Identifier: AGPL-3.0-only
"""Thin PostgreSQL adapter for the append-only datasource log.

Every datasource-log mutation routes through the versioned SQL API stored
function ``ati.append_datasource_log_event`` (SQL API v0025), which owns all
lifecycle/concurrency invariants: STARTED first and unique, datasource
identity stability, at most one terminal event, and no append after a
terminal outcome. This adapter never issues a direct INSERT/UPDATE/DELETE
against ``ati.datasource_log`` and never reproduces lifecycle logic in
Python. It only binds typed event values and translates the database's typed
``U27B*`` SQLSTATEs into application errors.
"""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceLogAppendAfterTerminalError,
    DatasourceLogDatasourceMismatchError,
    DatasourceLogDuplicateStartedError,
    DatasourceLogFirstEventError,
    DatasourceLogInvalidInputError,
    DatasourceLogRepository,
)
from agentic_threat_investigator.domain.datasource import DatasourceLogEvent

from .errors import sqlstate

SQLSTATE_DATASOURCE_LOG_INVALID_INPUT = "U27B1"
SQLSTATE_DATASOURCE_LOG_FIRST_EVENT = "U27B2"
SQLSTATE_DATASOURCE_LOG_DATASOURCE_MISMATCH = "U27B3"
SQLSTATE_DATASOURCE_LOG_DUPLICATE_STARTED = "U27B4"
SQLSTATE_DATASOURCE_LOG_APPEND_AFTER_TERMINAL = "U27B5"


class PostgresDatasourceLogRepository(DatasourceLogRepository):
    """Append-only datasource-log adapter over one active session."""

    def __init__(self, session: AsyncSession) -> None:
        """Bind the datasource-log repository to the caller's transaction session."""
        self._session = session

    async def append(self, event: DatasourceLogEvent) -> None:
        """Append one event in the caller's transaction without committing.

        The stored function validates the event against the execution's
        durable lifecycle; violations surface as typed errors and the
        caller's UnitOfWork remains the commit/rollback boundary.
        """
        try:
            await self._session.execute(
                text(
                    "SELECT * FROM ati.append_datasource_log_event("
                    ":p_execution_id, :p_datasource_id, :p_event_type, "
                    ":p_occurred_at, :p_item_count, :p_byte_count, :p_error_code)"
                ),
                {
                    "p_execution_id": event.execution_id,
                    "p_datasource_id": event.datasource_id.value,
                    "p_event_type": event.event_type.value,
                    "p_occurred_at": event.occurred_at,
                    "p_item_count": event.item_count,
                    "p_byte_count": event.byte_count,
                    "p_error_code": event.error_code,
                },
            )
        except DBAPIError as error:
            self._raise_from_dbapi(
                error,
                execution_id=event.execution_id,
                datasource_id=event.datasource_id.value,
            )
            raise  # pragma: no cover - _raise_from_dbapi always raises

    @staticmethod
    def _raise_from_dbapi(
        error: BaseException,
        *,
        execution_id: UUID,
        datasource_id: str,
    ) -> None:
        """Translate a typed datasource-log SQLSTATE into the application error."""
        state = sqlstate(error)
        if state == SQLSTATE_DATASOURCE_LOG_INVALID_INPUT:
            raise DatasourceLogInvalidInputError(
                "database rejected invalid datasource log input"
            ) from error
        if state == SQLSTATE_DATASOURCE_LOG_FIRST_EVENT:
            raise DatasourceLogFirstEventError(execution_id) from error
        if state == SQLSTATE_DATASOURCE_LOG_DATASOURCE_MISMATCH:
            raise DatasourceLogDatasourceMismatchError(
                execution_id, datasource_id
            ) from error
        if state == SQLSTATE_DATASOURCE_LOG_DUPLICATE_STARTED:
            raise DatasourceLogDuplicateStartedError(execution_id) from error
        if state == SQLSTATE_DATASOURCE_LOG_APPEND_AFTER_TERMINAL:
            raise DatasourceLogAppendAfterTerminalError(execution_id) from error
