# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL API investigation creation integration tests (23C-I02..I05).

Proves the atomic asynchronous submission contract over real PostgreSQL:
POST persists Investigation + durable job + audit + idempotency record in one
transaction, replays resolve to the same Investigation, mismatches return
409, and concurrent identical submissions create exactly one Investigation
and one job.
"""

from __future__ import annotations

import asyncio
import os
import uuid as _uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.investigation_submission import (
    IndicatorInput,
    InvestigationSubmission,
    InvestigationSubmissionService,
)
from agentic_threat_investigator.config import ensure_test_database_safe
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.integration.api_helpers import (
    api_client,
    api_settings,
    create_payload,
    csrf_headers,
    seed_user,
)


async def _count(engine: Any, table: str) -> int:
    """Return the row count of one ati table."""
    async with engine.begin() as connection:
        return int(await connection.scalar(text(f"SELECT count(*) FROM ati.{table}")))


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i02_create_investigation_transaction(
    session_factory: Any, integration_engine: Any
) -> None:
    """POST persists Investigation + job + audit + idempotency; no execution."""
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        assert login.status_code == 200

        response = client.post(
            "/api/v1/investigations",
            json=create_payload(),
            headers={"Idempotency-Key": "create-1", **csrf_headers(client)},
        )

    assert response.status_code == 202
    body = response.json()
    investigation_id = body["id"]
    assert body["status"] == "pending"
    assert response.headers["location"] == f"/api/v1/investigations/{investigation_id}"

    # Investigation, durable job, audit, and idempotency record all exist.
    assert await _count(integration_engine, "investigation") == 1
    assert await _count(integration_engine, "investigation_job") == 1
    assert await _count(integration_engine, "api_idempotency") == 1
    async with integration_engine.begin() as connection:
        audit_count = await connection.scalar(
            text(
                "SELECT count(*) FROM ati.audit_event "
                "WHERE object_type = 'investigation' AND object_id = :oid"
            ),
            {"oid": investigation_id},
        )
        job_status = await connection.scalar(
            text(
                "SELECT status FROM ati.investigation_job WHERE investigation_id = :oid"
            ),
            {"oid": investigation_id},
        )
    assert int(audit_count) == 1
    assert job_status == "pending"
    # The Investigation persisted as PENDING; the runner has not executed.
    async with integration_engine.begin() as connection:
        status = await connection.scalar(
            text("SELECT status FROM ati.investigation WHERE id = :oid"),
            {"oid": investigation_id},
        )
    assert status == "pending"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i03_idempotent_replay_returns_same_investigation(
    session_factory: Any, integration_engine: Any
) -> None:
    """Equivalent replay returns the same Investigation and one logical job."""
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        headers = {"Idempotency-Key": "create-1", **csrf_headers(client)}
        first = client.post(
            "/api/v1/investigations", json=create_payload(), headers=headers
        )
        second = client.post(
            "/api/v1/investigations", json=create_payload(), headers=headers
        )

    assert first.status_code == second.status_code == 202
    assert first.json()["id"] == second.json()["id"]
    assert first.headers["location"] == second.headers["location"]
    assert await _count(integration_engine, "investigation") == 1
    assert await _count(integration_engine, "investigation_job") == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i04_concurrent_identical_submissions_create_one_investigation(
    session_factory: Any, integration_engine: Any
) -> None:
    """Concurrent identical submissions create exactly one Investigation/job."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.fail("DATABASE_URL must point at the isolated integration database")
    ensure_test_database_safe(url)
    service = InvestigationSubmissionService(
        lambda: PostgresUnitOfWork(session_factory),
        clock=lambda: datetime.now(UTC),
    )
    submission = InvestigationSubmission(
        indicators=[IndicatorInput(type=EntityType.DOMAIN, value="example.com")],
        objective="assess the example domain",
    )
    actor_uuid = _uuid.uuid4()

    results = await asyncio.gather(
        service.submit(submission, actor_id=actor_uuid, idempotency_key="race-key"),
        service.submit(submission, actor_id=actor_uuid, idempotency_key="race-key"),
    )

    assert results[0].investigation_id == results[1].investigation_id
    assert await _count(integration_engine, "investigation") == 1
    assert await _count(integration_engine, "investigation_job") == 1
    assert await _count(integration_engine, "api_idempotency") == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i05_idempotency_mismatch_returns_409(
    session_factory: Any, integration_engine: Any
) -> None:
    """Same key with a different semantic request returns 409, no extra rows."""
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        headers = {"Idempotency-Key": "create-1", **csrf_headers(client)}
        first = client.post(
            "/api/v1/investigations", json=create_payload(), headers=headers
        )
        different = create_payload()
        different["objective"] = "a completely different objective"
        second = client.post("/api/v1/investigations", json=different, headers=headers)

    assert first.status_code == 202
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "idempotency_conflict"
    assert await _count(integration_engine, "investigation") == 1
    assert await _count(integration_engine, "investigation_job") == 1
