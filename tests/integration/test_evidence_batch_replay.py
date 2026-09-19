# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 28E required replay test: same-Evidence multi-state batch redelivery.

The canonical at-least-once case: a polled ``EvidenceBatch`` is persisted in
one atomic PostgreSQL transaction, the PostgreSQL COMMIT succeeds, the
consumer commit then FAILS (``log.fail_next_commit``), and the identical
ordered batch is redelivered. This test is the converted PR 28E STOP #10
probe: it must now PASS because the receipt table
(``ati.evidence_message_receipt``, keyed by the stable PR 28C
``message_id``) makes the redelivery idempotent.

Required sequence (from the reviewer decision):

1. publish messages ``[A, B, C]`` for one stable Evidence;
2. consume: PostgreSQL commits ``v1/v2/v3``, consumer commit fails;
3. redeliver the identical messages and consume again;
4. verify exactly three observations remain with no duplicate derived graph
   state (Entities, Relationships, RelationshipObservations unchanged).

The replay resolves every record through its receipt — the Evidence
transition and the derived graph writes are not invoked again. Nothing here
skips records in Python, compares material state instead of message
identity, uses transport positions as idempotency keys, or duplicates the
Evidence transition algorithm.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from agentic_threat_investigator.app.evidence_batch_persistence import (
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_consumer import (
    EvidencePersistenceConsumer,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceCommitError,
    EvidenceConsumerId,
    InMemoryEvidenceLog,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.evidence_batch_fixtures import (
    build_threatfox_fact,
    threatfox_message,
)

_RETRIEVED_AT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_CONSUMER_ID = EvidenceConsumerId("pr-28e-multistate-replay")


async def _count(uow: PostgresUnitOfWork, table: str) -> int:
    """Count all rows of one ati table inside the active transaction."""
    assert uow.session is not None
    result = await uow.session.execute(text(f"SELECT count(*) FROM ati.{table}"))
    return int(result.scalar_one())


def _states() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Return three distinct material states of one ThreatFox Evidence.

    The malware family differs per state so ``facts`` (the material state)
    differs; the IOC, source, and source-record identity (the stable
    Evidence identity) stay fixed.
    """
    return (
        {
            "matches": [
                build_threatfox_fact(
                    ioc="malicious-domain.test",
                    ioc_type="domain",
                    malware="win.asyncrat",
                )
            ]
        },
        {
            "matches": [
                build_threatfox_fact(
                    ioc="malicious-domain.test",
                    ioc_type="domain",
                    malware="agent.tesla",
                )
            ]
        },
        {
            "matches": [
                build_threatfox_fact(
                    ioc="malicious-domain.test",
                    ioc_type="domain",
                    malware="redline.stealer",
                )
            ]
        },
    )


async def _publish_three(log: InMemoryEvidenceLog) -> None:
    """Publish one EvidenceMessage per material state, in order."""
    from agentic_threat_investigator.app.evidence_message import EvidenceMessage

    records: list[EvidenceMessage] = []
    for index, facts in enumerate(_states()):
        message, _ = threatfox_message(
            ioc="malicious-domain.test",
            ioc_type="domain",
            source_record_id="same-evidence-record",
            sequence=index,
            retrieved_at=_RETRIEVED_AT,
            facts=facts,
        )
        records.append(message)

    await log.publisher().publish(tuple(records))


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_multistate_batch_redelivery_is_idempotent(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PostgreSQL-commit + consumer-commit-failure replay creates no rows."""
    log = InMemoryEvidenceLog()
    await _publish_three(log)

    service = EvidenceBatchPersistenceService(uow_factory)
    consumer = EvidencePersistenceConsumer(
        consumer=log.consumer(_CONSUMER_ID),
        persistence=service,
        batch_size=10,
    )

    # First pass: PostgreSQL commits [A,B,C]; the consumer commit fails.
    log.fail_next_commit(_CONSUMER_ID)
    with pytest.raises(EvidenceCommitError):
        await consumer.process_next_batch()

    async with uow_factory() as uow:
        assert uow.session is not None
        observations_after_commit = await _count(uow, "evidence_observation")
        entities_after_commit = await _count(uow, "entity")
        relationships_after_commit = await _count(uow, "relationship")
        relationship_observations_after_commit = await _count(
            uow, "relationship_observation"
        )
        receipts_after_commit = await _count(uow, "evidence_message_receipt")
        versions = [
            row[0]
            for row in (
                await uow.session.execute(
                    text(
                        "SELECT version FROM ati.evidence_observation ORDER BY version"
                    )
                )
            ).fetchall()
        ]
    assert versions == [1, 2, 3]
    assert observations_after_commit == 3
    assert receipts_after_commit == 3
    assert entities_after_commit == 4  # subject + one malware per state
    assert relationships_after_commit == 3
    assert relationship_observations_after_commit == 3

    # Redelivery: the identical ordered batch is re-persisted; every record
    # resolves through its receipt — no transition, no derived writes, and
    # the previously established authoritative results (CREATED for A,
    # APPENDED for B and C) are echoed back.
    result = await consumer.process_next_batch()
    assert result.committed is True
    assert result.persisted_count == 3
    assert (result.created_count, result.appended_count) == (1, 2)

    async with uow_factory() as uow:
        assert uow.session is not None
        assert await _count(uow, "evidence_observation") == observations_after_commit
        assert await _count(uow, "entity") == entities_after_commit
        assert await _count(uow, "relationship") == relationships_after_commit
        assert (
            await _count(uow, "relationship_observation")
            == relationship_observations_after_commit
        )
        assert await _count(uow, "evidence_message_receipt") == receipts_after_commit
        versions = [
            row[0]
            for row in (
                await uow.session.execute(
                    text(
                        "SELECT version FROM ati.evidence_observation ORDER BY version"
                    )
                )
            ).fetchall()
        ]
    assert versions == [1, 2, 3]

    # The consumer cursor advanced: the next poll is empty.
    empty = await log.consumer(_CONSUMER_ID).poll(10)
    assert not empty.records
