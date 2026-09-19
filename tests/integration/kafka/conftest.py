# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared Redpanda broker fixtures for real-broker Evidence-log tests (PR 28G).

The deterministic local broker is supplied by the integration harness
(``integration-test.sh``) as ``ATI_EVIDENCE_KAFKA_BOOTSTRAP``. When the
variable is absent the kafka integration tests skip cleanly rather than
failing on a missing external service; the unit gate never touches a broker.
A session-scoped Evidence topic with multiple partitions is provisioned once
per test run, and consumer group IDs are isolated per test.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from agentic_threat_investigator.infrastructure.kafka.topic import (
    ensure_evidence_topic,
)


def broker_bootstrap() -> str | None:
    """Return the configured local broker endpoint, or ``None`` when absent."""
    return os.environ.get("ATI_EVIDENCE_KAFKA_BOOTSTRAP") or None


@pytest_asyncio.fixture(scope="session")
async def kafka_bootstrap() -> AsyncIterator[str]:
    """Yield the isolated broker endpoint, skipping if none is configured.

    Forcing a skip (not a failure) lets the real-broker tests be discovered
    and collected in environments without a provisioned broker while keeping
    CI's isolated queue deterministic.
    """
    bootstrap = broker_bootstrap()
    if bootstrap is None:
        pytest.skip("ATI_EVIDENCE_KAFKA_BOOTSTRAP not set; skipping Redpanda tests")
    yield bootstrap


@pytest_asyncio.fixture(scope="session")
async def evidence_topic(kafka_bootstrap: str) -> AsyncIterator[str]:
    """Create one session-scoped multi-partition Evidence topic and yield it.

    A unique topic name isolates this test run from prior runs (no state
    bleed); three partitions prove the PR 28G multi-stream abstraction.
    """
    topic = f"ati.evidence.{uuid.uuid4().hex[:8]}"
    partitions = await ensure_evidence_topic(
        bootstrap_servers=kafka_bootstrap, topic=topic, partitions=3
    )
    assert partitions >= 3
    yield topic
