# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Evidence-topic creation and inspection (PR 28G).

PR 28G integration tests (and any local development harness) need an
explicitly created Evidence topic with more than one partition so the
broker-neutral multi-stream abstraction is actually exercised. This helper
is test/development infrastructure only: ATI does not provide an automatic
topic-management platform, and production topic administration is an
operator concern.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress

from aiokafka import AIOKafkaConsumer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import TopicAlreadyExistsError


class EvidenceTopicProvisionError(RuntimeError):
    """Raised when the Evidence topic cannot be provisioned.

    The message is bounded and never echoes broker metadata.
    """


async def ensure_evidence_topic(
    *,
    bootstrap_servers: str | tuple[str, ...],
    topic: str,
    partitions: int = 3,
    replication_factor: int = 1,
) -> int:
    """Create the Evidence topic if absent and return its partition count.

    ``replication_factor`` defaults to 1, appropriate for ATI's single-node
    deterministic test broker; single-node replication never proves
    production high availability. Only public ``aiokafka`` administration
    APIs are used; topic existence is confirmed before returning.
    """
    admin = AIOKafkaAdminClient(bootstrap_servers=bootstrap_servers)
    try:
        await admin.start()
        names = await _list_topics(admin)
        if topic not in names:
            with suppress(TopicAlreadyExistsError):
                await admin.create_topics(
                    [
                        NewTopic(
                            name=topic,
                            num_partitions=partitions,
                            replication_factor=replication_factor,
                        )
                    ]
                )
        await _wait_for_topic(bootstrap_servers, topic)
    finally:
        await admin.close()
    count = await _partition_count(bootstrap_servers, topic)
    if count is None:
        raise EvidenceTopicProvisionError("Evidence topic is not yet visible")
    return count


async def _list_topics(admin: AIOKafkaAdminClient) -> set[str]:
    """Return the current broker topic names through the public API."""
    return set(await admin.list_topics())


async def _wait_for_topic(
    bootstrap_servers: str | tuple[str, ...], topic: str, attempts: int = 20
) -> None:
    """Poll a short-lived consumer's metadata until the topic becomes visible."""
    for _ in range(attempts):
        if await _partition_count(bootstrap_servers, topic) is not None:
            return
        await asyncio.sleep(0.1)
    raise EvidenceTopicProvisionError("Evidence topic did not become visible")


async def _partition_count(
    bootstrap_servers: str | tuple[str, ...], topic: str
) -> int | None:
    """Return the partition count of one topic, or ``None`` while unknown.

    Uses the public consumer ``partitions_for_topic`` API (group-id-less) so
    no private broker internals are required.
    """
    consumer = AIOKafkaConsumer(
        group_id=None, bootstrap_servers=bootstrap_servers, enable_auto_commit=False
    )
    try:
        await consumer.start()
        partitions = await consumer.partitions_for_topic(topic)
    except Exception:  # noqa: BLE001 - the topic may not exist yet while provisioning; public-Api probe failure means "not visible", never raw error leakage
        return None
    finally:
        await consumer.stop()
    if not partitions:
        return None
    return len(partitions)
