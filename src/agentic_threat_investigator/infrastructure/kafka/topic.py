# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Evidence-topic creation and inspection (PR 28G).

PR 28G integration tests (and any local development harness) need an
explicitly created Evidence topic with more than one partition so the
broker-neutral multi-stream abstraction is actually exercised. This helper
is test/development infrastructure only: ATI does not provide an automatic
topic-management platform, and production topic administration is an
operator concern.

Topic existence and partition metadata are always inspected through the
public ``aiokafka`` administrative API. A temporary Kafka consumer is never
constructed for metadata: aiokafka 0.14's group-less consumer shutdown can
surface ``asyncio.CancelledError`` for short-lived metadata probes, which
would poison fixture teardown without any functional benefit. One
administrative client is started, reused for every probe, and always
closed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from typing import Protocol, cast

from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import TopicAlreadyExistsError


class TopicAdmin(Protocol):
    """Narrow public administrative boundary for Evidence-topic metadata.

    Only the public ``aiokafka`` administration operations the provisioning
    helper relies on are declared, so unit tests can substitute a
    deterministic double without a real broker connection. The real
    ``AIOKafkaAdminClient`` satisfies this boundary through ``cast`` at the
    construction site, mirroring the adapter factories.
    """

    async def start(self) -> None: ...
    async def close(self) -> None: ...
    async def list_topics(self) -> list[str]: ...
    async def create_topics(self, new_topics: list[NewTopic]) -> None: ...
    async def describe_topics(self, topics: list[str]) -> list[dict[str, object]]: ...


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
    admin_factory: Callable[[], TopicAdmin] | None = None,
) -> int:
    """Create the Evidence topic if absent and return its partition count.

    One administrative client is started, then reused for inspection,
    creation, bounded visibility polling, and the actual partition count,
    and always closed on normal completion or failure.

    ``replication_factor`` defaults to 1, appropriate for ATI's single-node
    deterministic test broker; single-node replication never proves
    production high availability. Only public ``aiokafka`` administration
    APIs are used; topic existence is confirmed before returning.
    """
    if admin_factory is None:

        def default_factory() -> TopicAdmin:
            return cast(
                TopicAdmin,
                AIOKafkaAdminClient(bootstrap_servers=bootstrap_servers),
            )

        admin_factory = default_factory
    admin = admin_factory()
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
        await _wait_for_topic(admin, topic)
        count = await _partition_count(admin, topic)
    finally:
        await admin.close()
    if count is None:
        raise EvidenceTopicProvisionError("Evidence topic is not yet visible")
    return count


async def _list_topics(admin: TopicAdmin) -> set[str]:
    """Return the current broker topic names through the public API."""
    return set(await admin.list_topics())


async def _wait_for_topic(admin: TopicAdmin, topic: str, attempts: int = 20) -> None:
    """Poll the running admin's metadata until the topic becomes visible."""
    for _ in range(attempts):
        if await _partition_count(admin, topic) is not None:
            return
        await asyncio.sleep(0.1)
    raise EvidenceTopicProvisionError("Evidence topic did not become visible")


async def _partition_count(admin: TopicAdmin, topic: str) -> int | None:
    """Return the partition count of one topic, or ``None`` while unknown.

    Uses the public admin ``list_topics`` / ``describe_topics`` API on the
    caller's already-started client: no private broker internals and no
    temporary Kafka consumer are involved.
    """
    try:
        names = set(await admin.list_topics())
    except Exception:  # noqa: BLE001 - metadata may not be visible yet while provisioning; public-API probe failure means "not visible", never raw error leakage
        return None
    if topic not in names:
        return None
    try:
        described = await admin.describe_topics([topic])
    except Exception:  # noqa: BLE001 - metadata may not be visible yet while provisioning; public-API probe failure means "not visible", never raw error leakage
        return None
    for metadata in described:
        if metadata.get("topic") != topic or metadata.get("error_code", 0) != 0:
            continue
        raw_partitions = metadata.get("partitions")
        if not isinstance(raw_partitions, list) or not raw_partitions:
            return None
        return len(raw_partitions)
    return None
