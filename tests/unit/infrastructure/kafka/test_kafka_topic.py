# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence-topic provisioning helper unit tests (PR 28G CI follow-up).

Covers the T28G-T matrix against a narrow deterministic double of the
public ``aiokafka`` administrative boundary. Metadata inspection must never
construct a temporary Kafka consumer (T28G-T06): the helper talks to a
broker only through :class:`TopicAdmin` administration operations.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest
from aiokafka.admin import NewTopic
from aiokafka.errors import TopicAlreadyExistsError

from agentic_threat_investigator.infrastructure.kafka import topic as topic_module
from agentic_threat_investigator.infrastructure.kafka.topic import (
    EvidenceTopicProvisionError,
    TopicAdmin,
    ensure_evidence_topic,
)

pytestmark = pytest.mark.unit

TOPIC = "ati.evidence.test"


class FakeTopicAdmin(TopicAdmin):
    """Deterministic administrative-boundary double.

    ``created`` tracks topics this double created; after creation a topic
    becomes visible to ``list_topics`` only once the probe counter passes
    ``visibility_delay`` (modelling lagging broker metadata), or never when
    ``never_visible`` is set.
    """

    def __init__(
        self,
        *,
        known: set[str] | None = None,
        partitions: dict[str, int] | None = None,
        create_error: BaseException | None = None,
        visibility_delay: int = 0,
        never_visible: bool = False,
    ) -> None:
        """Initialize the double with topic names, counts, and failure modes."""
        self.known = set(known or ())
        self.partitions = dict(partitions or {})
        self.create_error = create_error
        self.visibility_delay = visibility_delay
        self.never_visible = never_visible
        self.started = False
        self.closed = False
        self.create_calls: list[list[NewTopic]] = []
        self.created: set[str] = set()
        self.probes = 0

    async def start(self) -> None:
        """Mark the double started."""
        self.started = True

    async def close(self) -> None:
        """Mark the double closed."""
        self.closed = True

    async def list_topics(self) -> list[str]:
        """Return visible topic names, honouring creation/delay/never modes."""
        self.probes += 1
        visible = set(self.known)
        for name in self.created:
            if not self.never_visible and self.probes > self.visibility_delay:
                visible.add(name)
        return sorted(visible)

    async def create_topics(self, new_topics: list[NewTopic]) -> None:
        """Record the creation request, then apply the configured outcome."""
        self.create_calls.append(new_topics)
        for new_topic in new_topics:
            self.created.add(new_topic.name)
        if self.create_error is not None:
            raise self.create_error

    async def describe_topics(self, topics: list[str]) -> list[dict[str, object]]:
        """Return partition metadata for each currently visible requested topic."""
        visible = set(await self.list_topics())
        described: list[dict[str, object]] = []
        for name in topics:
            if name not in visible:
                continue
            count = self.partitions.get(name, 0)
            described.append(
                {
                    "topic": name,
                    "error_code": 0,
                    "partitions": [{"partition": index} for index in range(count)],
                }
            )
        return described


def _factory(admin: FakeTopicAdmin) -> Any:
    """Return a factory yielding the single provided administrative double."""
    return lambda: admin


@pytest.mark.asyncio
async def test_t01_existing_topic_no_create_returns_count() -> None:
    """T28G-T01: an existing topic is not recreated and its count is returned."""
    admin = FakeTopicAdmin(known={TOPIC}, partitions={TOPIC: 3})
    count = await ensure_evidence_topic(
        bootstrap_servers="h:1",
        topic=TOPIC,
        admin_factory=_factory(admin),
    )
    assert count == 3
    assert admin.create_calls == []
    assert admin.started and admin.closed


@pytest.mark.asyncio
async def test_t02_missing_topic_created_and_visible() -> None:
    """T28G-T02: an absent topic is created once and its count is returned."""
    admin = FakeTopicAdmin(known=set(), partitions={TOPIC: 4})
    count = await ensure_evidence_topic(
        bootstrap_servers="h:1",
        topic=TOPIC,
        partitions=4,
        admin_factory=_factory(admin),
    )
    assert count == 4
    assert len(admin.create_calls) == 1
    assert admin.create_calls[0][0].name == TOPIC
    assert admin.create_calls[0][0].num_partitions == 4
    assert admin.started and admin.closed


@pytest.mark.asyncio
async def test_t03_concurrent_creation_race_is_safe() -> None:
    """T28G-T03: a TopicAlreadyExistsError race continues to verification."""
    admin = FakeTopicAdmin(
        known=set(),
        partitions={TOPIC: 3},
        create_error=TopicAlreadyExistsError(TOPIC),
    )
    count = await ensure_evidence_topic(
        bootstrap_servers="h:1",
        topic=TOPIC,
        admin_factory=_factory(admin),
    )
    assert count == 3
    assert len(admin.create_calls) == 1
    assert admin.started and admin.closed


@pytest.mark.asyncio
async def test_t04_delayed_visibility_bounded_retry_succeeds() -> None:
    """T28G-T04: lagging metadata becomes visible within the bounded retry."""
    admin = FakeTopicAdmin(
        known=set(),
        partitions={TOPIC: 3},
        visibility_delay=3,
    )
    count = await ensure_evidence_topic(
        bootstrap_servers="h:1",
        topic=TOPIC,
        admin_factory=_factory(admin),
    )
    assert count == 3
    assert admin.probes > 1  # retried until visible


@pytest.mark.asyncio
async def test_t05_never_visible_raises_provision_error() -> None:
    """T28G-T05: permanent invisibility raises EvidenceTopicProvisionError."""
    admin = FakeTopicAdmin(
        known=set(),
        partitions={TOPIC: 3},
        never_visible=True,
    )
    with pytest.raises(EvidenceTopicProvisionError):
        await ensure_evidence_topic(
            bootstrap_servers="h:1",
            topic=TOPIC,
            admin_factory=_factory(admin),
        )
    assert admin.started and admin.closed


def test_t06_no_metadata_consumer_is_constructed() -> None:
    """T28G-T06: metadata inspection never constructs a Kafka consumer.

    Structural check: the provisioning module must not reference
    ``AIOKafkaConsumer`` anywhere; metadata access goes through the public
    administrative boundary only.
    """
    source = inspect.getsource(topic_module)
    assert "AIOKafkaConsumer" not in source


@pytest.mark.asyncio
async def test_t07_admin_closed_on_completion_and_failure() -> None:
    """T28G-T07: the admin client is closed on success and ordinary failure."""
    success = FakeTopicAdmin(known={TOPIC}, partitions={TOPIC: 3})
    await ensure_evidence_topic(
        bootstrap_servers="h:1", topic=TOPIC, admin_factory=_factory(success)
    )
    assert success.closed

    failure = FakeTopicAdmin(known=set(), partitions={TOPIC: 3}, never_visible=True)
    with pytest.raises(EvidenceTopicProvisionError):
        await ensure_evidence_topic(
            bootstrap_servers="h:1",
            topic=TOPIC,
            admin_factory=_factory(failure),
        )
    assert failure.closed
