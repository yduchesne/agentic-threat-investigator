# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Kafka-compatible infrastructure adapters for the distributed Evidence log (PR 28G).

The package implements the PR 28D :class:`EvidencePublisher` /
:class:`EvidenceConsumer` contracts against a Kafka-compatible broker
(Redpanda in ATI's deterministic local/integration deployments) using
``aiokafka``. It never leaks Kafka/aiokafka/Redpanda vocabulary into the
application Evidence domain: records are keyed by the stable
:class:`EvidenceMessage` ``evidence_id``, and broker partition/offset are
mapped to the broker-neutral ``(stream, offset)``
:class:`EvidenceLogPosition` at this boundary only.
"""

from agentic_threat_investigator.infrastructure.kafka.evidence_log import (
    KafkaEvidenceConsumer,
    KafkaEvidencePublisher,
)
from agentic_threat_investigator.infrastructure.kafka.topic import (
    ensure_evidence_topic,
)

__all__ = [
    "KafkaEvidenceConsumer",
    "KafkaEvidencePublisher",
    "ensure_evidence_topic",
]
