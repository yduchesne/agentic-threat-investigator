# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Composition of production Kafka Evidence adapters from configuration (PR 28G).

These functions wire the PR 28G infrastructure adapters from ATI's typed
:class:`EvidenceLogKafkaSettings` (and ATI's :class:`SecretsResolver` for
SASL credentials) so a future runtime seam can instantiate them cleanly. PR
28G deliberately does **not** invent the missing production orchestrator
(scheduler/worker supervisor): it only provides the composition boundary;
wiring a datasource execution runner remains PR 28H/transitional scope.
Resolved credentials are passed to the client and never logged, persisted,
or embedded in URLs.
"""

from __future__ import annotations

import ssl

from agentic_threat_investigator.app.evidence_log import EvidenceConsumerId
from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config.settings import (
    EvidenceLogKafkaSettings,
    KafkaSecurityProtocol,
)
from agentic_threat_investigator.infrastructure.kafka.evidence_log import (
    KafkaEvidenceConsumer,
    KafkaEvidencePublisher,
    build_kafka_consumer,
    build_kafka_publisher,
)


def _ssl_context_for(settings: EvidenceLogKafkaSettings) -> ssl.SSLContext | None:
    """Return a default TLS context when the protocol uses TLS, else ``None``.

    Real certificate-authority configuration remains an operator/TLS concern
    outside PR 28G; the default SSL context validates against the system
    trust store.
    """
    if settings.security_protocol in (
        KafkaSecurityProtocol.SSL,
        KafkaSecurityProtocol.SASL_SSL,
    ):
        return ssl.create_default_context()
    return None


def _sasl_credentials(
    settings: EvidenceLogKafkaSettings, secrets: SecretsResolver | None
) -> tuple[str | None, str | None]:
    """Resolve SASL username/password credential values, if configured."""
    if settings.security_protocol not in (
        KafkaSecurityProtocol.SASL_PLAINTEXT,
        KafkaSecurityProtocol.SASL_SSL,
    ):
        return None, None
    if secrets is None:
        raise ValueError("a SecretsResolver is required to compose a SASL Kafka client")
    username = (
        secrets.require(settings.sasl_username_secret)
        if settings.sasl_username_secret is not None
        else None
    )
    password = (
        secrets.require(settings.sasl_password_secret)
        if settings.sasl_password_secret is not None
        else None
    )
    return username, password


def compose_kafka_publisher(
    settings: EvidenceLogKafkaSettings,
    *,
    secrets: SecretsResolver | None = None,
) -> KafkaEvidencePublisher:
    """Compose a production KafkaEvidencePublisher from typed configuration."""
    username, password = _sasl_credentials(settings, secrets)
    return build_kafka_publisher(
        bootstrap_servers=settings.bootstrap_servers,
        topic=settings.topic,
        client_id=settings.client_id,
        security_protocol=settings.security_protocol.value,
        ssl_context=_ssl_context_for(settings),
        sasl_mechanism=settings.sasl_mechanism,
        sasl_plain_username=username,
        sasl_plain_password=password,
    )


def compose_kafka_consumer(
    settings: EvidenceLogKafkaSettings,
    *,
    consumer_id: EvidenceConsumerId,
    secrets: SecretsResolver | None = None,
) -> KafkaEvidenceConsumer:
    """Compose a production KafkaEvidenceConsumer from typed configuration."""
    username, password = _sasl_credentials(settings, secrets)
    return build_kafka_consumer(
        bootstrap_servers=settings.bootstrap_servers,
        topic=settings.topic,
        consumer_id=consumer_id,
        client_id=settings.client_id,
        poll_timeout_ms=settings.poll_timeout_ms,
        security_protocol=settings.security_protocol.value,
        auto_offset_reset=settings.auto_offset_reset,
        ssl_context=_ssl_context_for(settings),
        sasl_mechanism=settings.sasl_mechanism,
        sasl_plain_username=username,
        sasl_plain_password=password,
    )
