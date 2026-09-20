# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared synthetic PR 28C/28E message and batch fixtures.

Every payload is ATI-authored documentation-safe test data (RFC 5737
addresses, RFC 2606 ``.test`` domains, synthetic identifiers). Builders
produce real PR 28C :class:`EvidenceMessage` values through the public
builder so identity recomputation, codec, and validation are exercised by
the same production code the consumer uses.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_log import (
    EvidenceBatch,
    EvidenceConsumerId,
    EvidenceLogPosition,
    EvidenceLogRecord,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    evidence_message_from_converted,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)

FIXED_RETRIEVED_AT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
"""Deterministic retrieval time shared by every synthetic message."""

_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

_THREATFOX_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)
"""The canonical synthetic ThreatFox definition (mirrors PR 28C fixtures)."""


def threatfox_semantic_context(
    *,
    retrieved_at: datetime = FIXED_RETRIEVED_AT,
) -> SemanticSourceContext:
    """Build one ThreatFox semantic provenance context."""
    return SemanticSourceContext(
        datasource_id=_THREATFOX_DEFINITION.datasource_id,
        source_id=_THREATFOX_DEFINITION.source_id,
        semantic_format=_THREATFOX_DEFINITION.semantic_format,
        retrieved_at=retrieved_at,
        source_reference=_ENDPOINT,
    )


def build_threatfox_fact(
    *,
    ioc: str,
    ioc_type: str,
    malware: str = "win.asyncrat",
    malware_printable: str | None = "AsyncRAT",
    threatfox_id: str | None = None,
) -> dict[str, Any]:
    """Build one durable normalized ThreatFox match fact (documentation-safe).

    Mirrors the exact handoff keys of the production converter so the
    consumer-side message reconstruction sees byte-identical durable
    content.
    """
    return {
        "threatfox_id": threatfox_id or "864201",
        "ioc": ioc,
        "ioc_type": ioc_type,
        "threat_type": "botnet_cc",
        "threat_type_description": "Botnet Command&control (C&C)",
        "malware": malware,
        "malware_printable": malware_printable,
        "confidence_level": 100,
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": None,
        "reference": None,
        "tags": None,
    }


def threatfox_message(
    *,
    ioc: str,
    ioc_type: str,
    source_record_id: str,
    execution_id: UUID | None = None,
    sequence: int = 0,
    retrieved_at: datetime = FIXED_RETRIEVED_AT,
    facts: dict[str, Any] | None = None,
    observed_at: datetime | None = None,
) -> tuple[EvidenceMessage, ConvertedEvidence]:
    """Build one valid ThreatFox V1 message plus its exact ConvertedEvidence.

    The message goes through the public PR 28C builder, so every
    deterministic identity (Evidence, message, candidate) is recomputed and
    validated by production code.
    """
    context = threatfox_semantic_context(retrieved_at=retrieved_at)
    evidence = Evidence(
        id=evidence_id_for_source_record(
            SemanticFormatId.THREATFOX, SourceId.THREATFOX, source_record_id
        ),
        type=EvidenceType.THREAT_INTELLIGENCE,
        source=SourceId.THREATFOX.value,
        source_record_id=source_record_id,
    )
    converted = ConvertedEvidence(
        evidence=evidence,
        observation=EvidenceObservationCandidate(
            evidence_id=evidence.id,
            source_url=_ENDPOINT,
            observed_at=observed_at,
            retrieved_at=retrieved_at,
            facts=(
                facts
                if facts is not None
                else {"matches": [build_threatfox_fact(ioc=ioc, ioc_type=ioc_type)]}
            ),
            raw_payload=None,
        ),
    )
    message = evidence_message_from_converted(
        converted,
        datasource_execution_id=execution_id or uuid4(),
        semantic_source=context,
        sequence=sequence,
    )
    return message, converted


def message_batch(
    messages: tuple[EvidenceMessage, ...],
    *,
    consumer_id: str = "pr-28e-test-consumer",
) -> EvidenceBatch:
    """Wrap ordered messages in a descriptive EvidenceBatch with fake positions.

    Positions are per-test identifiers only; the PR 28D contract forbids
    using them as persistence identity, which the persistence path never
    receives.
    """
    return EvidenceBatch(
        consumer_id=EvidenceConsumerId(consumer_id),
        records=tuple(
            EvidenceLogRecord(
                position=EvidenceLogPosition(stream=0, offset=index),
                message=message,
            )
            for index, message in enumerate(messages)
        ),
    )
