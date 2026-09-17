# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Normalized EvidenceExtractionView fixtures for deterministic extraction tests.

Every fixture starts from a PR 28B extraction view (stable Evidence +
observation candidate + canonical invocation Entity), never from raw HTTP
responses: extraction tests consume exactly the fact shapes the providers
promise. All values are synthetic documentation-safe test data (RFC 5737
addresses, RFC 2606 ``.test`` domains, and synthetic identifiers).

The canonical scenario is reused by PR 18C and PR 19+:

```text
malicious-domain.test
  --DNS RESOLVES_TO-->
203.0.113.42
  --ThreatFox ASSOCIATED_WITH-->
win.asyncrat (AsyncRAT)
```
"""

# The evidence-builder helpers in extraction test modules intentionally
# share the normalized LegacyEvidence construction shape (see the established
# provider fixture family); the duplication is test-only and accepted.

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from agentic_threat_investigator.app.extraction.models import EvidenceExtractionView
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId

CANONICAL_INVESTIGATION_ID = UUID("22222222-2222-4222-8222-222222222222")
"""Fixed synthetic investigation identity of the canonical scenario."""

CANONICAL_DNS_EVIDENCE_ID = UUID("33333333-3333-4333-8333-333333333333")
"""Fixed persisted LegacyEvidence ID of the canonical DNS observation."""

CANONICAL_THREATFOX_EVIDENCE_ID = UUID("44444444-4444-4444-8444-444444444444")
"""Fixed persisted LegacyEvidence ID of the canonical ThreatFox observation."""

CANONICAL_ASYNCRAT_DOMAIN = "malicious-domain.test"
"""Synthetic documentation-safe C2 domain of the canonical scenario."""

CANONICAL_ASYNCRAT_IP = "203.0.113.42"
"""Synthetic RFC 5737 documentation address of the canonical scenario."""

CANONICAL_ASYNCRAT_MALWARE = "win.asyncrat"
"""Official ThreatFox machine malware identifier for AsyncRAT."""

CANONICAL_ASYNCRAT_PRINTABLE = "AsyncRAT"
"""Official ThreatFox printable malware name for AsyncRAT."""

RETRIEVED_AT = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
"""Fixed timezone-aware retrieval timestamp for deterministic fixtures."""


# One explicit argument per fixture dimension is intentional for tests.
def extraction_view(
    *,
    evidence_id: UUID | None = None,
    evidence_type: EvidenceType,
    source: str,
    subject_type: EntityType,
    subject_value: str,
    facts: dict[str, Any],
    retrieved_at: datetime | None = None,
    source_record_id: str | None = None,
    observed_at: datetime | None = None,
) -> EvidenceExtractionView:
    """Build one normalized PR 28B extraction view for the given facts.

    ``evidence_id`` is the deterministic stable Evidence identity of the
    fixture; ``source_record_id`` defaults to a synthetic fixture identity.
    The invocation Entity is the fixture subject (ordinary observation-level
    provenance, never a restricted domain field).
    """
    identity = evidence_id if evidence_id is not None else uuid4()
    record_id = (
        source_record_id if source_record_id is not None else f"fixture:{identity}"
    )
    evidence = Evidence(
        id=identity,
        type=evidence_type,
        source=source,
        source_record_id=record_id,
    )
    candidate = EvidenceObservationCandidate(
        evidence_id=identity,
        observed_at=observed_at,
        retrieved_at=retrieved_at if retrieved_at is not None else RETRIEVED_AT,
        facts=facts,
    )
    return EvidenceExtractionView(
        evidence=evidence,
        observation=candidate,
        invocation_entity=Entity(type=subject_type, value=subject_value),
    )


def evidence(
    *,
    source: str,
    evidence_type: EvidenceType,
    subject_type: EntityType,
    subject_value: str,
    facts: dict[str, Any],
    evidence_id: UUID | None = None,
    investigation_id: UUID | None = None,
    retrieved_at: datetime | None = None,
) -> EvidenceExtractionView:
    """Build one normalized PR 28B extraction view (legacy argument shape).

    ``investigation_id`` is accepted for test-source compatibility but is
    deliberately ignored: a global extraction view never owns an
    Investigation (exact admission happens at persistence).
    """
    return extraction_view(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        source=source,
        subject_type=subject_type,
        subject_value=subject_value,
        facts=facts,
        retrieved_at=retrieved_at,
    )


def canonical_dns_evidence() -> EvidenceExtractionView:
    """Build the canonical A-record evidence: domain resolves to the scenario IP."""
    return evidence(
        source=SourceId.GOOGLE_PUBLIC_DNS.value,
        evidence_type=EvidenceType.DNS,
        subject_type=EntityType.DOMAIN,
        subject_value=CANONICAL_ASYNCRAT_DOMAIN,
        evidence_id=CANONICAL_DNS_EVIDENCE_ID,
        facts={
            "query_name": CANONICAL_ASYNCRAT_DOMAIN,
            "query_type": "A",
            "status": 0,
            "flags": {"rd": True, "ra": True},
            "answers": [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "A",
                    "ttl": 300,
                    "value": CANONICAL_ASYNCRAT_IP,
                }
            ],
        },
    )


def canonical_threatfox_evidence() -> EvidenceExtractionView:
    """Build the canonical ThreatFox evidence: the scenario IP is AsyncRAT C2."""
    return evidence(
        source=SourceId.THREATFOX.value,
        evidence_type=EvidenceType.THREAT_INTELLIGENCE,
        subject_type=EntityType.IP_ADDRESS,
        subject_value=CANONICAL_ASYNCRAT_IP,
        evidence_id=CANONICAL_THREATFOX_EVIDENCE_ID,
        facts={
            "matches": [
                {
                    "threatfox_id": "864201",
                    "ioc": CANONICAL_ASYNCRAT_IP,
                    "ioc_type": "ip:port",
                    "threat_type": "botnet_cc",
                    "threat_type_description": (
                        "Indicator that identifies a botnet command&control server (C&C)"
                    ),
                    "malware": CANONICAL_ASYNCRAT_MALWARE,
                    "malware_printable": CANONICAL_ASYNCRAT_PRINTABLE,
                    "confidence_level": 100,
                    "first_seen": "2026-01-14T12:00:00Z",
                    "last_seen": "2026-01-15T12:00:00Z",
                    "reference": None,
                    "tags": ["AsyncRAT"],
                }
            ]
        },
    )


def dns_evidence(
    answers: list[object],
    *,
    subject_value: str = CANONICAL_ASYNCRAT_DOMAIN,
    subject_type: EntityType = EntityType.DOMAIN,
    query_type: str = "A",
    query_name: str | None = None,
    facts_overrides: dict[str, object] | None = None,
    evidence_id: UUID | None = None,
) -> EvidenceExtractionView:
    """Build one normalized DNS extraction view with the given answers."""
    facts: dict[str, object] = {
        "query_name": query_name if query_name is not None else subject_value,
        "query_type": query_type,
        "status": 0,
        "flags": {},
        "answers": answers,
    }
    if facts_overrides:
        facts.update(facts_overrides)
    return evidence(
        source=SourceId.GOOGLE_PUBLIC_DNS.value,
        evidence_type=EvidenceType.DNS,
        subject_type=subject_type,
        subject_value=subject_value,
        facts=facts,
        evidence_id=evidence_id,
    )


def a_answer(
    name: str = CANONICAL_ASYNCRAT_DOMAIN, value: str = CANONICAL_ASYNCRAT_IP
) -> dict[str, object]:
    """Build one normalized A answer."""
    return {"name": name, "record_type": "A", "ttl": 300, "value": value}
