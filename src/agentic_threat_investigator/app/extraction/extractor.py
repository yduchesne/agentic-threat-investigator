# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic extraction dispatcher.

Dispatches one normalized, persisted :class:`Evidence` observation to the
extractor registered for its ``(source, evidence type)`` combination. The
dispatcher is pure and synchronous: it performs no I/O, no persistence, no
provider calls, and no database access.

Dispatch policy:

- a registered combination is extracted by its source-specific extractor;
- a known evidence-producing source with an unregistered evidence type is a
  contract failure and raises :class:`EvidenceExtractionError`;
- an unknown or unregistered source deliberately yields an empty result so
  unregistered future sources can never fabricate graph structure silently.
"""

from collections.abc import Callable

from agentic_threat_investigator.app.extraction.dns import extract_dns
from agentic_threat_investigator.app.extraction.ipinfo import extract_ipinfo
from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionError,
    ExtractionErrorReason,
    ExtractionResult,
)
from agentic_threat_investigator.app.extraction.rdap import extract_rdap
from agentic_threat_investigator.app.extraction.threatfox import extract_threatfox
from agentic_threat_investigator.app.extraction.urlhaus import extract_urlhaus
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId

Extractor = Callable[[Evidence], ExtractionResult]
"""A pure, synchronous per-source extraction function."""


def extract_empty(_evidence: Evidence) -> ExtractionResult:
    """Return an empty result for fact-only contextual evidence.

    DB-IP City Lite geolocation and AbuseIPDB reputation remain contextual or
    reputational source facts: geolocation is approximate context rather than
    maliciousness evidence, and reputation scores never become graph
    structure, entities, or relationship confidence.
    """
    return ExtractionResult()


_EVIDENCE_EXTRACTORS: dict[tuple[str, EvidenceType], Extractor] = {
    (SourceId.GOOGLE_PUBLIC_DNS.value, EvidenceType.DNS): extract_dns,
    (SourceId.THREATFOX.value, EvidenceType.THREAT_INTELLIGENCE): extract_threatfox,
    (SourceId.URLHAUS.value, EvidenceType.THREAT_INTELLIGENCE): extract_urlhaus,
    (SourceId.RDAP.value, EvidenceType.NETWORK): extract_rdap,
    (SourceId.RDAP.value, EvidenceType.REGISTRATION): extract_rdap,
    (SourceId.IPINFO_LITE.value, EvidenceType.NETWORK): extract_ipinfo,
    (SourceId.DBIP_CITY_LITE.value, EvidenceType.GEOLOCATION): extract_empty,
    (SourceId.ABUSEIPDB.value, EvidenceType.REPUTATION): extract_empty,
}

_EVIDENCE_SOURCES = frozenset(source for source, _ in _EVIDENCE_EXTRACTORS)


def extract(evidence: Evidence) -> ExtractionResult:
    """Extract deterministic entities and assertions from one Evidence.

    Unknown sources return an empty result by documented policy; a known
    source paired with an evidence type it never produces is a contract
    failure.
    """
    extractor = _EVIDENCE_EXTRACTORS.get((evidence.source, evidence.type))
    if extractor is not None:
        return extractor(evidence)
    if evidence.source in _EVIDENCE_SOURCES:
        raise EvidenceExtractionError(
            evidence.source,
            ExtractionErrorReason.UNSUPPORTED_EVIDENCE_TYPE,
            "the evidence type is impossible for the registered source",
            evidence_id=evidence.id,
        )
    return ExtractionResult()
