# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the extraction dispatcher and empty policy extractors."""

# The evidence-builder helpers in extraction test modules intentionally
# share the normalized Evidence construction shape (see the established
# provider fixture family); the duplication is test-only and accepted.
# pylint: disable=duplicate-code

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.extraction import (
    EvidenceExtractionError,
    ExtractionErrorReason,
    extract,
)
from agentic_threat_investigator.app.extraction.models import ExtractionResult
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId

RETRIEVED_AT = datetime(2026, 1, 15, tzinfo=UTC)


def dbip_geolocation_evidence() -> Evidence:
    """Build realistic DB-IP City Lite geolocation evidence."""
    return Evidence(
        id=uuid4(),
        investigation_id=uuid4(),
        type=EvidenceType.GEOLOCATION,
        subject=EntityRef(type=EntityType.IP_ADDRESS, value="203.0.113.42"),
        source=SourceId.DBIP_CITY_LITE.value,
        retrieved_at=RETRIEVED_AT,
        facts={
            "country_code": "US",
            "country": "United States",
            "region": "California",
            "city": "Mountain View",
            "latitude": 37.386,
            "longitude": -122.084,
            "precision": "city",
            "provider": "urn:ati:source:dbip_city_lite",
        },
        raw_payload=None,
    )


def abuseipdb_reputation_evidence() -> Evidence:
    """Build realistic AbuseIPDB reputation evidence."""
    return Evidence(
        id=uuid4(),
        investigation_id=uuid4(),
        type=EvidenceType.REPUTATION,
        subject=EntityRef(type=EntityType.IP_ADDRESS, value="203.0.113.42"),
        source=SourceId.ABUSEIPDB.value,
        retrieved_at=RETRIEVED_AT,
        facts={
            "ipAddress": "203.0.113.42",
            "isPublic": True,
            "abuseConfidenceScore": 85,
            "totalReports": 12,
            "lastReportedAt": "2026-01-14T00:00:00+00:00",
            "reports": [],
        },
        raw_payload=None,
    )


def test_dbip_geolocation_yields_empty_result() -> None:
    """Geolocation never leaks graph structure: an empty extraction result."""
    result = extract(dbip_geolocation_evidence())

    assert result == ExtractionResult()


def test_abuseipdb_reputation_yields_empty_result() -> None:
    """Reputation never leaks graph structure: an empty extraction result."""
    result = extract(abuseipdb_reputation_evidence())

    assert result == ExtractionResult()


def test_unknown_source_yields_empty_result() -> None:
    """Unregistered sources deliberately yield an empty result."""
    evidence = abuseipdb_reputation_evidence().model_copy(
        update={"source": "urn:ati:source:some_future_source"}
    )

    assert extract(evidence) == ExtractionResult()


def test_known_source_with_impossible_type_fails() -> None:
    """A known source paired with an impossible evidence type is a contract failure."""
    evidence = abuseipdb_reputation_evidence().model_copy(
        update={"type": EvidenceType.DNS}
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.UNSUPPORTED_EVIDENCE_TYPE
