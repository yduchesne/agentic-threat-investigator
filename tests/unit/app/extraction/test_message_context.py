# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for consumer-side extraction input from durable messages (PR 28E).

Covers the E28E-X matrix: reconstruction of the exact ConvertedEvidence
from a real PR 28C ThreatFox message, canonical IOC invocation derivation
from durable normalized facts, fail-closed malformed/unsupported handling,
reuse of the existing ThreatFox extractor, and the absence of any
subject/log-position wire fields.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    converted_evidence_from_message,
)
from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.extraction.message_context import (
    MalformedMessageExtractionError,
    UnsupportedMessageExtractionError,
    extraction_view_from_message,
)
from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionView,
)
from agentic_threat_investigator.app.persistence.repositories import (
    PreparedEvidenceRecord,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.relationships import RelationshipType
from tests.support.evidence_batch_fixtures import (
    build_threatfox_fact,
    threatfox_message,
)

pytestmark = pytest.mark.unit

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def _view_for(message: EvidenceMessage) -> EvidenceExtractionView:
    """Build the extraction view of one message through production code."""
    converted = converted_evidence_from_message(message)
    return extraction_view_from_message(message, converted)


def test_x01_reconstructs_exact_converted_evidence() -> None:
    """A valid ThreatFox message reconstructs the exact ConvertedEvidence."""
    message, converted = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id="rec-1",
    )
    reconstructed = converted_evidence_from_message(message)
    assert reconstructed == converted
    view = extraction_view_from_message(message, reconstructed)
    assert view.evidence == converted.evidence
    assert view.observation == converted.observation
    assert view.observation.facts["matches"][0]["ioc"] == "malicious-domain.test"


def test_x02_ip_ioc_yields_canonical_ip_invocation() -> None:
    """An ip:port IOC derives the canonical IP invocation context."""
    message, _ = threatfox_message(
        ioc="203.0.113.42:443",
        ioc_type="ip:port",
        source_record_id="rec-ip",
    )
    view = _view_for(message)
    assert view.invocation_entity.type is EntityType.IP_ADDRESS
    assert view.invocation_entity.value == "203.0.113.42"


def test_x02b_bare_ip_ioc_yields_canonical_ip_invocation() -> None:
    """A bare IPv4 and a bracketed IPv6 host stay canonical."""
    message, _ = threatfox_message(
        ioc="2001:db8::1",
        ioc_type="ip:port",
        source_record_id="rec-v6",
    )
    view = _view_for(message)
    assert view.invocation_entity.type is EntityType.IP_ADDRESS
    assert view.invocation_entity.value == "2001:db8::1"
    message, _ = threatfox_message(
        ioc="[2001:db8::1]:8443",
        ioc_type="ip:port",
        source_record_id="rec-v6p",
    )
    view = _view_for(message)
    assert view.invocation_entity.value == "2001:db8::1"


def test_x03_domain_ioc_yields_canonical_domain_invocation() -> None:
    """A domain IOC derives the canonical domain invocation context."""
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id="rec-dom",
    )
    view = _view_for(message)
    assert view.invocation_entity.type is EntityType.DOMAIN
    assert view.invocation_entity.value == "malicious-domain.test"


def test_x04_missing_matches_fails_closed() -> None:
    """A ThreatFox message without matches is a typed malformed error."""
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id="rec-x4",
        facts={},
    )
    with pytest.raises(MalformedMessageExtractionError):
        _view_for(message)


def test_x04b_empty_matches_fails_closed() -> None:
    """An empty matches array is a typed malformed error, never empty graph."""
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id="rec-x4b",
        facts={"matches": []},
    )
    with pytest.raises(MalformedMessageExtractionError):
        _view_for(message)


def test_x05_inconsistent_ioc_across_matches_fails_closed() -> None:
    """Matches that disagree on the IOC identity fail closed."""
    matches = [
        build_threatfox_fact(ioc="malicious-domain.test", ioc_type="domain"),
        build_threatfox_fact(ioc="second-domain.test", ioc_type="domain"),
    ]
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id="rec-x5",
        facts={"matches": matches},
    )
    with pytest.raises(MalformedMessageExtractionError):
        _view_for(message)


def test_x06_malformed_ioc_fails_closed() -> None:
    """Malformed IP/domain IOCs are typed malformed errors."""
    invalid = (
        ("999.1.1.1:443", "ip:port"),
        ("2001:db8::1", "domain"),
        ("not an ip at all", "ip:port"),
    )
    for index, (ioc, ioc_type) in enumerate(invalid):
        message, _ = threatfox_message(
            ioc=ioc,
            ioc_type=ioc_type,
            source_record_id=f"rec-x6-{index}",
        )
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)


def test_x06b_noncanonical_domain_ioc_fails_closed() -> None:
    """A durable domain IOC that is not canonical fails closed (plan 8.3)."""
    message, _ = threatfox_message(
        ioc="Mixed-Case-Domain.test",
        ioc_type="domain",
        source_record_id="rec-x6b",
    )
    with pytest.raises(MalformedMessageExtractionError):
        _view_for(message)


def test_x06c_ambiguous_ip_port_spellings_fail_closed() -> None:
    """Ambiguous/invalid ip:port spellings never silently canonicalize."""
    invalid = (
        "203.0.113.42:443:extra",  # multi-colon; not a bare IPv6
        "[2001:db8::1]",  # bracketed without a port
        "[not-an-ip]:443",
        "203.0.113.42:0",  # invalid port
        "203.0.113.42:65536",  # invalid port
        "203.0.113.42:",  # empty port
    )
    for index, ioc in enumerate(invalid):
        message, _ = threatfox_message(
            ioc=ioc,
            ioc_type="ip:port",
            source_record_id=f"rec-x6c-{index}",
        )
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)


def test_x07_unsupported_source_fails_closed() -> None:
    """A non-ThreatFox message has no durable extraction adapter (typed)."""
    from uuid import uuid4

    from agentic_threat_investigator.app.evidence_message import (
        evidence_message_id,
        evidence_observation_candidate_id,
    )
    from agentic_threat_investigator.domain.datasource import DatasourceId
    from agentic_threat_investigator.domain.evidence import (
        evidence_id_for_source_record,
    )

    # A fully valid PR 28C message under the STIX 2.1 semantic format and
    # the URLhaus source: deterministic identities recompute exactly.
    source_record_id = "unsupported-record-1"
    evidence_id = evidence_id_for_source_record(
        SemanticFormatId.STIX_21, SourceId.URLHAUS, source_record_id
    )
    execution_id = uuid4()
    message_id = evidence_message_id(execution_id, 0, evidence_id)
    message = EvidenceMessage(
        schema_version=1,
        message_id=message_id,
        observation_candidate_id=evidence_observation_candidate_id(message_id),
        datasource_execution_id=execution_id,
        datasource_id=DatasourceId("urlhaus-live"),
        source_id=SourceId.URLHAUS,
        semantic_format=SemanticFormatId.STIX_21,
        sequence=0,
        evidence_id=evidence_id,
        evidence_type=EvidenceType.THREAT_INTELLIGENCE,
        source_record_id=source_record_id,
        retrieved_at=_FIXED_TS,
        observed_at=None,
        source_url="https://urlhaus.abuse.ch/",
        facts={"matches": [build_threatfox_fact(ioc="x", ioc_type="url")]},
        raw_payload=None,
    )
    with pytest.raises(UnsupportedMessageExtractionError):
        _view_for(message)


def test_x07b_url_ioc_fails_closed_as_unsupported() -> None:
    """A ThreatFox URL IOC has no invocation adapter (extractor subject gap)."""
    message, _ = threatfox_message(
        ioc="https://example.test/path",
        ioc_type="url",
        source_record_id="rec-x7b",
    )
    with pytest.raises(UnsupportedMessageExtractionError):
        _view_for(message)


def test_x08_existing_threatfox_extractor_is_reused() -> None:
    """The extraction dispatcher processes the reconstructed view directly."""
    message, _ = threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id="rec-x8",
    )
    view = _view_for(message)
    result = extract(view)
    assert len(result.entities) == 1
    assert result.entities[0].type is EntityType.MALWARE
    assert result.entities[0].value == "win.asyncrat"
    assert len(result.relationships) == 1
    assertion = result.relationships[0]
    assert assertion.type is RelationshipType.ASSOCIATED_WITH
    assert assertion.source.type is EntityType.DOMAIN
    assert assertion.source.value == "malicious-domain.test"
    assert assertion.target.value == "win.asyncrat"


def test_x09_no_log_position_enters_prepared_persistence() -> None:
    """PreparedEvidenceRecord carries no transport position field."""
    fields = PreparedEvidenceRecord.__dataclass_fields__
    assert "position" not in fields
    assert "message_id" in fields
    assert "observation_candidate_id" in fields


def test_x10_no_subject_wire_field_exists() -> None:
    """EvidenceMessage never exposes a subject/invocation wire field."""
    assert "subject" not in EvidenceMessage.model_fields
    assert "invocation_entity" not in EvidenceMessage.model_fields
    assert "investigation_id" not in EvidenceMessage.model_fields
