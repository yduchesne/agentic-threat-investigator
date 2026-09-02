# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Golden tests for stable URN vocabulary.

These tests pin URN values as contract: they are persisted in the database
and exchanged through the API and must never drift silently.
"""

from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import StopReason
from agentic_threat_investigator.domain.relationships import RelationshipType


def test_source_identifier_urns_are_stable() -> None:
    """Source URNs match the confirmed v0.1 source set."""

    assert {item.value for item in SourceId} == {
        "urn:ati:source:ipinfo_lite",
        "urn:ati:source:rdap",
        "urn:ati:source:google_public_dns",
        "urn:ati:source:dbip_city_lite",
        "urn:ati:source:abuseipdb",
        "urn:ati:source:threatfox",
        "urn:ati:source:urlhaus",
        "urn:ati:source:mitre_attack",
        "urn:ati:source:cisa_kev",
    }


def test_evidence_type_urns_are_stable() -> None:
    """Evidence URNs match the confirmed evidence types."""

    assert {item.value for item in EvidenceType} == {
        "urn:ati:evidence:dns",
        "urn:ati:evidence:registration",
        "urn:ati:evidence:network",
        "urn:ati:evidence:geolocation",
        "urn:ati:evidence:reputation",
        "urn:ati:evidence:threat_intelligence",
        "urn:ati:evidence:vulnerability",
        "urn:ati:evidence:threat_research",
    }


def test_relationship_type_urns_are_stable() -> None:
    """Relationship URNs match the confirmed relationship types."""

    assert {item.value for item in RelationshipType} == {
        "urn:ati:relationship:dns:resolves_to",
        "urn:ati:relationship:dns:cname_of",
        "urn:ati:relationship:dns:uses_name_server",
        "urn:ati:relationship:dns:uses_mail_server",
        "urn:ati:relationship:network:belongs_to",
        "urn:ati:relationship:routing:announced_by",
        "urn:ati:relationship:registration:registered_to",
        "urn:ati:relationship:organization:operated_by",
        "urn:ati:relationship:threat:associated_with",
        "urn:ati:relationship:attack:uses_technique",
        "urn:ati:relationship:vulnerability:exploits",
    }


def test_stop_reason_values_are_stable() -> None:
    """Stop reasons match the confirmed stopping vocabulary."""

    assert {item.value for item in StopReason} == {
        "sufficient_evidence",
        "no_eligible_pivots",
        "depth_limit_reached",
        "entity_budget_exhausted",
        "provider_budget_exhausted",
        "replan_limit_reached",
        "fatal_error",
    }
