# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic Evidence description unit tests (PR 35-1 Part 1).

The description is pure API presentation derived from normalized Evidence
state; these tests pin the Fake World DNS distinctions and the safe
fallback contract without touching the database or an LLM.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from agentic_threat_investigator.api.evidence_description import (
    evidence_description,
)
from agentic_threat_investigator.api.mappers import to_evidence_response
from agentic_threat_investigator.app.query.evidence import EvidenceReadItem
from agentic_threat_investigator.domain.evidence import (
    Evidence,
    EvidenceObservation,
    EvidenceType,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)

_WORLD_PATH = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "agentic_threat_investigator"
    / "infrastructure"
    / "fake_runtime"
    / "data"
    / "v1"
    / "world.json"
)


def _read_item(
    evidence_type: EvidenceType,
    facts: dict[str, Any],
    *,
    source: str = "urn:ati:source:google_public_dns",
    raw_payload: dict[str, Any] | None = None,
) -> EvidenceReadItem:
    """Build one exact admitted observation read item for presentation tests."""
    observation_id = uuid4()
    observation = EvidenceObservation(
        id=observation_id,
        evidence_id=uuid4(),
        version=1,
        retrieved_at=datetime(2026, 5, 1, tzinfo=UTC),
        facts=facts,
        raw_payload=raw_payload,
    )
    return EvidenceReadItem(
        observation=observation,
        evidence=Evidence(
            id=observation.evidence_id,
            type=evidence_type,
            source=source,
            source_record_id="presenter-world",
        ),
        entities=(),
        admission=InvestigationEvidence(
            investigation_id=uuid4(),
            evidence_observation_id=observation_id,
            inclusion_reason=InvestigationEvidenceReason.INITIAL,
            added_at=datetime(2026, 5, 1, tzinfo=UTC),
            added_by=InvestigationEvidenceActor.SYSTEM,
        ),
    )


def _update_package_facts() -> dict[str, dict[str, Any]]:
    """Return the Fake World ``update-package.test`` facts by evidence type."""
    world = json.loads(_WORLD_PATH.read_text())
    facts_by_type: dict[str, dict[str, Any]] = {}
    for provider_result in world["provider_results"]:
        if provider_result["entity_value"] != "update-package.test":
            continue
        for observation in provider_result.get("observations", []):
            facts_by_type[observation["evidence_type"]] = observation["facts"]
    return facts_by_type


def test_e01_dns_a_chain_description() -> None:
    """E01: the A/CNAME chain names the query and each address hop."""
    world = json.loads(_WORLD_PATH.read_text())
    dns_facts = [
        observation["facts"]
        for provider_result in world["provider_results"]
        if provider_result["entity_value"] == "update-package.test"
        for observation in provider_result.get("observations", [])
        if observation["evidence_type"] == EvidenceType.DNS.value
        and observation["facts"].get("query_type") == "A"
    ]
    assert dns_facts
    description = evidence_description(_read_item(EvidenceType.DNS, dns_facts[0]))
    assert description.startswith("A: update-package.test")
    assert "assets-edge.test" in description
    assert "203.0.113.81" in description


def test_e02_dns_mx_description() -> None:
    """E02: MX names the exchange and preference, never transport flags."""
    world = json.loads(_WORLD_PATH.read_text())
    facts = [
        observation["facts"]
        for provider_result in world["provider_results"]
        if provider_result["entity_value"] == "update-package.test"
        for observation in provider_result.get("observations", [])
        if observation["facts"].get("query_type") == "MX"
    ][0]
    description = evidence_description(_read_item(EvidenceType.DNS, facts))
    assert description == "MX: mail-01.test (priority 10)"


def test_e03_dns_ns_description() -> None:
    """E03: NS names the nameserver host."""
    world = json.loads(_WORLD_PATH.read_text())
    facts = [
        observation["facts"]
        for provider_result in world["provider_results"]
        if provider_result["entity_value"] == "update-package.test"
        for observation in provider_result.get("observations", [])
        if observation["facts"].get("query_type") == "NS"
    ][0]
    description = evidence_description(_read_item(EvidenceType.DNS, facts))
    assert description == "NS: ns-host.test"


def test_e04_dns_txt_description() -> None:
    """E04: TXT carries the bounded readable value."""
    world = json.loads(_WORLD_PATH.read_text())
    facts = [
        observation["facts"]
        for provider_result in world["provider_results"]
        if provider_result["entity_value"] == "update-package.test"
        for observation in provider_result.get("observations", [])
        if observation["facts"].get("query_type") == "TXT"
    ][0]
    description = evidence_description(_read_item(EvidenceType.DNS, facts))
    assert description == "TXT: trusted marketing partner newsletter"


def test_e04b_dns_txt_is_bounded() -> None:
    """E04b: an oversized TXT value never exceeds the public bound."""
    facts = {
        "query_name": "example.test",
        "query_type": "TXT",
        "status": 0,
        "flags": {"rd": True, "ra": True},
        "answers": [
            {"name": "example.test", "record_type": "TXT", "value": "x" * 5000}
        ],
    }
    description = evidence_description(_read_item(EvidenceType.DNS, facts))
    assert len(description) <= 240


def test_e05_threat_intelligence_description() -> None:
    """E05: threat intelligence leads with the IOC and its malware context."""
    facts = _update_package_facts()[EvidenceType.THREAT_INTELLIGENCE.value]
    description = evidence_description(
        _read_item(
            EvidenceType.THREAT_INTELLIGENCE,
            facts,
            source="urn:ati:source:threatfox",
        )
    )
    assert description.startswith("Threat intelligence: domain update-package.test")
    assert "BadLoader v2" in description
    assert "confidence 90" in description


def test_e06_registration_description() -> None:
    """E06: registration names the object class, handle, and registrar."""
    facts = _update_package_facts()[EvidenceType.REGISTRATION.value]
    description = evidence_description(
        _read_item(
            EvidenceType.REGISTRATION,
            facts,
            source="urn:ati:source:rdap",
        )
    )
    assert description == (
        "Registration: domain D-UPDATE-PACKAGE (registrar Synthetic Registrar)"
    )


def test_e07_unknown_type_fallback_is_safe_and_bounded() -> None:
    """E07: an unhandled type yields a type-oriented, non-raw description."""
    description = evidence_description(
        _read_item(EvidenceType.VULNERABILITY, {"first_key": {"nested": "raw"}})
    )
    assert description == "Vulnerability observation"
    assert "first_key" not in description


def test_e08_mapper_maps_description_and_omits_raw_payload() -> None:
    """E08: the public DTO carries the description and never the raw payload."""
    read_item = _read_item(
        EvidenceType.DNS,
        {
            "query_name": "example.test",
            "query_type": "A",
            "answers": [{"record_type": "A", "value": "203.0.113.9"}],
        },
        raw_payload={"http_response": {"body": "secret"}},
    )
    response = to_evidence_response(read_item)
    assert response.description == "A: example.test -> 203.0.113.9"
    payload = json.loads(response.model_dump_json())
    assert payload["description"] == "A: example.test -> 203.0.113.9"
    assert "raw_payload" not in payload
    assert payload["facts"] == json.loads(json.dumps(read_item.observation.facts))
