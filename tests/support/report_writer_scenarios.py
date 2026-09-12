# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical Report Writer scenario fixtures (PR 23B).

Each fixture name maps to a deterministic :class:`ReportWriterFixture` that
the materializer persists and the canonical output builder consumes. The
scenario JSON files under ``evals/scenarios/report_writer/`` reference these
fixtures by name; this map is the single source of truth for fixture content.
"""

from __future__ import annotations

from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType
from agentic_threat_investigator.evaluation.analyst.models import (
    FixtureEntity,
    FixtureEvidence,
    FixtureObservation,
    FixtureRelationship,
)

from .report_writer_fixtures import (
    FixtureFinding,
    FixtureResearchCitation,
    FixtureResearchClaim,
    FixtureResearchResult,
    ReportWriterFixture,
)

_TARGET_DOMAIN = FixtureEntity(
    label="target_domain", type=EntityType.DOMAIN, value="malicious.example.com"
)
_MALWARE_FAMILY = FixtureEntity(
    label="malware_family", type=EntityType.MALWARE, value="unit_malware"
)
_TARGET_IP = FixtureEntity(
    label="target_ip", type=EntityType.IP_ADDRESS, value="203.0.113.42"
)
_INFRA_PREFIX = FixtureEntity(
    label="infra_prefix", type=EntityType.NETWORK_PREFIX, value="198.51.100.0/24"
)


def _malicious_fixture(*, research: bool) -> ReportWriterFixture:
    """The canonical clearly-malicious fixture with optional research context."""
    relationships: tuple[FixtureRelationship, ...] = ()
    observations: tuple[FixtureObservation, ...] = ()
    research_results: tuple[FixtureResearchResult, ...] = ()
    if research:
        relationships = (
            FixtureRelationship(
                label="associated_with",
                type=RelationshipType.ASSOCIATED_WITH,
                source="target_domain",
                target="malware_family",
            ),
        )
        observations = (
            FixtureObservation(
                label="malware_obs",
                relationship="associated_with",
                evidence="reputation_hit",
                source="urn:ati:source:abuseipdb",
                confidence=0.9,
            ),
        )
        research_results = (
            FixtureResearchResult(
                subject_label="malware_family",
                query="malware family infrastructure",
                claims=(
                    FixtureResearchClaim(
                        label="malicious_context",
                        text=(
                            "The malware family is associated with credential "
                            "theft infrastructure."
                        ),
                        citation_labels=("malware_ctx_citation",),
                    ),
                ),
                citations=(
                    FixtureResearchCitation(
                        label="malware_ctx_citation",
                        title="Credential theft infrastructure report",
                        source_id="urn:ati:source:mitre_attack",
                        source_record_id="report--credential-theft",
                        text="The family operates credential theft infrastructure.",
                        source_url="https://attack.mitre.org/techniques/example",
                    ),
                ),
            ),
        )
    return ReportWriterFixture(
        objective="Assess the malicious indicator.",
        root_entity="target_domain",
        entities=(_TARGET_DOMAIN, _MALWARE_FAMILY),
        evidence=(
            FixtureEvidence(
                label="reputation_hit",
                type=EvidenceType.REPUTATION,
                subject="target_domain",
                source="urn:ati:source:abuseipdb",
                facts={"score": 90, "reports": 5},
            ),
        ),
        relationships=relationships,
        observations=observations,
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        summary="The indicator is malicious based on reputation evidence.",
        findings=(
            FixtureFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="Reputation evidence indicates malicious activity.",
                confidence=AssessmentConfidence.HIGH,
                evidence_labels=("reputation_hit",),
                observation_labels=("malware_obs",) if research else (),
            ),
        ),
        limitations=("reputation evidence is third-party and may lag",),
        recommended_next_steps=("monitor the indicator for 30 days",),
        research_results=research_results,
    )


REPORT_WRITER_FIXTURES: dict[str, ReportWriterFixture] = {
    "report-malicious": _malicious_fixture(research=True),
    "report-no-research": _malicious_fixture(research=False),
    "report-inconclusive": ReportWriterFixture(
        objective="Assess the root indicator.",
        root_entity="target_ip",
        entities=(_TARGET_IP,),
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="No evidence was available for analysis.",
        limitations=("no evidence was available",),
        unresolved_questions=("why no reputation data was retrieved",),
    ),
    "report-conflicting": ReportWriterFixture(
        objective="Assess the root indicator.",
        root_entity="target_ip",
        entities=(_TARGET_IP,),
        evidence=(
            FixtureEvidence(
                label="reputation_high",
                type=EvidenceType.REPUTATION,
                subject="target_ip",
                source="urn:ati:source:abuseipdb",
                facts={"score": 90},
            ),
            FixtureEvidence(
                label="reputation_low",
                type=EvidenceType.REPUTATION,
                subject="target_ip",
                source="urn:ati:source:threatfox",
                facts={"score": 5},
            ),
        ),
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="Reputation evidence conflicts.",
        findings=(
            FixtureFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="High reputation score indicates abuse.",
                confidence=AssessmentConfidence.MEDIUM,
                evidence_labels=("reputation_high",),
            ),
            FixtureFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.CONTRADICTING,
                statement="Low reputation score contradicts abuse.",
                confidence=AssessmentConfidence.LOW,
                evidence_labels=("reputation_low",),
            ),
        ),
        limitations=("one reputation source conflicts with the others",),
    ),
    "report-research-context": ReportWriterFixture(
        objective="Assess the suspicious infrastructure.",
        root_entity="target_ip",
        entities=(_TARGET_IP, _INFRA_PREFIX),
        evidence=(
            FixtureEvidence(
                label="dns_obs",
                type=EvidenceType.DNS,
                subject="target_ip",
                source="urn:ati:source:google_public_dns",
                facts={"resolves_to": "198.51.100.0/24"},
            ),
        ),
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="The indicator shares infrastructure with low-reputation hosts.",
        findings=(
            FixtureFinding(
                category=FindingCategory.NETWORK,
                disposition=FindingDisposition.SUPPORTING,
                statement="The indicator shares a network prefix with low-reputation hosts.",
                confidence=AssessmentConfidence.MEDIUM,
                evidence_labels=("dns_obs",),
            ),
        ),
        research_results=(
            FixtureResearchResult(
                subject_label="infra_prefix",
                query="network prefix reputation context",
                claims=(
                    FixtureResearchClaim(
                        label="contextual_claim",
                        text=("The prefix hosts other low-reputation infrastructure."),
                        citation_labels=("context_citation",),
                    ),
                ),
                citations=(
                    FixtureResearchCitation(
                        label="context_citation",
                        title="Prefix reputation notes",
                        source_id="urn:ati:source:mitre_attack",
                        source_record_id="report--prefix-reputation",
                        text="The prefix hosts low-reputation infrastructure.",
                    ),
                ),
            ),
        ),
    ),
    "report-unsupported-ref": _malicious_fixture(research=False),
    "report-verdict-override": _malicious_fixture(research=False),
    "report-stale-race": _malicious_fixture(research=False),
}


def report_writer_fixture(name: str) -> ReportWriterFixture:
    """Return the canonical fixture for one scenario name."""
    try:
        return REPORT_WRITER_FIXTURES[name]
    except KeyError as error:
        raise KeyError(f"unknown report writer fixture: {name}") from error
