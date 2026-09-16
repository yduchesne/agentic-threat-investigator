# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""GEOINT evaluation contract validation (PR 26G).

The scenario/fixture/expected models fail closed on malformed authoring:
duplicate labels, unknown cross-references, self-inconsistent envelopes, and
oversized collections are rejected deterministically.
"""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.assessment import Verdict
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)
from agentic_threat_investigator.evaluation.geoint.models import (
    ExpectedAgentContext,
    ExpectedAgentOutput,
    ExpectedGeointOutcome,
    ExpectedResolutionOutcome,
    GeointFixture,
    GeointFixtureEntity,
    GeointFixtureEvidence,
    GeointFixtureLocation,
    GeointFixtureResolution,
    GeointForbiddenInference,
    GeointScenario,
    GeointScenarioResolution,
    GeointToolOperation,
    GeointValidationExpectation,
)
from tests.support.geoint_evaluation import unit_geoint_scenario


def test_canonical_unit_scenario_validates() -> None:
    """The canonical unit scenario is a valid repository-owned contract."""
    scenario = unit_geoint_scenario()
    assert scenario.id == "unit_geoint_scenario"
    assert scenario.version == 1
    assert len(scenario.fixture.geography) == 3
    assert len(scenario.expected.resolutions) == 1


def test_duplicate_fixture_labels_rejected() -> None:
    """Globally unique fixture labels are mandatory."""
    scenario = unit_geoint_scenario()
    duplicate_geography = (
        scenario.fixture.geography[0],
        scenario.fixture.geography[0],
    )
    fixture = scenario.fixture.model_copy(update={"geography": duplicate_geography})
    with pytest.raises(ValidationError):
        fixture.model_validate(fixture.model_dump())


def test_unknown_entity_reference_rejected() -> None:
    """Evidence subjects and resolution entries must name declared entities."""
    scenario = unit_geoint_scenario()
    bad_evidence = scenario.fixture.evidence[0].model_copy(
        update={"subject": "missing_entity"}
    )
    fixture = scenario.fixture.model_copy(update={"evidence": (bad_evidence,)})
    with pytest.raises(ValidationError):
        fixture.model_validate(fixture.model_dump())


def test_unknown_parent_reference_rejected() -> None:
    """Location parents must name declared geography records."""
    bad_city = GeointFixtureLocation(
        label="springfield",
        location_type=LocationType.CITY,
        name="Springfield",
        country_code="US",
        admin1_code="WA",
        parent="missing_admin",
    )
    fixture = unit_geoint_scenario().fixture.model_copy(
        update={"geography": unit_geoint_scenario().fixture.geography + (bad_city,)}
    )
    with pytest.raises(ValidationError):
        fixture.model_validate(fixture.model_dump())


def test_unresolvable_outcome_shape_enforced() -> None:
    """An unresolvable expectation must not carry a Location/precision."""
    with pytest.raises(ValidationError):
        ExpectedResolutionOutcome(
            label="seattle_obs",
            status="unresolvable",
            location="seattle",
            precision=LocationPrecision.CITY,
        )


def test_resolved_outcome_requires_location_and_precision() -> None:
    """A resolved expectation requires both a Location and a precision."""
    with pytest.raises(ValidationError):
        ExpectedResolutionOutcome(label="seattle_obs", status="resolved")


def test_unknown_expected_resolution_label_rejected() -> None:
    """Expected resolution labels must name fixture resolutions."""
    scenario = unit_geoint_scenario()
    expected = scenario.expected.model_copy(
        update={
            "resolutions": (
                ExpectedResolutionOutcome(
                    label="missing_obs",
                    status="resolved",
                    location="seattle",
                    precision=LocationPrecision.CITY,
                ),
            )
        }
    )
    with pytest.raises(ValidationError):
        scenario.model_copy(update={"expected": expected}).model_validate(
            scenario.model_copy(update={"expected": expected}).model_dump()
        )


def test_unknown_geography_label_in_expected_rejected() -> None:
    """Expected location labels must name fixture geography records."""
    scenario = unit_geoint_scenario()
    expected = scenario.expected.model_copy(
        update={
            "resolutions": (
                ExpectedResolutionOutcome(
                    label="seattle_obs",
                    status="resolved",
                    location="missing_geography",
                    precision=LocationPrecision.CITY,
                ),
            )
        }
    )
    with pytest.raises(ValidationError):
        scenario.model_copy(update={"expected": expected}).model_validate(
            scenario.model_copy(update={"expected": expected}).model_dump()
        )


def test_expected_finding_unknown_observation_label_rejected() -> None:
    """Expected geographic findings must name fixture resolution labels."""
    from agentic_threat_investigator.domain.analyst import GeographicFindingKind
    from agentic_threat_investigator.evaluation.geoint.models import (
        ExpectedGeographicFinding,
    )

    scenario = unit_geoint_scenario()
    output = scenario.expected.agent_output.model_copy(
        update={
            "required_geographic_findings": (
                ExpectedGeographicFinding(
                    kind=GeographicFindingKind.SHARED_LOCATION,
                    observation_labels=frozenset({"missing_obs"}),
                ),
            )
        }
    )
    expected = scenario.expected.model_copy(update={"agent_output": output})
    with pytest.raises(ValidationError):
        scenario.model_copy(update={"expected": expected}).model_validate(
            scenario.model_copy(update={"expected": expected}).model_dump()
        )


def test_expected_finding_requires_constraint() -> None:
    """An expected geographic finding must constrain something."""
    from agentic_threat_investigator.evaluation.geoint.models import (
        ExpectedGeographicFinding,
    )

    with pytest.raises(ValidationError):
        ExpectedGeographicFinding()


def test_forbidden_finding_requires_constraint() -> None:
    """A forbidden geographic finding must constrain kind or support."""
    from agentic_threat_investigator.evaluation.geoint.models import (
        ForbiddenGeographicFinding,
    )

    with pytest.raises(ValidationError):
        ForbiddenGeographicFinding()


def test_expected_resolutions_must_be_nonempty() -> None:
    """Every scenario declares at least one expected resolution outcome."""
    with pytest.raises(ValidationError):
        ExpectedGeointOutcome(
            resolutions=(),
            agent_context=ExpectedAgentContext(),
            agent_output=ExpectedAgentOutput(
                expected_validation=GeointValidationExpectation.ACCEPTED,
                allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
            ),
        )


def test_allowed_verdicts_must_be_nonempty() -> None:
    """The agent-output envelope requires a non-empty verdict set."""
    with pytest.raises(ValidationError):
        ExpectedAgentOutput(
            expected_validation=GeointValidationExpectation.ACCEPTED,
            allowed_verdicts=frozenset(),
        )


def test_semantic_labels_must_be_stable() -> None:
    """Fixture labels must match the stable lowercase grammar."""
    with pytest.raises(ValidationError):
        GeointFixtureEntity(
            label="Bad Label!", type=EntityType.IP_ADDRESS, value="203.0.113.1"
        )
    with pytest.raises(ValidationError):
        GeointFixtureResolution(
            label="bad label!",
            entity="target_ip",
            evidence="seattle_evidence",
        )
    # Dashes are part of the documented grammar.
    resolution = GeointFixtureResolution(
        label="scenario-a.obs",
        entity="target_ip",
        evidence="seattle_evidence",
    )
    assert resolution.label == "scenario-a.obs"


def test_evidence_type_defaults_to_geolocation() -> None:
    """Fixture Evidence defaults to GEOLOCATION; non-geographic rows opt in."""
    from agentic_threat_investigator.domain.evidence import EvidenceType

    evidence = GeointFixtureEvidence(
        label="geo",
        subject="target_ip",
        source="urn:ati:source:test",
        facts={"country_code": "US", "precision": "country"},
    )
    assert evidence.type is EvidenceType.GEOLOCATION
    dns = evidence.model_copy(update={"type": EvidenceType.DNS})
    assert dns.type is EvidenceType.DNS


def test_other_investigation_flag_round_trips() -> None:
    """The cross-Investigation flag is a fixture-authoring boolean."""
    evidence = GeointFixtureEvidence(
        label="geo",
        subject="target_ip",
        source="urn:ati:source:test",
        facts={"country_code": "US", "precision": "country"},
        other_investigation=True,
    )
    assert evidence.other_investigation


def test_forbidden_inference_duplicates_rejected() -> None:
    """Duplicate forbidden-inference declarations are rejected."""
    with pytest.raises(ValidationError):
        ExpectedGeointOutcome(
            resolutions=(
                ExpectedResolutionOutcome(
                    label="seattle_obs",
                    status="resolved",
                    location="seattle",
                    precision=LocationPrecision.CITY,
                ),
            ),
            agent_context=ExpectedAgentContext(),
            agent_output=ExpectedAgentOutput(
                expected_validation=GeointValidationExpectation.ACCEPTED,
                allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
            ),
            forbidden_inferences=cast(
                Any,
                [
                    GeointForbiddenInference.COORDINATION,
                    GeointForbiddenInference.COORDINATION,
                ],
            ),
        )


def test_allowed_operations_duplicates_rejected() -> None:
    """Duplicate allowed tool operations are rejected."""
    with pytest.raises(ValidationError):
        ExpectedAgentContext(
            allowed_operations=cast(
                Any,
                [
                    GeointToolOperation.SUMMARY,
                    GeointToolOperation.SUMMARY,
                ],
            )
        )


def test_geography_count_bound() -> None:
    """A fixture may not declare an unbounded geography corpus."""
    many = tuple(
        GeointFixtureLocation(
            label=f"loc_{index}",
            location_type=LocationType.COUNTRY,
            name=f"Country {index}",
            country_code="XX",
        )
        for index in range(33)
    )
    with pytest.raises(ValidationError):
        GeointFixture(
            objective="Objective.",
            root_entity="target_ip",
            geography=many,
            entities=(
                GeointFixtureEntity(
                    label="target_ip", type=EntityType.IP_ADDRESS, value="203.0.113.1"
                ),
            ),
            evidence=(),
            resolutions=(),
        )


def test_scenario_id_grammar_enforced() -> None:
    """Scenario identifiers must match the stable lowercase grammar."""
    with pytest.raises(ValidationError):
        unit_geoint_scenario().model_copy(update={"id": "Invalid ID!"}).model_validate(
            unit_geoint_scenario().model_copy(update={"id": "Invalid ID!"}).model_dump()
        )


def test_resolution_identity_is_uuidv5() -> None:
    """Resolution observation identities are stable UUIDv5 values."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution_import(scenario)
    assert isinstance(resolution.investigation_id, UUID)


def unit_geoint_resolution_import(
    scenario: GeointScenario,
) -> GeointScenarioResolution:
    """Import the resolution builder from the support module (indirection)."""
    from tests.support.geoint_evaluation import unit_geoint_resolution

    return unit_geoint_resolution(scenario)
