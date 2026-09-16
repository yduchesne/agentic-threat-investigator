# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic GEOINT evaluator hard-check matrix (PR 26G).

The evaluator is pure: every input is built in memory (never a database).
Each test constructs one scenario, its resolution, the persisted geographic
state, the model-visible context, an evaluation-recorded tool trace, and the
scripted agent output, then asserts the stable bounded failure codes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.domain.analyst import (
    AnalystEntityGeointContext,
    AnalystGeointContext,
    AnalystGeointLocation,
    AnalystGeointObservation,
    AnalystGeointPrecisionCounts,
    AnalystGeointSummary,
    GeographicFinding,
    GeographicFindingKind,
    GeographicTemporalInterpretation,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import LocationPrecision, LocationType
from agentic_threat_investigator.evaluation.geoint.evaluator import (
    GeointDeterministicEvaluator,
)
from agentic_threat_investigator.evaluation.geoint.models import (
    ExpectedAgentOutput,
    ExpectedGeographicFinding,
    ForbiddenGeographicFinding,
    GeointAgentEvaluationInput,
    GeointCurrentState,
    GeointEvaluationFailure,
    GeointEvaluationFailureCode,
    GeointEvaluationMetrics,
    GeointEvaluationResult,
    GeointForbiddenInference,
    GeointGeographicState,
    GeointResolutionState,
    GeointScenario,
    GeointScenarioResolution,
    GeointToolOperation,
    GeointToolOperationRecord,
    GeointValidationExpectation,
    GeointValidationOutcome,
    PersistedGeointObservation,
)
from tests.support.geoint_evaluation import (
    accepted_decision,
    accepted_input,
    unit_geoint_resolution,
    unit_geoint_scenario,
)

_FIXED = datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC)

EVALUATOR = GeointDeterministicEvaluator()


def _empty_summary() -> AnalystGeointSummary:
    """Build one empty model-visible summary DTO."""
    return AnalystGeointSummary(
        entity_count_with_location=1,
        observation_count=1,
        location_count=1,
        country_count=0,
        administrative_area_count=0,
        city_count=1,
        precision_counts=AnalystGeointPrecisionCounts(
            country=0, administrative_area=0, city=1
        ),
        top_locations=(),
        truncated=False,
    )


def _analyst_location(resolution: GeointScenarioResolution) -> AnalystGeointLocation:
    """Build one model-visible Location DTO without representative coordinates."""
    return AnalystGeointLocation(
        location_id=resolution.geography_ids["seattle"],
        location_type=LocationType.CITY,
        canonical_location_name="Seattle",
        country_code="US",
        admin1_code="WA",
        parent_location_id=resolution.geography_ids["washington"],
    )


def _context_observation(
    resolution: GeointScenarioResolution, observation_label: str, entity_label: str
) -> AnalystGeointObservation:
    """Build one model-visible observation for a resolution/entity label pair."""
    location = _analyst_location(resolution)
    if observation_label == "b_obs":
        location = location.model_copy(
            update={
                "location_id": resolution.geography_ids["dallas"],
                "canonical_location_name": "Dallas",
                "admin1_code": "TX",
            }
        )
    return AnalystGeointObservation(
        observation_id=resolution.observation_ids[observation_label],
        entity_id=resolution.entity_ids[entity_label],
        evidence_id=resolution.evidence_ids[
            "b_evidence" if observation_label == "b_obs" else "a_evidence"
        ],
        location=location,
        precision=LocationPrecision.CITY,
        resolution_method="canonical_geography_v1",
        observed_at=_FIXED,
        retrieved_at=_FIXED,
        resolved_at=_FIXED,
    )


def _context(resolution: GeointScenarioResolution) -> AnalystGeointContext:
    """Build the canonical model-visible context of the unit scenario."""
    observation = AnalystGeointObservation(
        observation_id=resolution.observation_ids["seattle_obs"],
        entity_id=resolution.entity_ids["target_ip"],
        evidence_id=resolution.evidence_ids["seattle_evidence"],
        location=_analyst_location(resolution),
        precision=LocationPrecision.CITY,
        resolution_method="canonical_geography_v1",
        observed_at=_FIXED,
        retrieved_at=_FIXED,
        resolved_at=_FIXED,
    )
    return AnalystGeointContext(
        summary=_empty_summary(),
        entities=(
            AnalystEntityGeointContext(
                entity_id=resolution.entity_ids["target_ip"],
                entity_type=EntityType.IP_ADDRESS,
                entity_value="203.0.113.42",
                current_observation=observation,
            ),
        ),
    )


def _observation(
    resolution: GeointScenarioResolution,
    *,
    location_id: UUID,
    precision: LocationPrecision = LocationPrecision.CITY,
) -> PersistedGeointObservation:
    """Build one persisted observation snapshot from the resolution map."""
    return PersistedGeointObservation(
        observation_id=resolution.observation_ids["seattle_obs"],
        entity_id=resolution.entity_ids["target_ip"],
        location_id=location_id,
        evidence_id=resolution.evidence_ids["seattle_evidence"],
        precision=precision,
        observed_at=_FIXED,
        retrieved_at=_FIXED,
    )


def _resolved_state(resolution: GeointScenarioResolution) -> GeointGeographicState:
    """Build the canonical resolved state of the unit scenario."""
    observation = _observation(
        resolution, location_id=resolution.geography_ids["seattle"]
    )
    return GeointGeographicState(
        observations=(observation,),
        current=(
            GeointCurrentState(
                entity_id=resolution.entity_ids["target_ip"],
                location_id=resolution.geography_ids["seattle"],
                precision=LocationPrecision.CITY,
                latest_observation_id=observation.observation_id,
            ),
        ),
        resolutions=(
            GeointResolutionState(
                label="seattle_obs",
                status="resolved",
                observation_id=observation.observation_id,
                location_id=resolution.geography_ids["seattle"],
                precision=LocationPrecision.CITY,
            ),
        ),
    )


def _finding(resolution: GeointScenarioResolution) -> GeographicFinding:
    """Build the canonical descriptive SHARED_LOCATION finding."""
    return GeographicFinding(
        kind=GeographicFindingKind.SHARED_LOCATION,
        statement="The entity was observed in Seattle.",
        temporal_interpretation=GeographicTemporalInterpretation.NONE,
        observation_ids=(resolution.observation_ids["seattle_obs"],),
        evidence_ids=(resolution.evidence_ids["seattle_evidence"],),
        entity_ids=(resolution.entity_ids["target_ip"],),
        location_ids=(resolution.geography_ids["seattle"],),
    )


def _canonical_trace(
    resolution: GeointScenarioResolution, *, entity_label: str = "target_ip"
) -> tuple[GeointToolOperationRecord, ...]:
    """Return the delivered-policy tool trace for the unit scenario."""
    return (
        GeointToolOperationRecord(
            operation=GeointToolOperation.SUMMARY,
            investigation_id=resolution.investigation_id,
        ),
        GeointToolOperationRecord(
            operation=GeointToolOperation.CURRENT_FOR_ENTITY,
            investigation_id=resolution.investigation_id,
            entity_id=resolution.entity_ids[entity_label],
        ),
        GeointToolOperationRecord(
            operation=GeointToolOperation.HISTORY_FOR_ENTITY,
            investigation_id=resolution.investigation_id,
            entity_id=resolution.entity_ids[entity_label],
            limit=5,
            has_more=False,
        ),
    )


def _evaluate(
    scenario: GeointScenario,
    resolution: GeointScenarioResolution,
    state: GeointGeographicState,
    context: AnalystGeointContext | None,
    trace: tuple[GeointToolOperationRecord, ...],
    agent: GeointAgentEvaluationInput,
) -> GeointEvaluationResult:
    """Run the deterministic evaluator over the built inputs."""
    return EVALUATOR.evaluate(
        scenario=scenario,
        resolution=resolution,
        state=state,
        context=context,
        tool_trace=trace,
        agent=agent,
    )


def _failure_codes(
    result: GeointEvaluationResult,
) -> set[GeointEvaluationFailureCode]:
    """Return the stable failure codes of one result."""
    return {failure.code for failure in result.failures}


def test_canonical_scenario_passes() -> None:
    """The canonical resolved/accepted scenario passes with exact metrics."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    state = _resolved_state(resolution)
    context = _context(resolution)
    decision = accepted_decision(geographic_findings=(_finding(resolution),))
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario, resolution, state, context, _canonical_trace(resolution), agent
    )
    assert result.passed, "; ".join(f.message for f in result.failures)
    assert result.metrics.geographic_claim_count == 1
    assert result.metrics.supported_geographic_claim_count == 1
    assert result.metrics.unsupported_geographic_claim_count == 0
    assert result.metrics.provenance_closure_rate == 1.0
    assert result.metrics.tool_call_count == 3
    assert result.metrics.geoint_context_entity_count == 1
    assert result.metrics.geoint_context_observation_count == 1
    assert result.metrics.observation_count == 1
    assert result.metrics.resolution_count == 1


def test_precision_inflation_is_hard_failure() -> None:
    """An observation precision that contradicts the input is a hard failure."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    # The claim declared city precision; a persisted country precision is an
    # unsupported downgrade and the evaluator must report it.
    observation = _observation(
        resolution,
        location_id=resolution.geography_ids["seattle"],
        precision=LocationPrecision.COUNTRY,
    )
    state = GeointGeographicState(
        observations=(observation,),
        current=(),
        resolutions=(
            GeointResolutionState(
                label="seattle_obs",
                status="resolved",
                observation_id=observation.observation_id,
                location_id=resolution.geography_ids["seattle"],
                precision=LocationPrecision.COUNTRY,
            ),
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        state,
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.PRECISION_INFLATION in _failure_codes(result)


def test_wrong_canonical_location_is_hard_failure() -> None:
    """An observation bound to the wrong canonical Location fails hard."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    wrong = uuid4()
    state = GeointGeographicState(
        observations=(_observation(resolution, location_id=wrong),),
        current=(),
        resolutions=(
            GeointResolutionState(
                label="seattle_obs",
                status="resolved",
                observation_id=resolution.observation_ids["seattle_obs"],
                location_id=wrong,
                precision=LocationPrecision.CITY,
            ),
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        state,
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.WRONG_CANONICAL_LOCATION in _failure_codes(
        result
    )


def test_wrong_current_state_is_hard_failure() -> None:
    """Investigation-relative current must match the expected Location."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    wrong = uuid4()
    state = _resolved_state(resolution).model_copy(
        update={
            "current": (
                GeointCurrentState(
                    entity_id=resolution.entity_ids["target_ip"],
                    location_id=wrong,
                    precision=LocationPrecision.CITY,
                    latest_observation_id=resolution.observation_ids["seattle_obs"],
                ),
            ),
        }
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        state,
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.WRONG_CURRENT_STATE in _failure_codes(result)


def test_wrong_history_order_is_hard_failure() -> None:
    """Newest-first history ordering must match the expected labels."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    extra = PersistedGeointObservation(
        observation_id=uuid4(),
        entity_id=resolution.entity_ids["target_ip"],
        location_id=resolution.geography_ids["washington"],
        evidence_id=resolution.evidence_ids["seattle_evidence"],
        precision=LocationPrecision.ADMINISTRATIVE_AREA,
        observed_at=_FIXED,
        retrieved_at=_FIXED,
    )
    state = _resolved_state(resolution).model_copy(
        update={
            "observations": (
                _observation(
                    resolution, location_id=resolution.geography_ids["seattle"]
                ),
                extra,
            )
        }
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        state,
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.WRONG_HISTORY_ORDER in _failure_codes(result)


def test_duplicate_geographic_truth_is_hard_failure() -> None:
    """Two observations for one Entity/Evidence pair are duplicate truth."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    first = _observation(resolution, location_id=resolution.geography_ids["seattle"])
    duplicate = first.model_copy(update={"observation_id": uuid4()})
    state = GeointGeographicState(
        observations=(first, duplicate),
        current=(),
        resolutions=(
            GeointResolutionState(
                label="seattle_obs",
                status="resolved",
                observation_id=first.observation_id,
                location_id=resolution.geography_ids["seattle"],
                precision=LocationPrecision.CITY,
            ),
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        state,
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.DUPLICATE_GEOGRAPHIC_TRUTH in _failure_codes(
        result
    )


def test_wrong_resolution_status_is_hard_failure() -> None:
    """An expected resolved outcome that stayed unresolved fails hard."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    state = GeointGeographicState(
        observations=(),
        current=(),
        resolutions=(
            GeointResolutionState(label="seattle_obs", status="unresolvable"),
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        state,
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.WRONG_RESOLUTION_STATUS in _failure_codes(result)


def test_wrong_investigation_provenance_is_hard_failure() -> None:
    """An observation citing Evidence outside the scenario fails hard."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    state = GeointGeographicState(
        observations=(
            PersistedGeointObservation(
                observation_id=uuid4(),
                entity_id=resolution.entity_ids["target_ip"],
                location_id=resolution.geography_ids["seattle"],
                evidence_id=uuid4(),
                precision=LocationPrecision.CITY,
                observed_at=_FIXED,
                retrieved_at=_FIXED,
            ),
        ),
        current=(),
        resolutions=(),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        state,
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.WRONG_INVESTIGATION_PROVENANCE in _failure_codes(
        result
    )


def test_disallowed_tool_operation_is_hard_failure() -> None:
    """A proximity operation never exists in the delivered facade."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    trace = (
        GeointToolOperationRecord(
            operation=GeointToolOperation.PROXIMITY,
            investigation_id=resolution.investigation_id,
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        trace,
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.DISALLOWED_TOOL_OPERATION in _failure_codes(
        result
    )


def test_tool_bound_exceeded_is_hard_failure() -> None:
    """A history page over the delivered bound fails hard."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    trace = (
        GeointToolOperationRecord(
            operation=GeointToolOperation.HISTORY_FOR_ENTITY,
            investigation_id=resolution.investigation_id,
            entity_id=resolution.entity_ids["target_ip"],
            limit=25,
            has_more=False,
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        trace,
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.TOOL_BOUND_EXCEEDED in _failure_codes(result)


def test_cursor_draining_is_hard_failure() -> None:
    """The facade must never request a cursor."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    trace = (
        GeointToolOperationRecord(
            operation=GeointToolOperation.HISTORY_FOR_ENTITY,
            investigation_id=resolution.investigation_id,
            entity_id=resolution.entity_ids["target_ip"],
            limit=5,
            cursor_requested=True,
            has_more=True,
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        trace,
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.CURSOR_DRAINING in _failure_codes(result)


def test_unrelated_entity_fanout_is_hard_failure() -> None:
    """A context Entity outside the scenario's eligible Entities fails hard."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    observation = _context(resolution).entities[0].current_observation
    assert observation is not None
    foreign_entity_id = uuid4()
    foreign_observation = observation.model_copy(
        update={"observation_id": uuid4(), "entity_id": foreign_entity_id}
    )
    context = AnalystGeointContext(
        summary=_empty_summary(),
        entities=(
            AnalystEntityGeointContext(
                entity_id=resolution.entity_ids["target_ip"],
                entity_type=EntityType.IP_ADDRESS,
                entity_value="203.0.113.42",
                current_observation=observation,
            ),
            AnalystEntityGeointContext(
                entity_id=foreign_entity_id,
                entity_type=EntityType.IP_ADDRESS,
                entity_value="203.0.113.99",
                current_observation=foreign_observation,
            ),
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        context,
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.UNRELATED_ENTITY_FANOUT in _failure_codes(result)


def test_cross_investigation_leak_is_hard_failure() -> None:
    """A context observation outside the scenario fails hard."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    observation = _context(resolution).entities[0].current_observation
    assert observation is not None
    foreign = observation.model_copy(update={"observation_id": uuid4()})
    context = AnalystGeointContext(
        summary=_empty_summary(),
        entities=(
            AnalystEntityGeointContext(
                entity_id=resolution.entity_ids["target_ip"],
                entity_type=EntityType.IP_ADDRESS,
                entity_value="203.0.113.42",
                current_observation=foreign,
            ),
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        context,
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.CROSS_INVESTIGATION_LEAK in _failure_codes(
        result
    )


def test_truncation_not_surfaced_is_hard_failure() -> None:
    """has_more_history must be surfaced when a history page was bounded."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    trace = (
        GeointToolOperationRecord(
            operation=GeointToolOperation.HISTORY_FOR_ENTITY,
            investigation_id=resolution.investigation_id,
            entity_id=resolution.entity_ids["target_ip"],
            limit=5,
            has_more=True,
        ),
    )
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        trace,
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.TRUNCATION_NOT_SURFACED in _failure_codes(result)


def test_unknown_observation_cited_is_hard_failure() -> None:
    """A finding citing an observation outside the scenario fails hard."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    decision = accepted_decision(
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.SHARED_LOCATION,
                statement="A fabricated observation.",
                temporal_interpretation=GeographicTemporalInterpretation.NONE,
                observation_ids=(uuid4(),),
                evidence_ids=(resolution.evidence_ids["seattle_evidence"],),
                entity_ids=(resolution.entity_ids["target_ip"],),
                location_ids=(resolution.geography_ids["seattle"],),
            ),
        )
    )
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.UNKNOWN_OBSERVATION_CITED in _failure_codes(
        result
    )


def test_omitted_context_observation_cited_is_hard_failure() -> None:
    """A finding citing a scenario observation not supplied in context fails."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    decision = accepted_decision(geographic_findings=(_finding(resolution),))
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        None,
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert (
        GeointEvaluationFailureCode.OMITTED_CONTEXT_OBSERVATION_CITED
        in _failure_codes(result)
    )


def test_substituted_evidence_is_hard_failure() -> None:
    """A finding Evidence that does not match the cited observation fails."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    decision = accepted_decision(
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.SHARED_LOCATION,
                statement="Substituted evidence.",
                temporal_interpretation=GeographicTemporalInterpretation.NONE,
                observation_ids=(resolution.observation_ids["seattle_obs"],),
                evidence_ids=(uuid4(),),
                entity_ids=(resolution.entity_ids["target_ip"],),
                location_ids=(resolution.geography_ids["seattle"],),
            ),
        )
    )
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.SUBSTITUTED_EVIDENCE in _failure_codes(result)


def test_wrong_finding_location_support_is_hard_failure() -> None:
    """A finding whose Location support does not match the observations fails."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    decision = accepted_decision(
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.SHARED_LOCATION,
                statement="Wrong location support.",
                temporal_interpretation=GeographicTemporalInterpretation.NONE,
                observation_ids=(resolution.observation_ids["seattle_obs"],),
                evidence_ids=(resolution.evidence_ids["seattle_evidence"],),
                entity_ids=(resolution.entity_ids["target_ip"],),
                location_ids=(uuid4(),),
            ),
        )
    )
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.WRONG_FINDING_LOCATION_SUPPORT in _failure_codes(
        result
    )


def test_overstated_shared_location_is_hard_failure() -> None:
    """shared_location with observations in two cities is an overstatement."""
    from tests.support.geoint_evaluation import overstatement_scenario

    scenario = overstatement_scenario()
    resolution = unit_geoint_resolution(scenario)
    a_obs = resolution.observation_ids["a_obs"]
    b_obs = resolution.observation_ids["b_obs"]
    context = AnalystGeointContext(
        summary=_empty_summary(),
        entities=(
            AnalystEntityGeointContext(
                entity_id=resolution.entity_ids["ip_a"],
                entity_type=EntityType.IP_ADDRESS,
                entity_value="203.0.113.221",
                current_observation=_context_observation(resolution, "a_obs", "ip_a"),
            ),
            AnalystEntityGeointContext(
                entity_id=resolution.entity_ids["ip_b"],
                entity_type=EntityType.IP_ADDRESS,
                entity_value="203.0.113.222",
                current_observation=_context_observation(resolution, "b_obs", "ip_b"),
            ),
        ),
    )
    state = GeointGeographicState(
        observations=(
            PersistedGeointObservation(
                observation_id=a_obs,
                entity_id=resolution.entity_ids["ip_a"],
                location_id=resolution.geography_ids["seattle"],
                evidence_id=resolution.evidence_ids["a_evidence"],
                precision=LocationPrecision.CITY,
                observed_at=_FIXED,
                retrieved_at=_FIXED,
            ),
            PersistedGeointObservation(
                observation_id=b_obs,
                entity_id=resolution.entity_ids["ip_b"],
                location_id=resolution.geography_ids["dallas"],
                evidence_id=resolution.evidence_ids["b_evidence"],
                precision=LocationPrecision.CITY,
                observed_at=_FIXED,
                retrieved_at=_FIXED,
            ),
        ),
        current=(),
        resolutions=(),
    )
    decision = accepted_decision(
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.SHARED_LOCATION,
                statement="They are colocated.",
                temporal_interpretation=GeographicTemporalInterpretation.NONE,
                observation_ids=(a_obs, b_obs),
                evidence_ids=(
                    resolution.evidence_ids["a_evidence"],
                    resolution.evidence_ids["b_evidence"],
                ),
                entity_ids=(
                    resolution.entity_ids["ip_a"],
                    resolution.entity_ids["ip_b"],
                ),
                location_ids=(
                    resolution.geography_ids["seattle"],
                    resolution.geography_ids["dallas"],
                ),
            ),
        )
    )
    agent = accepted_input(
        decision=decision, validation=GeointValidationOutcome.REJECTED
    )
    result = _evaluate(
        scenario,
        resolution,
        state,
        context,
        _canonical_trace(resolution, entity_label="ip_a"),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.WRONG_FINDING_LOCATION_SUPPORT in _failure_codes(
        result
    )
    assert (
        GeointEvaluationFailureCode.UNEXPECTED_VALIDATION_OUTCOME
        not in _failure_codes(result)
    )


def test_invalid_location_change_is_hard_failure() -> None:
    """location_change_observed requires distinct locations and times."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    observation = _context(resolution).entities[0].current_observation
    assert observation is not None
    decision = accepted_decision(
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
                statement="The entity changed location.",
                temporal_interpretation=(
                    GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED
                ),
                observation_ids=(observation.observation_id,),
                evidence_ids=(observation.evidence_id,),
                entity_ids=(observation.entity_id,),
                location_ids=(observation.location.location_id,),
            ),
        )
    )
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.INVALID_LOCATION_CHANGE in _failure_codes(result)


def test_unsupported_containment_is_hard_failure() -> None:
    """contained_location_context requires a containment selection."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    observation = _context(resolution).entities[0].current_observation
    assert observation is not None
    decision = accepted_decision(
        geographic_findings=(
            GeographicFinding(
                kind=GeographicFindingKind.CONTAINED_LOCATION_CONTEXT,
                statement="Contained context.",
                temporal_interpretation=GeographicTemporalInterpretation.NONE,
                observation_ids=(observation.observation_id,),
                evidence_ids=(observation.evidence_id,),
                entity_ids=(observation.entity_id,),
                location_ids=(observation.location.location_id,),
            ),
        )
    )
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.UNSUPPORTED_CONTAINMENT in _failure_codes(result)


def test_missing_required_geographic_finding_is_hard_failure() -> None:
    """An expected finding absent from the decision fails hard."""
    base = unit_geoint_scenario()
    scenario = base.model_copy(
        update={
            "expected": base.expected.model_copy(
                update={
                    "agent_output": ExpectedAgentOutput(
                        expected_validation=GeointValidationExpectation.ACCEPTED,
                        allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
                        required_geographic_findings=(
                            ExpectedGeographicFinding(
                                kind=GeographicFindingKind.SHARED_LOCATION,
                                observation_labels=frozenset({"seattle_obs"}),
                            ),
                        ),
                    )
                }
            )
        }
    )
    resolution = unit_geoint_resolution(scenario)
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert (
        GeointEvaluationFailureCode.MISSING_REQUIRED_GEOGRAPHIC_FINDING
        in _failure_codes(result)
    )


def test_forbidden_geographic_finding_is_hard_failure() -> None:
    """A finding matching a forbidden pattern fails hard."""
    base = unit_geoint_scenario()
    scenario = base.model_copy(
        update={
            "expected": base.expected.model_copy(
                update={
                    "agent_output": ExpectedAgentOutput(
                        expected_validation=GeointValidationExpectation.ACCEPTED,
                        allowed_verdicts=frozenset({Verdict.INCONCLUSIVE}),
                        forbidden_geographic_findings=(
                            ForbiddenGeographicFinding(
                                kind=GeographicFindingKind.SHARED_LOCATION,
                                observation_labels=frozenset({"seattle_obs"}),
                            ),
                        ),
                    )
                }
            )
        }
    )
    resolution = unit_geoint_resolution(scenario)
    decision = accepted_decision(geographic_findings=(_finding(resolution),))
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.FORBIDDEN_GEOGRAPHIC_FINDING in _failure_codes(
        result
    )


def test_unexpected_validation_outcome_is_hard_failure() -> None:
    """Expected acceptance with a runtime rejection fails hard."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    agent = accepted_input(
        decision=accepted_decision(),
        validation=GeointValidationOutcome.REJECTED,
    )
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.UNEXPECTED_VALIDATION_OUTCOME in _failure_codes(
        result
    )


def test_geography_only_verdict_is_hard_failure() -> None:
    """Geography alone can never support a positive verdict."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    decision = accepted_decision(
        verdict=Verdict.MALICIOUS,
        geographic_findings=(_finding(resolution),),
    )
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert not result.passed
    assert GeointEvaluationFailureCode.GEOGRAPHY_ONLY_VERDICT in _failure_codes(result)


def test_geographic_evidence_misuse_is_hard_failure() -> None:
    """Geographic Evidence can never materially support a non-GEOLOCATION finding."""
    base = unit_geoint_scenario()
    scenario = base.model_copy(
        update={
            "expected": base.expected.model_copy(
                update={
                    "forbidden_inferences": frozenset(
                        {GeointForbiddenInference.COORDINATION}
                    )
                }
            )
        }
    )
    resolution = unit_geoint_resolution(scenario)
    decision = accepted_decision(
        verdict=Verdict.MALICIOUS,
        findings=(
            AnalyticalFinding(
                category=FindingCategory.REPUTATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="The reputation finding.",
                confidence=AssessmentConfidence.MEDIUM,
                support=(
                    EvidenceSupport(
                        kind="evidence",
                        evidence_id=resolution.evidence_ids["seattle_evidence"],
                    ),
                ),
            ),
        ),
    )
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    codes = _failure_codes(result)
    assert not result.passed
    assert GeointEvaluationFailureCode.GEOGRAPHIC_EVIDENCE_MISUSED in codes
    assert GeointEvaluationFailureCode.UNSUPPORTED_MATERIAL_FINDING in codes
    assert GeointEvaluationFailureCode.FORBIDDEN_INFERENCE_EXPRESSED in codes


def test_reference_location_only_support_is_hard_failure() -> None:
    """A GEOLOCATION Finding citing Evidence without an observation fails."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    state = GeointGeographicState(observations=(), current=(), resolutions=())
    assessment = Assessment(
        investigation_id=resolution.investigation_id,
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="Summary.",
        analyzed_evidence_ids=(resolution.evidence_ids["seattle_evidence"],),
        findings=(
            AnalyticalFinding(
                category=FindingCategory.GEOLOCATION,
                disposition=FindingDisposition.SUPPORTING,
                statement="The location statement.",
                confidence=AssessmentConfidence.LOW,
                support=(
                    EvidenceSupport(
                        kind="evidence",
                        evidence_id=resolution.evidence_ids["seattle_evidence"],
                    ),
                ),
            ),
        ),
    )
    agent = GeointAgentEvaluationInput(
        decision=None,
        validation=GeointValidationOutcome.ACCEPTED,
        assessment=assessment,
    )
    result = _evaluate(
        scenario, resolution, state, None, _canonical_trace(resolution), agent
    )
    assert not result.passed
    assert (
        GeointEvaluationFailureCode.REFERENCE_LOCATION_ONLY_SUPPORT
        in _failure_codes(result)
    )


def test_independent_support_with_descriptive_geography_passes() -> None:
    """Independent non-geographic support plus descriptive GEOINT passes."""
    base = unit_geoint_scenario()
    scenario = base.model_copy(
        update={
            "expected": base.expected.model_copy(
                update={
                    "forbidden_inferences": frozenset(
                        {GeointForbiddenInference.MALICIOUSNESS}
                    )
                }
            )
        }
    )
    resolution = unit_geoint_resolution(scenario)
    decision = accepted_decision(
        verdict=Verdict.MALICIOUS,
        geographic_findings=(_finding(resolution),),
    )
    decision = decision.model_copy(
        update={
            "findings": (
                AnalyticalFinding(
                    category=FindingCategory.REPUTATION,
                    disposition=FindingDisposition.SUPPORTING,
                    statement="Independent reputation support.",
                    confidence=AssessmentConfidence.MEDIUM,
                    support=(
                        EvidenceSupport(
                            kind="evidence",
                            evidence_id=uuid4(),  # non-geographic, never observed
                        ),
                    ),
                ),
            ),
        }
    )
    agent = accepted_input(decision=decision)
    result = _evaluate(
        scenario,
        resolution,
        _resolved_state(resolution),
        _context(resolution),
        _canonical_trace(resolution),
        agent,
    )
    assert result.passed, "; ".join(f.message for f in result.failures)


def test_metrics_close_provenance_on_empty_state() -> None:
    """An empty state scores perfect closure with zero claims (denominator-safe)."""
    scenario = unit_geoint_scenario()
    resolution = unit_geoint_resolution(scenario)
    state = GeointGeographicState(observations=(), current=(), resolutions=())
    agent = accepted_input(decision=accepted_decision())
    result = _evaluate(
        scenario, resolution, state, None, _canonical_trace(resolution), agent
    )
    assert not result.passed  # the scenario expects a resolved observation
    assert result.metrics.geographic_claim_count == 0
    assert result.metrics.provenance_closure_rate == 1.0


def test_passed_requires_no_failures() -> None:
    """The result model rejects a self-contradictory passed flag."""
    with pytest.raises(ValueError):
        GeointEvaluationResult(
            scenario_id="x",
            scenario_version=1,
            passed=True,
            failures=(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.PRECISION_INFLATION,
                    message="x",
                ),
            ),
            metrics=GeointEvaluationMetrics(
                geographic_claim_count=0,
                supported_geographic_claim_count=0,
                unsupported_geographic_claim_count=0,
                tool_call_count=0,
                geoint_context_entity_count=0,
                geoint_context_observation_count=0,
                observation_count=0,
                resolution_count=0,
            ),
        )
