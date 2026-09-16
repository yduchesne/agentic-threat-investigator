# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure deterministic GEOINT behavioral evaluator (PR 26G).

The evaluator consumes a **materialized and completed** scenario: the
persisted geographic state read through the normal repositories, the
model-visible context produced by the delivered PR 26F policy, an
evaluation-recorded tool trace, and the scripted agent decision with its
runtime validation outcome and the persisted Assessment. It is synchronous
and pure: no database, network, LLM, environment, or clock access.

Hard checks are grouped and emitted in a fixed order:

1. resolution/spatial (wrong status, missing observation, wrong canonical
   Location, precision inflation, duplicate geographic truth);
2. current/history (wrong current, wrong history ordering);
3. state provenance (wrong Investigation, observation/Evidence mismatch);
4. tool/context (disallowed operation, bound exceeded, cursor draining,
   unrelated Entity fan-out, truncation not surfaced);
5. structured output (validation outcome, unsupported kind, unknown/omitted
   observation, substituted Evidence, wrong Entity/Location support,
   unsupported containment, invalid location change, required/forbidden
   findings);
6. epistemic gates (geography-only verdict, geographic Evidence misuse,
   unsupported material finding, declared forbidden inferences).

Within a group the ordering never depends on set/hash iteration. Metrics
derive from the same comparisons as the failures.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime
from uuid import UUID

from agentic_threat_investigator.app.query.geoint import effective_observation_time
from agentic_threat_investigator.domain.analyst import (
    AnalystGeointContext,
    EvidenceAnalystDecision,
    GeographicFinding,
    GeographicFindingKind,
)
from agentic_threat_investigator.domain.assessment import (
    EvidenceSupport,
    FindingCategory,
    Verdict,
)
from agentic_threat_investigator.evaluation.geoint.models import (
    ExpectedAgentOutput,
    ExpectedGeographicFinding,
    ExpectedGeointOutcome,
    ForbiddenGeographicFinding,
    GeointAgentEvaluationInput,
    GeointEvaluationFailure,
    GeointEvaluationFailureCode,
    GeointEvaluationMetrics,
    GeointEvaluationResult,
    GeointFixtureResolution,
    GeointForbiddenInference,
    GeointGeographicState,
    GeointScenario,
    GeointScenarioResolution,
    GeointToolOperation,
    GeointToolOperationRecord,
    GeointValidationExpectation,
    GeointValidationOutcome,
    PersistedGeointObservation,
)

# The delivered closed descriptive vocabulary. Any finding kind outside this
# set would be an unsupported inference (coordination/ownership/campaign/
# targeting/attribution/travel/route are structurally impossible).
_APPROVED_KINDS = frozenset(GeographicFindingKind)

_MATERIAL_INFERENCE_CODES = frozenset(
    {
        GeointForbiddenInference.COORDINATION,
        GeointForbiddenInference.OWNERSHIP,
        GeointForbiddenInference.CAMPAIGN,
        GeointForbiddenInference.TARGETING,
        GeointForbiddenInference.ATTRIBUTION,
        GeointForbiddenInference.TRAVEL,
        GeointForbiddenInference.ROUTE,
    }
)
"""Forbidden-inference codes whose structural predicate is geographic-evidence misuse."""


class GeointDeterministicEvaluator:
    """Compare one materialized GEOINT scenario against its envelope.

    The evaluator is a stateless synchronous object; all inputs arrive
    through :meth:`evaluate`, so identical inputs always produce identical
    JSON-compatible results.
    """

    def evaluate(
        self,
        *,
        scenario: GeointScenario,
        resolution: GeointScenarioResolution,
        state: GeointGeographicState,
        context: AnalystGeointContext | None,
        tool_trace: tuple[GeointToolOperationRecord, ...],
        agent: GeointAgentEvaluationInput,
    ) -> GeointEvaluationResult:
        """Return the deterministic behavioral result for the scenario."""
        expected = scenario.expected
        failures: list[GeointEvaluationFailure] = []
        self._validate_resolution_coverage(expected, resolution)
        fixture_resolutions = {
            item.label: item for item in scenario.fixture.resolutions
        }

        self._evaluate_resolutions(
            expected, resolution, fixture_resolutions, state, failures
        )
        self._evaluate_current_and_history(expected, resolution, state, failures)
        self._evaluate_state_provenance(resolution, state, failures)
        self._evaluate_tool_and_context(
            expected, resolution, context, tool_trace, failures
        )
        self._evaluate_agent_output(
            expected, resolution, state, context, agent, failures
        )
        self._evaluate_epistemic_gates(expected, state, agent, failures)

        metrics = self._metrics(agent, context, tool_trace, state)
        return GeointEvaluationResult(
            scenario_id=scenario.id,
            scenario_version=scenario.version,
            passed=not failures,
            failures=tuple(failures),
            metrics=metrics,
        )

    # -- group helpers -------------------------------------------------------

    @staticmethod
    def _validate_resolution_coverage(
        expected: ExpectedGeointOutcome, resolution: GeointScenarioResolution
    ) -> None:
        """Resolve every expectation label before any comparison begins.

        The evaluator fails closed on unknown labels even when a comparison
        would never otherwise resolve them, exactly like the analyst
        evaluator contract.
        """
        for outcome in expected.resolutions:
            _resolve_label(resolution.resolution_ids, "resolution", outcome.label)
            if outcome.location is not None:
                _resolve_label(resolution.geography_ids, "geography", outcome.location)
        for current in expected.current:
            _resolve_label(resolution.entity_ids, "entity", current.entity)
            _resolve_label(resolution.geography_ids, "geography", current.location)
        for history in expected.histories:
            _resolve_label(resolution.entity_ids, "entity", history.entity)
            for label in history.locations:
                _resolve_label(resolution.geography_ids, "geography", label)

    def _evaluate_resolutions(
        self,
        expected: ExpectedGeointOutcome,
        resolution: GeointScenarioResolution,
        fixture_resolutions: Mapping[str, GeointFixtureResolution],
        state: GeointGeographicState,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Evaluate every expected resolution outcome in declaration order."""
        by_label = {item.label: item for item in state.resolutions}
        for outcome in expected.resolutions:
            observed = by_label.get(outcome.label)
            if observed is None:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.MISSING_EXPECTED_OBSERVATION,
                        message=(
                            f"expected resolution {outcome.label!r} has no "
                            "observed terminal state"
                        ),
                    )
                )
                continue
            if observed.status != outcome.status:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.WRONG_RESOLUTION_STATUS,
                        message=(
                            f"resolution {outcome.label!r} status "
                            f"{observed.status!r} != expected {outcome.status!r}"
                        ),
                    )
                )
                continue
            if outcome.status == "unresolvable":
                continue
            if observed.observation_id is None:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.MISSING_EXPECTED_OBSERVATION,
                        message=(
                            f"expected resolved resolution {outcome.label!r} "
                            "produced no observation"
                        ),
                    )
                )
                continue
            expected_location = resolution.geography_ids[outcome.location or ""]
            if observed.location_id != expected_location:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.WRONG_CANONICAL_LOCATION,
                        message=(
                            f"resolution {outcome.label!r} resolved to a "
                            "location outside the expected canonical Location"
                        ),
                    )
                )
            if observed.precision != outcome.precision:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.PRECISION_INFLATION,
                        message=(
                            f"resolution {outcome.label!r} precision "
                            f"{observed.precision.value if observed.precision else None!r} "
                            f"!= expected {outcome.precision.value if outcome.precision else None!r}"
                        ),
                    )
                )
            fixture_resolution = fixture_resolutions.get(outcome.label)
            if fixture_resolution is None:  # pragma: no cover
                raise ValueError(
                    f"expected resolution {outcome.label!r} does not name a "
                    "fixture resolution"
                )
            self._check_duplicate_truth(fixture_resolution, resolution, state, failures)

    @staticmethod
    def _check_duplicate_truth(
        fixture_resolution: GeointFixtureResolution,
        resolution: GeointScenarioResolution,
        state: GeointGeographicState,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Reject duplicate observations for one Entity/Evidence pair."""
        entity_id = resolution.entity_ids[fixture_resolution.entity]
        evidence_id = resolution.evidence_ids[fixture_resolution.evidence]
        matches = [
            item
            for item in state.observations
            if item.entity_id == entity_id and item.evidence_id == evidence_id
        ]
        if len(matches) > 1:
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.DUPLICATE_GEOGRAPHIC_TRUTH,
                    message=(
                        f"resolution {fixture_resolution.label!r} produced "
                        f"{len(matches)} observations; exactly one is authoritative"
                    ),
                )
            )

    def _evaluate_current_and_history(
        self,
        expected: ExpectedGeointOutcome,
        resolution: GeointScenarioResolution,
        state: GeointGeographicState,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Evaluate Investigation-relative current and history expectations."""
        current_by_entity = {item.entity_id: item for item in state.current}
        for current in expected.current:
            entity_id = resolution.entity_ids[current.entity]
            observed = current_by_entity.get(entity_id)
            if observed is None:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.WRONG_CURRENT_STATE,
                        message=(
                            f"entity {current.entity!r} has no Investigation-"
                            "relative current state"
                        ),
                    )
                )
                continue
            expected_location = resolution.geography_ids[current.location]
            if (
                observed.location_id != expected_location
                or observed.precision != current.precision
            ):
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.WRONG_CURRENT_STATE,
                        message=(
                            f"entity {current.entity!r} current state does not "
                            "match the expected canonical Location/precision"
                        ),
                    )
                )
        for history in expected.histories:
            entity_id = resolution.entity_ids[history.entity]
            observations = [
                item for item in state.observations if item.entity_id == entity_id
            ]
            ordered = sorted(
                observations,
                key=lambda item: (_effective_time(item), item.observation_id),
                reverse=True,
            )
            expected_labels = history.locations
            if len(ordered) != len(expected_labels):
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.WRONG_HISTORY_ORDER,
                        message=(
                            f"entity {history.entity!r} history has "
                            f"{len(ordered)} observations, expected "
                            f"{len(expected_labels)}"
                        ),
                    )
                )
                continue
            label_by_id = {
                value: key for key, value in resolution.geography_ids.items()
            }
            observed_labels = tuple(
                label_by_id.get(item.location_id) for item in ordered
            )
            if observed_labels != expected_labels:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.WRONG_HISTORY_ORDER,
                        message=(
                            f"entity {history.entity!r} history order "
                            f"{observed_labels!r} != expected {expected_labels!r}"
                        ),
                    )
                )

    @staticmethod
    def _evaluate_state_provenance(
        resolution: GeointScenarioResolution,
        state: GeointGeographicState,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Verify every persisted observation closes to scenario Evidence."""
        scenario_evidence = set(resolution.evidence_ids.values())
        for observation in state.observations:
            if observation.evidence_id not in scenario_evidence:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.WRONG_INVESTIGATION_PROVENANCE,
                        message=(
                            f"observation {observation.observation_id} cites "
                            "Evidence outside the scenario Investigation"
                        ),
                    )
                )

    def _evaluate_tool_and_context(
        self,
        expected: ExpectedGeointOutcome,
        resolution: GeointScenarioResolution,
        context: AnalystGeointContext | None,
        tool_trace: tuple[GeointToolOperationRecord, ...],
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Evaluate the delivered PR 26F tool/context policy deterministically."""
        envelope = expected.agent_context
        allowed = envelope.allowed_operations
        for record in tool_trace:
            if (
                record.operation
                in (
                    GeointToolOperation.PROXIMITY,
                    GeointToolOperation.ARBITRARY_SPATIAL_QUERY,
                )
                or record.operation not in allowed
            ):
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.DISALLOWED_TOOL_OPERATION,
                        message=(
                            f"tool operation {record.operation.value!r} is "
                            "outside the delivered policy"
                        ),
                    )
                )
            if (
                record.operation is GeointToolOperation.HISTORY_FOR_ENTITY
                and record.limit is not None
                and record.limit > envelope.max_observations_per_entity
            ):
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.TOOL_BOUND_EXCEEDED,
                        message=(
                            f"history page limit {record.limit} exceeds the "
                            f"delivered bound {envelope.max_observations_per_entity}"
                        ),
                    )
                )
            if record.cursor_requested:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.CURSOR_DRAINING,
                        message="the analysis facade must never request a cursor",
                    )
                )
        if context is not None:
            scenario_entities = set(resolution.entity_ids.values())
            for entity in context.entities:
                if entity.entity_id not in scenario_entities:
                    failures.append(
                        GeointEvaluationFailure(
                            code=GeointEvaluationFailureCode.UNRELATED_ENTITY_FANOUT,
                            message=(
                                f"context includes entity {entity.entity_id} "
                                "outside the scenario's eligible Entities"
                            ),
                        )
                    )
            for observation_id in _context_observation_ids(context):
                if observation_id not in resolution.observation_ids.values():
                    failures.append(
                        GeointEvaluationFailure(
                            code=GeointEvaluationFailureCode.CROSS_INVESTIGATION_LEAK,
                            message=(
                                f"context includes observation {observation_id} "
                                "outside the scenario Investigation"
                            ),
                        )
                    )
            if len(context.entities) > envelope.max_entities:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.TOOL_BOUND_EXCEEDED,
                        message=(
                            f"context entities {len(context.entities)} exceed "
                            f"the delivered bound {envelope.max_entities}"
                        ),
                    )
                )
            if _context_observation_count(context) > envelope.max_total_observations:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.TOOL_BOUND_EXCEEDED,
                        message=(
                            f"context observations {_context_observation_count(context)} "
                            f"exceed the delivered bound {envelope.max_total_observations}"
                        ),
                    )
                )
            serialized = context.model_dump_json().encode("utf-8")
            if len(serialized) > envelope.max_context_bytes:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.TOOL_BOUND_EXCEEDED,
                        message=(
                            f"serialized context {len(serialized)} bytes exceed "
                            f"the delivered bound {envelope.max_context_bytes}"
                        ),
                    )
                )
            if _context_exposes_coordinates(context):
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.CONTEXT_EXPOSES_COORDINATES,
                        message=(
                            "the model-visible context must never carry "
                            "representative coordinates"
                        ),
                    )
                )
        # has_more_history surfacing: every history page that reported more
        # rows must be surfaced explicitly in the model-visible context.
        for record in tool_trace:
            if record.operation is not GeointToolOperation.HISTORY_FOR_ENTITY:
                continue
            if not record.has_more:
                continue
            if context is None or not any(
                entity.entity_id == record.entity_id and entity.has_more_history
                for entity in context.entities
            ):
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.TRUNCATION_NOT_SURFACED,
                        message=(
                            f"history for entity {record.entity_id} reported "
                            "more rows but the context did not surface "
                            "has_more_history"
                        ),
                    )
                )

    def _evaluate_agent_output(
        self,
        expected: ExpectedGeointOutcome,
        resolution: GeointScenarioResolution,
        state: GeointGeographicState,
        context: AnalystGeointContext | None,
        agent: GeointAgentEvaluationInput,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Evaluate the structured agent output and its runtime fate."""
        envelope = expected.agent_output
        self._evaluate_validation_outcome(envelope, agent, failures)
        self._evaluate_reference_location_support(state, agent, failures)
        decision = agent.decision
        if decision is None:
            return
        context_observation_ids = _context_observation_ids(context)
        contained_ids = set(context.contained_observation_ids) if context else set()
        resolution_observation_ids = set(resolution.observation_ids.values())
        for finding in decision.geographic_findings:
            self._evaluate_finding(
                finding,
                state,
                context_observation_ids,
                resolution_observation_ids,
                contained_ids,
                failures,
            )
        self._evaluate_required_findings(envelope, decision, resolution, failures)
        self._evaluate_forbidden_findings(envelope, decision, resolution, failures)

    @staticmethod
    def _evaluate_reference_location_support(
        state: GeointGeographicState,
        agent: GeointAgentEvaluationInput,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Reject a GEOLOCATION Finding whose Evidence has no observation.

        A canonical Location is reference data, not Evidence; a persisted
        GEOLOCATION Finding must close to an exact observation/Evidence pair
        in the same Investigation. An Evidence id without a persisted
        observation proves the support came from a bare Location/evidence
        row, never a resolved observation.
        """
        if agent.assessment is None:
            return
        observation_evidence = {item.evidence_id for item in state.observations}
        for finding in agent.assessment.findings:
            if finding.category is not FindingCategory.GEOLOCATION:
                continue
            for support in finding.support:
                if (
                    isinstance(support, EvidenceSupport)
                    and support.evidence_id not in observation_evidence
                ):
                    failures.append(
                        GeointEvaluationFailure(
                            code=GeointEvaluationFailureCode.REFERENCE_LOCATION_ONLY_SUPPORT,
                            message=(
                                "GEOLOCATION finding support cites Evidence with "
                                "no persisted observation; a canonical Location "
                                "alone is never analytical support"
                            ),
                        )
                    )

    @staticmethod
    def _evaluate_validation_outcome(
        envelope: ExpectedAgentOutput,
        agent: GeointAgentEvaluationInput,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Compare the expected and observed runtime validation outcomes."""
        expected_validation = envelope.expected_validation
        observed = agent.validation
        if expected_validation is GeointValidationExpectation.ACCEPTED and (
            observed is not GeointValidationOutcome.ACCEPTED
        ):
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.UNEXPECTED_VALIDATION_OUTCOME,
                    message=(
                        "expected the deterministic validator to accept the "
                        "decision but it was rejected"
                    ),
                )
            )
        if expected_validation is GeointValidationExpectation.REJECTED and (
            observed is not GeointValidationOutcome.REJECTED
        ):
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.UNEXPECTED_VALIDATION_OUTCOME,
                    message=(
                        "expected the deterministic validator to reject the "
                        "decision but it was accepted"
                    ),
                )
            )

    def _evaluate_finding(
        self,
        finding: GeographicFinding,
        state: GeointGeographicState,
        context_observation_ids: set[UUID],
        resolution_observation_ids: set[UUID],
        contained_ids: set[UUID],
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Evaluate one geographic finding's structural support and kind."""
        if finding.kind not in _APPROVED_KINDS:
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.UNSUPPORTED_FINDING_KIND,
                    message="geographic finding uses an unsupported kind",
                )
            )
        for observation_id in finding.observation_ids:
            if observation_id not in resolution_observation_ids:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.UNKNOWN_OBSERVATION_CITED,
                        message=(
                            f"geographic finding cites observation "
                            f"{observation_id} outside the scenario"
                        ),
                    )
                )
            elif observation_id not in context_observation_ids:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.OMITTED_CONTEXT_OBSERVATION_CITED,
                        message=(
                            f"geographic finding cites observation "
                            f"{observation_id} that was not supplied in the "
                            "model context"
                        ),
                    )
                )
        observation_by_id = {
            observation.observation_id: observation
            for observation in state.observations
            if observation.observation_id in finding.observation_ids
        }
        for observation_id, evidence_id in zip(
            finding.observation_ids, finding.evidence_ids, strict=True
        ):
            observation = observation_by_id.get(observation_id)
            if observation is None or observation.evidence_id != evidence_id:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.SUBSTITUTED_EVIDENCE,
                        message=(
                            f"geographic finding evidence does not match the "
                            f"cited observation {observation_id}"
                        ),
                    )
                )
        observed_entities = {item.entity_id for item in observation_by_id.values()}
        observed_locations = {item.location_id for item in observation_by_id.values()}
        if (
            finding.kind is GeographicFindingKind.SHARED_LOCATION
            and len(observed_locations) != 1
        ):
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.WRONG_FINDING_LOCATION_SUPPORT,
                    message=(
                        "shared_location observations must share one canonical location"
                    ),
                )
            )
        if (
            finding.kind is GeographicFindingKind.LOCATION_HISTORY
            and len(observed_entities) != 1
        ):
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.WRONG_FINDING_ENTITY_SUPPORT,
                    message=("location_history must span observations of one entity"),
                )
            )
        if set(finding.entity_ids) != observed_entities:
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.WRONG_FINDING_ENTITY_SUPPORT,
                    message=(
                        "geographic finding entity_ids do not match the cited "
                        "observations"
                    ),
                )
            )
        if set(finding.location_ids) != observed_locations:
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.WRONG_FINDING_LOCATION_SUPPORT,
                    message=(
                        "geographic finding location_ids do not match the "
                        "cited observations"
                    ),
                )
            )
        if finding.kind is GeographicFindingKind.LOCATION_CHANGE_OBSERVED:
            if len(observed_locations) < 2:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.INVALID_LOCATION_CHANGE,
                        message=(
                            "location_change_observed requires observations in "
                            "different canonical locations"
                        ),
                    )
                )
            effective_times = {
                _effective_time(item) for item in observation_by_id.values()
            }
            if len(effective_times) < 2:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.INVALID_LOCATION_CHANGE,
                        message=(
                            "location_change_observed requires distinct "
                            "effective observation times"
                        ),
                    )
                )
        if finding.kind is GeographicFindingKind.CONTAINED_LOCATION_CONTEXT and not all(
            observation_id in contained_ids
            for observation_id in finding.observation_ids
        ):
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.UNSUPPORTED_CONTAINMENT,
                    message=(
                        "contained_location_context requires the cited "
                        "observations to have been supplied by a containment "
                        "selection"
                    ),
                )
            )

    @staticmethod
    def _evaluate_required_findings(
        envelope: ExpectedAgentOutput,
        decision: EvidenceAnalystDecision,
        resolution: GeointScenarioResolution,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Evaluate every required geographic finding in declaration order."""
        for expectation in envelope.required_geographic_findings:
            if not any(
                _finding_satisfies(expectation, finding, resolution)
                for finding in decision.geographic_findings
            ):
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.MISSING_REQUIRED_GEOGRAPHIC_FINDING,
                        message=(
                            "required geographic finding missing: "
                            + _expectation_description(expectation)
                        ),
                    )
                )

    @staticmethod
    def _evaluate_forbidden_findings(
        envelope: ExpectedAgentOutput,
        decision: EvidenceAnalystDecision,
        resolution: GeointScenarioResolution,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Evaluate every forbidden geographic finding pattern."""
        for pattern in envelope.forbidden_geographic_findings:
            matched = any(
                _forbidden_pattern_match(pattern, finding, resolution)
                for finding in decision.geographic_findings
            )
            if matched:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.FORBIDDEN_GEOGRAPHIC_FINDING,
                        message=(
                            "forbidden geographic finding present for pattern "
                            + _expectation_description(pattern)
                        ),
                    )
                )

    @staticmethod
    def _evaluate_epistemic_gates(
        expected: ExpectedGeointOutcome,
        state: GeointGeographicState,
        agent: GeointAgentEvaluationInput,
        failures: list[GeointEvaluationFailure],
    ) -> None:
        """Enforce the independent-support gate and geographic Evidence misuse.

        A geographic finding may supplement an Assessment, but geography
        alone cannot support a positive verdict and geographic Evidence can
        never materially support a non-GEOLOCATION finding. Geographic
        Evidence means Evidence that produced a persisted observation (only
        GEOLOCATION rows do), so an independent DNS row is never treated as
        contextual-only. Every declared forbidden inference is mapped onto
        these structural predicates.
        """
        decision = agent.decision
        if decision is None:
            return
        geographic_evidence = {item.evidence_id for item in state.observations}
        material_findings = [
            finding
            for finding in decision.findings
            if finding.category is not FindingCategory.GEOLOCATION
        ]
        geography_only_positive = (
            bool(decision.geographic_findings)
            and decision.verdict is not Verdict.INCONCLUSIVE
            and not material_findings
        )
        if geography_only_positive:
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.GEOGRAPHY_ONLY_VERDICT,
                    message=(
                        "geographic findings alone cannot support a "
                        "non-INCONCLUSIVE verdict"
                    ),
                )
            )
        inference_expressed: set[str] = set()
        for finding in material_findings:
            used_geographic = [
                support.evidence_id
                for support in finding.support
                if isinstance(support, EvidenceSupport)
                and support.evidence_id in geographic_evidence
            ]
            if not used_geographic:
                continue
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.GEOGRAPHIC_EVIDENCE_MISUSED,
                    message=(
                        "geographic Evidence used as material support in "
                        f"{finding.category.value} finding: ["
                        + ",".join(str(item) for item in used_geographic)
                        + "]"
                    ),
                )
            )
            support_ids = {
                support.evidence_id
                for support in finding.support
                if isinstance(support, EvidenceSupport)
            }
            if support_ids <= geographic_evidence:
                failures.append(
                    GeointEvaluationFailure(
                        code=GeointEvaluationFailureCode.UNSUPPORTED_MATERIAL_FINDING,
                        message=(
                            "material finding support is entirely geographic Evidence"
                        ),
                    )
                )
            for code in _MATERIAL_INFERENCE_CODES:
                if code in expected.forbidden_inferences:
                    inference_expressed.add(code.value)
        if (
            GeointForbiddenInference.MALICIOUSNESS in expected.forbidden_inferences
            and geography_only_positive
        ):
            inference_expressed.add(GeointForbiddenInference.MALICIOUSNESS.value)
        if inference_expressed:
            failures.append(
                GeointEvaluationFailure(
                    code=GeointEvaluationFailureCode.FORBIDDEN_INFERENCE_EXPRESSED,
                    message=(
                        "declared forbidden inferences expressed: "
                        + ",".join(sorted(inference_expressed))
                    ),
                )
            )

    @staticmethod
    def _metrics(
        agent: GeointAgentEvaluationInput,
        context: AnalystGeointContext | None,
        tool_trace: tuple[GeointToolOperationRecord, ...],
        state: GeointGeographicState,
    ) -> GeointEvaluationMetrics:
        """Return the deterministic metrics from the same comparisons."""
        decision = agent.decision
        claims = decision.geographic_findings if decision is not None else ()
        persisted_observation_ids = {item.observation_id for item in state.observations}
        supported = sum(
            all(
                observation_id in persisted_observation_ids
                for observation_id in finding.observation_ids
            )
            for finding in claims
        )
        return GeointEvaluationMetrics(
            geographic_claim_count=len(claims),
            supported_geographic_claim_count=supported,
            unsupported_geographic_claim_count=len(claims) - supported,
            tool_call_count=len(tool_trace),
            geoint_context_entity_count=len(context.entities)
            if context is not None
            else 0,
            geoint_context_observation_count=(
                _context_observation_count(context) if context is not None else 0
            ),
            observation_count=len(state.observations),
            resolution_count=len(state.resolutions),
        )


def _effective_time(observation: PersistedGeointObservation) -> datetime:
    """Return the deterministic effective observation time of one snapshot."""
    return effective_observation_time(observation.observed_at, observation.retrieved_at)


def _context_observation_ids(context: AnalystGeointContext | None) -> set[UUID]:
    """Return every observation identity the model-visible context carries."""
    if context is None:
        return set()
    ids: set[UUID] = set()
    for entity in context.entities:
        if entity.current_observation is not None:
            ids.add(entity.current_observation.observation_id)
        ids.update(item.observation_id for item in entity.history)
    return ids


def _context_observation_count(context: AnalystGeointContext | None) -> int:
    """Return the number of observations the context carries."""
    if context is None:
        return 0
    return sum(
        1 + len(entity.history)
        for entity in context.entities
        if entity.current_observation is not None
    )


def _context_exposes_coordinates(context: AnalystGeointContext) -> bool:
    """Return whether the serialized model-visible context carries coordinates.

    The delivered :class:`AnalystGeointLocation` DTO structurally omits
    latitude/longitude; this is a defensive invariant check against the
    serialized payload so representative reference coordinates can never
    become exact source physical position in model context.
    """
    payload = json.loads(context.model_dump_json())
    return _contains_json_key(payload, "latitude") or _contains_json_key(
        payload, "longitude"
    )


def _contains_json_key(value: object, key: str) -> bool:
    """Return whether one JSON value contains the key at any depth."""
    if isinstance(value, dict):
        if key in value:
            return True
        return any(_contains_json_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_json_key(item, key) for item in value)
    return False


def _resolve_label(mapping: Mapping[str, UUID], kind: str, label: str) -> UUID:
    """Resolve one semantic label to its exact persisted UUID or fail closed."""
    value = mapping.get(label)
    if value is None:
        raise ValueError(f"unknown {kind} label in scenario resolution: {label!r}")
    return value


def _finding_satisfies(
    expectation: ExpectedGeographicFinding,
    finding: GeographicFinding,
    resolution: GeointScenarioResolution,
) -> bool:
    """Return whether one geographic finding satisfies one expectation."""
    if expectation.kind is not None and finding.kind is not expectation.kind:
        return False
    if not _labels_satisfied(
        expectation.observation_labels,
        finding.observation_ids,
        resolution.observation_ids,
    ):
        return False
    if not _labels_satisfied(
        expectation.evidence_labels, finding.evidence_ids, resolution.evidence_ids
    ):
        return False
    if not _labels_satisfied(
        expectation.entity_labels, finding.entity_ids, resolution.entity_ids
    ):
        return False
    if not _labels_satisfied(
        expectation.location_labels, finding.location_ids, resolution.geography_ids
    ):
        return False
    return not any(
        _resolve_label(resolution.observation_ids, "observation", label)
        in finding.observation_ids
        for label in expectation.forbidden_observation_labels
    )


def _labels_satisfied(
    labels: Iterable[str],
    actual: Iterable[UUID],
    mapping: Mapping[str, UUID],
) -> bool:
    """Return whether every required label maps into the actual identity set."""
    actual_set = set(actual)
    return all(
        _resolve_label(mapping, "label", label) in actual_set for label in labels
    )


def _forbidden_pattern_match(
    pattern: ForbiddenGeographicFinding,
    finding: GeographicFinding,
    resolution: GeointScenarioResolution,
) -> bool:
    """Return whether one finding matches a forbidden pattern."""
    if pattern.kind is not None and finding.kind is not pattern.kind:
        return False
    if not pattern.observation_labels:
        return True
    return any(
        _resolve_label(resolution.observation_ids, "observation", label)
        in finding.observation_ids
        for label in pattern.observation_labels
    )


def _expectation_description(expectation: object) -> str:
    """Render one expectation deterministically for failure messages."""
    if isinstance(expectation, ForbiddenGeographicFinding):
        forbidden_parts: list[str] = []
        if expectation.kind is not None:
            forbidden_parts.append(f"kind={expectation.kind.value}")
        if expectation.observation_labels:
            forbidden_parts.append(
                "observations=["
                + ",".join(sorted(expectation.observation_labels))
                + "]"
            )
        return " ".join(forbidden_parts)
    if isinstance(expectation, ExpectedGeographicFinding):
        parts: list[str] = []
        if expectation.kind is not None:
            parts.append(f"kind={expectation.kind.value}")
        if expectation.observation_labels:
            parts.append(
                "observations=["
                + ",".join(sorted(expectation.observation_labels))
                + "]"
            )
        if expectation.evidence_labels:
            parts.append(
                "evidence=[" + ",".join(sorted(expectation.evidence_labels)) + "]"
            )
        if expectation.entity_labels:
            parts.append(
                "entities=[" + ",".join(sorted(expectation.entity_labels)) + "]"
            )
        if expectation.location_labels:
            parts.append(
                "locations=[" + ",".join(sorted(expectation.location_labels)) + "]"
            )
        return " ".join(parts)
    return repr(expectation)
