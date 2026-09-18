# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic validation of Evidence Analyst geographic output (PR 26F).

Validation runs after the LLM call and before Assessment persistence. An
immutable validation context is derived from the exact model-supplied
``AnalystGeointContext``; every model-returned geographic reference must be
one of the exact observation/Evidence pairs supplied to that invocation.
Unknown, substituted, cross-scope, or structurally unsupported references
are rejected with :class:`GeographicFindingValidationError`, and no
geographic finding can by itself support a non-INCONCLUSIVE verdict
(independent non-geographic support is required).

The main safeguard is structural: the approved finding kinds are descriptive
only, the temporal interpretation is a closed enum, and geography alone
cannot establish maliciousness, cyber relationship, ownership, campaign,
coordination, targeting, attribution, travel, or route. No fragile
free-text censorship is attempted.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from uuid import UUID

from agentic_threat_investigator.app.query.geoint import effective_observation_time
from agentic_threat_investigator.domain.analyst import (
    AnalystGeointContext,
    AnalystGeointObservation,
    EvidenceAnalystDecision,
    GeographicFinding,
    GeographicFindingKind,
    GeographicTemporalInterpretation,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)

_SHARED_TEMPORAL = frozenset(
    {
        GeographicTemporalInterpretation.NONE,
        GeographicTemporalInterpretation.SAME_OBSERVATION_WINDOW,
        GeographicTemporalInterpretation.DIFFERENT_OBSERVATION_TIMES,
    }
)
"""Temporal interpretations permitted for non-Entity-change findings."""

_ALL_TEMPORAL = frozenset(GeographicTemporalInterpretation)
"""Every approved temporal interpretation (Entity history context)."""


class GeographicFindingValidationError(ValueError):
    """A model-returned geographic finding is unsupported or invalid.

    Deterministic rejection happens before Assessment persistence; failed
    geographic validation never triggers an unbounded model loop.
    """


class _ValidationObservation:
    """One exact supplied observation with its immutable provenance."""

    def __init__(self, observation: AnalystGeointObservation) -> None:
        """Bind the observation and its exact provenance fields."""
        self.observation_id = observation.observation_id
        self.observation = observation


class GeointFindingValidationContext:
    """Immutable validation inputs derived only from the supplied context.

    The context captures exactly the observations the model could have seen:
    there is no persistence read and no cross-Investigation lookup, so a
    reference to any other resource is indistinguishable from an unknown one
    and is rejected.
    """

    def __init__(self, context: AnalystGeointContext | None) -> None:
        """Index the supplied observations and containment tags."""
        observations: dict[UUID, _ValidationObservation] = {}
        contained: set[UUID] = set()
        if context is not None:
            contained = set(context.contained_observation_ids)
            for entity in context.entities:
                candidates: list[AnalystGeointObservation] = list(entity.history)
                if entity.current_observation is not None:
                    candidates.append(entity.current_observation)
                for observation in candidates:
                    observations.setdefault(
                        observation.observation_id,
                        _ValidationObservation(observation),
                    )
        self._observations: Mapping[UUID, _ValidationObservation] = MappingProxyType(
            observations
        )
        self._contained = frozenset(contained)

    def observation(self, observation_id: UUID) -> _ValidationObservation | None:
        """Return the exact supplied observation, or ``None`` when unknown."""
        return self._observations.get(observation_id)

    def is_contained(self, observation_id: UUID) -> bool:
        """Return whether one supplied observation was containment-selected."""
        return observation_id in self._contained


class GeointFindingValidator:
    """Deterministic validation of the decision's geographic findings.

    No provider, network, dispatcher, or LLM call is ever performed; the
    validator operates exclusively on its immutable context and the typed
    decision.
    """

    def __init__(self, context: AnalystGeointContext | None) -> None:
        """Bind the immutable validation context."""
        self._context = GeointFindingValidationContext(context)

    def validate(self, decision: EvidenceAnalystDecision) -> None:
        """Validate every geographic finding and the independent-support gate.

        Raises the first typed :class:`GeographicFindingValidationError`
        instead of collecting failures, so a failed candidate Assessment is
        rejected deterministically and no pointer is updated.
        """
        for finding in decision.geographic_findings:
            self._validate_finding(finding)
        self._validate_independent_support(decision)

    def _validate_finding(self, finding: GeographicFinding) -> None:
        """Validate one geographic finding against the supplied context."""
        known: list[_ValidationObservation] = []
        for observation_id in finding.observation_ids:
            observation = self._context.observation(observation_id)
            if observation is None:
                raise GeographicFindingValidationError(
                    f"geographic finding cites unknown or omitted observation: "
                    f"{observation_id}"
                )
            known.append(observation)

        for observation_id, evidence_observation_id in zip(
            finding.observation_ids,
            finding.evidence_observation_ids,
            strict=True,
        ):
            observation = self._context.observation(observation_id)
            if (
                observation is None
                or observation.observation.evidence_observation_id
                != evidence_observation_id
            ):
                raise GeographicFindingValidationError(
                    f"geographic finding evidence does not match the cited "
                    f"observation: {observation_id}"
                )

        observed_entities = {observation.observation.entity_id for observation in known}
        observed_locations = {
            observation.observation.location.location_id for observation in known
        }
        if set(finding.entity_ids) != observed_entities:
            raise GeographicFindingValidationError(
                "geographic finding entity_ids do not match the cited observations"
            )
        if set(finding.location_ids) != observed_locations:
            raise GeographicFindingValidationError(
                "geographic finding location_ids do not match the cited observations"
            )

        self._validate_kind(finding, known, observed_entities, observed_locations)
        self._validate_temporal(finding)

    def _validate_kind(
        self,
        finding: GeographicFinding,
        known: list[_ValidationObservation],
        observed_entities: set[UUID],
        observed_locations: set[UUID],
    ) -> None:
        """Enforce the descriptive structural semantics of each finding kind.

        Validation is structural only: no free-text censorship is performed,
        and sequential observations can never establish movement or travel.
        """
        kind = finding.kind
        if kind is GeographicFindingKind.SHARED_LOCATION:
            if len(observed_locations) != 1:
                raise GeographicFindingValidationError(
                    "shared_location observations must share one canonical location"
                )
        elif kind is GeographicFindingKind.LOCATION_HISTORY:
            if len(known) < 2:
                raise GeographicFindingValidationError(
                    "location_history requires at least two observations"
                )
            if len(observed_entities) != 1:
                raise GeographicFindingValidationError(
                    "location_history must span observations of one entity"
                )
        elif kind is GeographicFindingKind.LOCATION_CHANGE_OBSERVED:
            if len(known) < 2:
                raise GeographicFindingValidationError(
                    "location_change_observed requires at least two observations"
                )
            if len(observed_entities) != 1:
                raise GeographicFindingValidationError(
                    "location_change_observed must span observations of one entity"
                )
            if len(observed_locations) < 2:
                raise GeographicFindingValidationError(
                    "location_change_observed requires observations in different "
                    "canonical locations"
                )
            effective_times = {
                effective_observation_time(
                    observation.observation.observed_at,
                    observation.observation.retrieved_at,
                )
                for observation in known
            }
            if len(effective_times) < 2:
                raise GeographicFindingValidationError(
                    "location_change_observed requires distinct effective "
                    "observation times"
                )
        elif kind is GeographicFindingKind.GEOGRAPHIC_DISTRIBUTION:
            if len(observed_locations) < 2:
                raise GeographicFindingValidationError(
                    "geographic_distribution requires observations in at least "
                    "two distinct canonical locations"
                )
        elif kind is GeographicFindingKind.CONTAINED_LOCATION_CONTEXT and not all(
            self._context.is_contained(observation_id)
            for observation_id in finding.observation_ids
        ):
            raise GeographicFindingValidationError(
                "contained_location_context requires the cited observations "
                "to have been supplied by a containment selection"
            )

    @staticmethod
    def _validate_temporal(finding: GeographicFinding) -> None:
        """Enforce the closed temporal interpretation per finding kind."""
        kind = finding.kind
        temporal = finding.temporal_interpretation
        if kind is GeographicFindingKind.LOCATION_CHANGE_OBSERVED:
            if (
                temporal
                is not GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED
            ):
                raise GeographicFindingValidationError(
                    "location_change_observed findings require the "
                    "location_change_observed temporal interpretation"
                )
        elif kind is GeographicFindingKind.LOCATION_HISTORY:
            if temporal not in _ALL_TEMPORAL:
                raise GeographicFindingValidationError(
                    "location_history temporal interpretation is outside the "
                    "approved vocabulary"
                )
        elif temporal not in _SHARED_TEMPORAL:
            raise GeographicFindingValidationError(
                "geographic finding temporal interpretation is outside the "
                "approved vocabulary for its kind"
            )

    def _validate_independent_support(self, decision: EvidenceAnalystDecision) -> None:
        """Require independent non-geographic support for positive verdicts.

        A geographic finding may supplement an Assessment, but geography
        alone cannot support a malicious/positive verdict: a non-INCONCLUSIVE
        verdict with geographic findings requires at least one material
        Finding outside the geographic category, otherwise the candidate
        Assessment is rejected conservatively.
        """
        if not decision.geographic_findings:
            return
        if decision.verdict is Verdict.INCONCLUSIVE:
            return
        if any(
            finding.category is not FindingCategory.GEOLOCATION
            for finding in decision.findings
        ):
            return
        raise GeographicFindingValidationError(
            "geographic findings alone cannot support a non-INCONCLUSIVE verdict"
        )


def map_geographic_findings(
    decision: EvidenceAnalystDecision,
) -> tuple[AnalyticalFinding, ...]:
    """Map validated geographic findings onto existing GEOLOCATION Findings.

    Durable Assessment support remains the exact existing Evidence referenced
    by each observation (``EvidenceSupport``); observation identities are
    validated analysis-time traceability only. PR 26F introduces zero new
    geographic persistence, so the exact ``EntityLocationObservation`` IDs
    are not durably stored (the current Assessment schema has no
    geography-specific structured field) and are never hidden in prose.
    """
    if not decision.geographic_findings:
        return decision.findings
    mapped = tuple(
        AnalyticalFinding(
            category=FindingCategory.GEOLOCATION,
            disposition=FindingDisposition.SUPPORTING,
            statement=finding.statement,
            confidence=_mapped_confidence(decision.confidence),
            support=tuple(
                EvidenceSupport(kind="evidence", evidence_id=evidence_observation_id)
                for evidence_observation_id in finding.evidence_observation_ids
            ),
        )
        for finding in decision.geographic_findings
    )
    return decision.findings + mapped


def _mapped_confidence(confidence: AssessmentConfidence) -> AssessmentConfidence:
    """Return the Assessment confidence carried onto mapped geographic Findings.

    The mapped Finding reuses the decision's confidence: Findings express
    confidence in the Assessment verdict, and the independent-support gate
    already prevents geographic findings from raising a verdict without
    independent non-geographic support.
    """
    return confidence
