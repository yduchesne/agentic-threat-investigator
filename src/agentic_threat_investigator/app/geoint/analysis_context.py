# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic selection of one bounded GEOINT analysis context (PR 26F).

The policy---never the model---chooses which Investigation-scoped GEOINT
facts enter one Evidence Analyst invocation: the bounded summary first, then
Investigation-relative current context and one bounded history page for each
eligible Entity already present in the Evidence Analyst's authoritative
input. There is no automatic fan-out from top Locations to Entities, no
automatic contained expansion, no proximity query, and no cursor draining.

The policy is pure and deterministic: the same persisted investigation state
(already normalized into one ``EvidenceAnalystInput``) always yields the
same ``AnalystGeointContext``. Aggregate bounds fail closed with typed
errors before any model call.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from agentic_threat_investigator.app.geoint.analysis_tools import (
    GeointAnalysisTools,
)
from agentic_threat_investigator.app.geoint.errors import (
    GeointAnalysisInputBoundsError,
    GeointObservationEvidenceError,
)
from agentic_threat_investigator.app.query.geoint import (
    GeointEntityLocationItem,
    GeointLocationRef,
    GeointObservationItem,
    GeointSummary,
    GeointTopLocation,
)
from agentic_threat_investigator.domain.analyst import (
    AnalystEntityGeointContext,
    AnalystGeointContext,
    AnalystGeointLocation,
    AnalystGeointObservation,
    AnalystGeointPrecisionCounts,
    AnalystGeointSummary,
    AnalystGeointTopLocation,
    EvidenceAnalystInput,
)

_MAX_ENTITIES_CEILING = 200
_MAX_OBSERVATIONS_PER_ENTITY_CEILING = 200
_MAX_TOTAL_OBSERVATIONS_CEILING = 1000
_MAX_CONTEXT_BYTES_FLOOR = 1000
_MAX_CONTEXT_BYTES_CEILING = 1_000_000

_BOUND_ENTITIES = "max_entities"
_BOUND_TOTAL_OBSERVATIONS = "max_total_observations"
_BOUND_SERIALIZED_BYTES = "serialized_context_bytes"


def _eligible_entity_ids(analyst_input: EvidenceAnalystInput) -> list[UUID]:
    """Return the deterministic eligible Entity order of the analyst input.

    The order preserves the Evidence Analyst's authoritative ordering: root
    Entities first, then Evidence subjects, then RelationshipObservation
    endpoints, each deduplicated while keeping first appearance. Python set
    iteration never determines context order.
    """
    ordered: list[UUID] = []
    seen: set[UUID] = set()

    def add(entity_id: UUID) -> None:
        """Append one Entity identity if not already present."""
        if entity_id in seen:
            return
        seen.add(entity_id)
        ordered.append(entity_id)

    for entity in analyst_input.root_entities:
        add(entity.entity_id)
    for item in analyst_input.evidence:
        add(item.subject.entity_id)
    for observation in analyst_input.relationship_observations:
        add(observation.source_entity.entity_id)
        add(observation.target_entity.entity_id)
    return ordered


def _analyst_location(reference: GeointLocationRef) -> AnalystGeointLocation:
    """Map one canonical Location reference, omitting representative coordinates."""
    return AnalystGeointLocation(
        location_id=reference.location_id,
        location_type=reference.location_type,
        canonical_location_name=reference.canonical_name,
        country_code=reference.country_code,
        admin1_code=reference.admin1_code,
        admin2_code=reference.admin2_code,
        parent_location_id=reference.parent_location_id,
    )


def _analyst_observation(item: GeointObservationItem) -> AnalystGeointObservation:
    """Map one Investigation-scoped observation onto the model-visible DTO."""
    return AnalystGeointObservation(
        observation_id=item.observation_id,
        entity_id=item.entity_id,
        evidence_id=item.evidence_id,
        location=_analyst_location(item.location),
        precision=item.precision,
        resolution_method=item.resolution_method,
        observed_at=item.observed_at,
        retrieved_at=item.retrieved_at,
        resolved_at=item.resolved_at,
    )


def _analyst_top_location(item: GeointTopLocation) -> AnalystGeointTopLocation:
    """Map one bounded summary top-location group onto the model-visible DTO."""
    return AnalystGeointTopLocation(
        location=_analyst_location(item.location),
        scoped_entity_count=item.scoped_entity_count,
    )


def _analyst_summary(summary: GeointSummary) -> AnalystGeointSummary:
    """Map the bounded PR 26D summary onto the model-visible DTO."""
    return AnalystGeointSummary(
        entity_count_with_location=summary.entity_count_with_location,
        observation_count=summary.observation_count,
        location_count=summary.location_count,
        country_count=summary.country_count,
        administrative_area_count=summary.administrative_area_count,
        city_count=summary.city_count,
        precision_counts=AnalystGeointPrecisionCounts(
            country=summary.precision_counts.country,
            administrative_area=summary.precision_counts.administrative_area,
            city=summary.precision_counts.city,
        ),
        top_locations=tuple(
            _analyst_top_location(item) for item in summary.top_locations
        ),
        truncated=summary.truncated,
    )


class GeointAnalysisContextPolicy:
    """Deterministically select one bounded GEOINT context for the analyst.

    The context selection is fully deterministic and bound-checked: eligible
    Entities come only from the already-loaded analyst input, each eligible
    Entity contributes its Investigation-relative current observation plus
    one bounded history page, and the aggregate observation and serialized
    byte bounds fail with :class:`GeointAnalysisInputBoundsError` instead of
    silently dropping items. The v0.1 policy never performs Location
    fan-out, contained expansion, or proximity queries, so no observation is
    ever tagged as containment-supplied.
    """

    def __init__(
        self,
        *,
        max_entities: int = 10,
        max_observations_per_entity: int = 5,
        max_total_observations: int = 50,
        max_context_bytes: int = 262_144,
    ) -> None:
        """Bind the explicit aggregate context bounds.

        Hard ceilings mirror the ``Settings`` validators so direct
        construction cannot bypass the configured safety ceilings, and the
        aggregate observation bound must be reachable from the entity and
        per-entity bounds.
        """
        if not 1 <= max_entities <= _MAX_ENTITIES_CEILING:
            raise ValueError(
                f"max_entities must be in the range 1..{_MAX_ENTITIES_CEILING}"
            )
        if not (
            1 <= max_observations_per_entity <= _MAX_OBSERVATIONS_PER_ENTITY_CEILING
        ):
            raise ValueError(
                "max_observations_per_entity must be in the range 1.."
                f"{_MAX_OBSERVATIONS_PER_ENTITY_CEILING}"
            )
        if not 1 <= max_total_observations <= _MAX_TOTAL_OBSERVATIONS_CEILING:
            raise ValueError(
                "max_total_observations must be in the range 1.."
                f"{_MAX_TOTAL_OBSERVATIONS_CEILING}"
            )
        if (
            not _MAX_CONTEXT_BYTES_FLOOR
            <= max_context_bytes
            <= _MAX_CONTEXT_BYTES_CEILING
        ):
            raise ValueError(
                "max_context_bytes must be in the range "
                f"{_MAX_CONTEXT_BYTES_FLOOR}..{_MAX_CONTEXT_BYTES_CEILING}"
            )
        self._max_entities = max_entities
        self._max_observations_per_entity = max_observations_per_entity
        self._max_total_observations = max_total_observations
        self._max_context_bytes = max_context_bytes

    async def select(
        self, analyst_input: EvidenceAnalystInput, tools: GeointAnalysisTools
    ) -> AnalystGeointContext:
        """Return the bounded model-visible GEOINT context for one invocation.

        ``analyst_input`` is the already-loaded authoritative Evidence
        Analyst input; the policy never interprets arbitrary model text.
        Every supplied observation preserves its exact ``observation_id``
        and ``evidence_id``, and every observation's Evidence must already
        be part of the analyst input or the context fails closed.
        """
        investigation_id = analyst_input.investigation_id
        summary = await tools.summary(investigation_id)

        eligible = _eligible_entity_ids(analyst_input)
        if len(eligible) > self._max_entities:
            raise GeointAnalysisInputBoundsError(
                _BOUND_ENTITIES, self._max_entities, len(eligible)
            )

        evidence_ids = {item.evidence_id for item in analyst_input.evidence}
        entity_contexts: list[AnalystEntityGeointContext] = []
        total_observations = 0
        for entity_id in eligible:
            current = await tools.current_for_entity(investigation_id, entity_id)
            if current is None:
                continue
            history_result = await tools.history_for_entity(
                investigation_id,
                entity_id,
                limit=self._max_observations_per_entity,
            )
            observations = self._observations_for_entity(
                current, history_result.items, evidence_ids
            )
            current_observation, history = observations
            total_observations += 1 + len(history)
            if total_observations > self._max_total_observations:
                raise GeointAnalysisInputBoundsError(
                    _BOUND_TOTAL_OBSERVATIONS,
                    self._max_total_observations,
                    total_observations,
                )
            entity_contexts.append(
                AnalystEntityGeointContext(
                    entity_id=entity_id,
                    entity_type=current.entity_type,
                    entity_value=current.entity_value,
                    current_observation=current_observation,
                    history=history,
                    has_more_history=history_result.has_more,
                )
            )

        context = AnalystGeointContext(
            summary=_analyst_summary(summary),
            entities=tuple(entity_contexts),
            # The v0.1 policy never performs contained Location expansion, so
            # no supplied observation is ever containment-tagged; validator
            # assertions of contained context therefore fail closed.
            contained_observation_ids=(),
        )
        serialized = context.model_dump_json().encode("utf-8")
        if len(serialized) > self._max_context_bytes:
            raise GeointAnalysisInputBoundsError(
                _BOUND_SERIALIZED_BYTES,
                self._max_context_bytes,
                len(serialized),
            )
        return context

    @staticmethod
    def _observations_for_entity(
        current: GeointEntityLocationItem,
        history_items: tuple[GeointObservationItem, ...],
        evidence_ids: set[UUID],
    ) -> tuple[AnalystGeointObservation, tuple[AnalystGeointObservation, ...]]:
        """Return the current observation and its strictly-older history DTOs.

        ``current`` is the Investigation-relative current observation and
        ``history_items`` the one bounded first page (newest-first, already
        containing the current observation in normal operation). The returned
        history excludes the current observation so the model-visible context
        never duplicates an observation, and every returned observation fails
        closed when its Evidence is missing from the analyst input.
        """
        current_dto = _analyst_observation(current.current_observation)
        history: list[AnalystGeointObservation] = []
        seen: set[UUID] = set()
        for item in history_items:
            if item.observation_id in seen:
                continue
            if item.observation_id == current_dto.observation_id:
                seen.add(item.observation_id)
                continue
            seen.add(item.observation_id)
            history.append(_analyst_observation(item))
        for observation in (*history, current_dto):
            if observation.evidence_id not in evidence_ids:
                raise GeointObservationEvidenceError(
                    observation.observation_id, observation.evidence_id
                )
        return current_dto, tuple(history)


class GeointAnalystContextLoader:
    """Load the bounded GEOINT context with a short-lived tools scope (PR 26F).

    The composition calls :meth:`load` with the already-loaded analyst input
    (the loader's short read-only UnitOfWork has already closed), opens one
    bounded tools scope, runs the deterministic policy, and always closes the
    tools scope before returning---so no database transaction or session is
    ever held across the Evidence Analyst's LLM accounting or model I/O.
    """

    def __init__(
        self,
        tools_factory: Callable[[], GeointAnalysisTools],
        policy: GeointAnalysisContextPolicy,
    ) -> None:
        """Bind the tools factory and the deterministic context policy."""
        self._tools_factory = tools_factory
        self._policy = policy

    async def load(
        self,
        investigation_id: UUID,
        analyst_input: EvidenceAnalystInput,
    ) -> AnalystGeointContext:
        """Load the bounded context, closing the tools scope in all cases."""
        if analyst_input.investigation_id != investigation_id:
            raise ValueError(
                "geoint context analyst input does not match the "
                "requested investigation"
            )
        tools = self._tools_factory()
        try:
            return await self._policy.select(analyst_input, tools)
        finally:
            await tools.aclose()
