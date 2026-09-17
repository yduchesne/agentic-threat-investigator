# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic assembly of the Evidence Analyst input (PR 28B).

The loader runs one short, read-only UnitOfWork against persisted
authoritative resources only, then closes the transaction before the caller
may invoke the LLM. Input ordering and bounds are deterministic: the same
persisted investigation state always yields the same
:class:`~agentic_threat_investigator.domain.analyst.EvidenceAnalystInput`.

Evidence items identify exact admitted EvidenceObservations (never stable
global Evidence identity) and carry the deterministic bounded tuple of
Entities associated with the exact observation instead of a privileged
subject. Every model-visible RelationshipObservation is backed by an
EvidenceObservation in the exact admitted analyst Evidence set.

When a :class:`GeointAnalystContextLoader` is injected (PR 26F), the plain
analyst input is loaded and its UnitOfWork closed, then the bounded GEOINT
analysis context is loaded through the existing PR 26D ``GeointQueryService``
beyond any open write transaction. No geographic observations remain a
normal case: an empty or absent context changes no pre-26F behavior.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from uuid import UUID

from agentic_threat_investigator.app.evidence_analyst.errors import (
    EvidenceAnalystInputBoundsError,
)
from agentic_threat_investigator.app.geoint.analysis_context import (
    GeointAnalystContextLoader,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    UnitOfWork,
)
from agentic_threat_investigator.domain.analyst import (
    AnalystEntity,
    AnalystEvidenceItem,
    AnalystRelationshipObservation,
    EvidenceAnalystInput,
)
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import (
    Evidence,
    EvidenceObservation,
)
from agentic_threat_investigator.domain.relationships import Relationship

_BOUND_EVIDENCE = "evidence_items"
_BOUND_OBSERVATIONS = "relationship_observations"
_BOUND_NORMALIZED_FACTS = "normalized_facts"
_BOUND_SERIALIZED = "serialized_input"

# Hard constructor ceilings mirroring the Settings validators so a direct
# caller cannot bypass the configured safety ceilings.
_MAX_EVIDENCE_ITEMS_CEILING = 500
_MAX_RELATIONSHIP_OBSERVATIONS_CEILING = 1000
_MAX_INPUT_BYTES_CEILING = 1_000_000
_MAX_INPUT_BYTES_FLOOR = 1000


def _normalized_facts_bytes(observation: EvidenceObservation) -> int:
    """Return the UTF-8 byte size of one observation's normalized facts.

    Only the normalized ``facts`` mapping is serialized in deterministic JSON
    form; ``raw_payload`` is never inspected or included.
    """
    payload = json.dumps(
        observation.facts,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return len(payload.encode("utf-8"))


def _analyst_entity(entity: Entity) -> AnalystEntity:
    """Map a persisted canonical Entity to its analyst view."""
    if entity.id is None:  # pragma: no cover - persisted rows carry an id
        raise ValueError("persisted entity has no identity")
    return AnalystEntity(
        entity_id=entity.id,
        entity_type=entity.type,
        value=entity.value,
    )


class EvidenceAnalystInputLoader:
    """Assemble the immutable, bounded analyst input for one Investigation.

    ``max_evidence_items``, ``max_relationship_observations``,
    ``max_normalized_facts_bytes``, and ``max_input_bytes`` are the explicit
    context bounds; an oversize input raises
    :class:`EvidenceAnalystInputBoundsError` before any model call. Hard
    ceilings mirror the ``Settings`` validators so direct construction cannot
    bypass them. ``geoint_context_loader`` (PR 26F) optionally extends the
    input with the bounded GEOINT analysis context after the read-only
    UnitOfWork has closed.
    """

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        *,
        max_evidence_items: int = 100,
        max_relationship_observations: int = 200,
        max_normalized_facts_bytes: int = 131_072,
        max_input_bytes: int = 262_144,
        geoint_context_loader: GeointAnalystContextLoader | None = None,
    ) -> None:
        """Bind the UnitOfWork factory and the explicit context bounds.

        ``geoint_context_loader`` optionally extends the loaded input with
        the bounded GEOINT analysis context (PR 26F). When it is ``None`` the
        loader keeps the pre-26F behavior exactly: no GEOINT context is
        loaded and the input carries ``geoint_context=None``.
        """
        if not 1 <= max_evidence_items <= _MAX_EVIDENCE_ITEMS_CEILING:
            raise ValueError(
                "max_evidence_items must be in the range "
                f"1..{_MAX_EVIDENCE_ITEMS_CEILING}"
            )
        if (
            not 1
            <= max_relationship_observations
            <= _MAX_RELATIONSHIP_OBSERVATIONS_CEILING
        ):
            raise ValueError(
                "max_relationship_observations must be in the range "
                f"1..{_MAX_RELATIONSHIP_OBSERVATIONS_CEILING}"
            )
        if not _MAX_INPUT_BYTES_FLOOR <= max_input_bytes <= _MAX_INPUT_BYTES_CEILING:
            raise ValueError(
                "max_input_bytes must be in the range "
                f"{_MAX_INPUT_BYTES_FLOOR}..{_MAX_INPUT_BYTES_CEILING}"
            )
        if not 1_000 <= max_normalized_facts_bytes <= 1_000_000:
            raise ValueError(
                "max_normalized_facts_bytes must be in the range 1000..1000000"
            )
        self._uow_factory = uow_factory
        self._max_evidence_items = max_evidence_items
        self._max_relationship_observations = max_relationship_observations
        self._max_normalized_facts_bytes = max_normalized_facts_bytes
        self._max_input_bytes = max_input_bytes
        self._geoint_context_loader = geoint_context_loader

    async def load(self, investigation_id: UUID) -> EvidenceAnalystInput:
        """Load the bounded input in one read-only UnitOfWork.

        The UnitOfWork is closed before the returned input escapes and the
        optional bounded GEOINT context is loaded only after that close, so
        no transaction is ever left open across LLM latency.
        """
        async with self._uow_factory() as uow:
            analyst_input = await self._load_in_transaction(uow, investigation_id)
        if self._geoint_context_loader is None or not analyst_input.evidence:
            return analyst_input
        geoint_context = await self._geoint_context_loader.load(
            investigation_id, analyst_input
        )
        return analyst_input.model_copy(update={"geoint_context": geoint_context})

    async def _load_in_transaction(
        self, uow: UnitOfWork, investigation_id: UUID
    ) -> EvidenceAnalystInput:
        """Assemble the input while the read-only transaction is open."""
        # Loading several correlated resource maps in one loop per resource is
        # intrinsic; the branch/local counts reflect that shape.
        investigation = await uow.investigations.get_by_id(investigation_id)
        if investigation is None:
            raise InvestigationNotFoundError(str(investigation_id))

        observation_rows = await uow.evidence.list_for_investigation(
            investigation_id, limit=self._max_evidence_items + 1
        )
        if len(observation_rows) > self._max_evidence_items:
            raise EvidenceAnalystInputBoundsError(
                _BOUND_EVIDENCE,
                self._max_evidence_items,
                len(observation_rows),
            )
        observation_rows = observation_rows[: self._max_evidence_items]

        observation_meta: dict[UUID, Evidence] = {}
        for observation_row in observation_rows:
            evidence = await uow.evidence.get_stable_evidence(
                observation_row.evidence_id
            )
            if evidence is not None:
                observation_meta[observation_row.id] = evidence

        relationship_rows = await uow.relationship_observations.list_for_investigation(
            investigation_id, limit=self._max_relationship_observations + 1
        )
        if len(relationship_rows) > self._max_relationship_observations:
            raise EvidenceAnalystInputBoundsError(
                _BOUND_OBSERVATIONS,
                self._max_relationship_observations,
                len(relationship_rows),
            )
        relationship_rows = relationship_rows[: self._max_relationship_observations]

        # Resolve the stable Relationships and endpoint Entities referenced by
        # the eligible observations. A missing or soft-deleted Relationship or
        # endpoint Entity makes the whole observation ineligible: it is omitted
        # consistently (matching the PR 20A validator's fail-closed posture,
        # which would reject any citation to it).
        relationships: dict[UUID, Relationship] = {}
        pending_relationship_ids = {
            observation.relationship_id for observation in relationship_rows
        }
        for relationship_id in pending_relationship_ids:
            relationship = await uow.relationships.get_by_id(relationship_id)
            if relationship is not None:
                relationships[relationship_id] = relationship

        pending_entity_ids = set(investigation.root_entity_ids)
        for relationship in relationships.values():
            pending_entity_ids.add(relationship.source_entity_id)
            pending_entity_ids.add(relationship.target_entity_id)
        # Associated Entities of the exact admitted observations (PR 28B):
        # the analyst views the deterministic associated set, never a
        # privileged subject.
        for observation_row in observation_rows:
            for (
                association
            ) in await uow.evidence_observation_entities.list_for_observation(
                observation_row.id
            ):
                pending_entity_ids.add(association.entity_id)
        entities: dict[UUID, Entity] = {}
        for entity_id in pending_entity_ids:
            entity = await uow.entities.get_by_id(entity_id)
            if entity is not None:
                entities[entity_id] = entity

        root_entities = tuple(
            _analyst_entity(entities[entity_id])
            for entity_id in _deduplicate(investigation.root_entity_ids)
            if entity_id in entities
        )

        built_items: list[AnalystEvidenceItem] = []
        for observation in observation_rows:
            built_items.append(
                await self._build_evidence_item(
                    uow, observation, observation_meta, entities
                )
            )
        evidence_items = tuple(built_items)
        # Independently bound the aggregate normalized-facts size: only each
        # observation's ``facts`` mapping is serialized (deterministic JSON,
        # UTF-8 byte counts); ``raw_payload`` is never inspected.
        facts_bytes = sum(
            _normalized_facts_bytes(observation) for observation in observation_rows
        )
        if facts_bytes > self._max_normalized_facts_bytes:
            raise EvidenceAnalystInputBoundsError(
                _BOUND_NORMALIZED_FACTS,
                self._max_normalized_facts_bytes,
                facts_bytes,
            )

        observations: list[AnalystRelationshipObservation] = []
        for relationship_observation in relationship_rows:
            relationship = relationships.get(relationship_observation.relationship_id)
            if relationship is None:
                continue
            source_entity = entities.get(relationship.source_entity_id)
            target_entity = entities.get(relationship.target_entity_id)
            if source_entity is None or target_entity is None:
                continue
            observations.append(
                AnalystRelationshipObservation(
                    relationship_observation_id=relationship_observation.id,
                    evidence_observation_id=(
                        relationship_observation.evidence_observation_id
                    ),
                    relationship_id=relationship_observation.relationship_id,
                    relationship_type=relationship.type,
                    source_entity=_analyst_entity(source_entity),
                    target_entity=_analyst_entity(target_entity),
                    observed_at=relationship_observation.observed_at,
                    retrieved_at=relationship_observation.retrieved_at,
                    source=relationship_observation.source,
                    confidence=relationship_observation.confidence,
                )
            )

        analyst_input = EvidenceAnalystInput(
            investigation_id=investigation_id,
            objective=investigation.objective,
            root_entities=root_entities,
            evidence=evidence_items,
            relationship_observations=tuple(observations),
        )
        serialized = analyst_input.model_dump_json().encode("utf-8")
        if len(serialized) > self._max_input_bytes:
            raise EvidenceAnalystInputBoundsError(
                _BOUND_SERIALIZED,
                self._max_input_bytes,
                len(serialized),
            )
        return analyst_input

    async def _build_evidence_item(
        self,
        uow: UnitOfWork,
        observation: EvidenceObservation,
        evidence_by_observation: dict[UUID, Evidence],
        entities: dict[UUID, Entity],
    ) -> AnalystEvidenceItem:
        """Map one exact admitted observation to its minimized analyst view."""
        evidence = evidence_by_observation.get(observation.id)
        if evidence is None:  # pragma: no cover - observation rows are admitted
            raise ValueError("admitted observation has no stable evidence")
        associated_ids = tuple(
            association.entity_id
            for association in await uow.evidence_observation_entities.list_for_observation(
                observation.id
            )
        )
        associated = tuple(
            entity
            for entity_id in associated_ids
            if (entity := entities.get(entity_id)) is not None
        )
        return AnalystEvidenceItem(
            evidence_observation_id=observation.id,
            type=evidence.type,
            entities=tuple(_analyst_entity(entity) for entity in associated),
            source=evidence.source,
            source_record_id=evidence.source_record_id,
            observed_at=observation.observed_at,
            retrieved_at=observation.retrieved_at,
            facts=observation.facts,
        )


def _deduplicate(values: list[UUID]) -> list[UUID]:
    """Return the values in order with duplicates removed."""
    seen: set[UUID] = set()
    result: list[UUID] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
