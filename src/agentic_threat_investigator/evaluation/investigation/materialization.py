# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end Investigation scenario materialization (PR 30F).

Materialization persists only the **minimum production-valid initial state**:
the canonical root Entity and a RUNNING Investigation with its initial
traversal metadata and budget. Providers/extractors discover every other
entity during the real run; nothing is pre-created. The Investigation
identity is execution-scoped (``uuid5`` over the scenario id plus the
execution id), so repeated runs of one scenario stay isolated and never
collide on canonical Entity identities.

After the run, :meth:`InvestigationScenarioMaterializer.resolve_persisted`
maps every fixture-declared semantic label to its exact persisted canonical
Entity identity (roots and provider-discovered entities alike) through the
normal repository read seam, failing closed on any missing label.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid5

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.investigation import (
    EntityTraversalStateBuilder,
    InvestigationBudget,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.evaluation.investigation.fixtures import (
    InvestigationFixture,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    InvestigationScenario,
    InvestigationScenarioResolution,
)

_FIXED_STARTED_AT = datetime(2026, 6, 15, tzinfo=UTC)
"""Fixed UTC started-at timestamp of every investigation evaluation world."""

_FIXED_MAX_ENTITIES = 15
"""Documented entity budget for end-to-end evaluation worlds.

The v0.1 default (10) is deliberately tight for canonical multi-hop worlds
that discover the root, CNAME/MX/NS neighbors, their IPs, shared prefixes,
and a researchable malware family; the evaluation materializer raises the
per-investigation data budget to a documented bound without changing any
production policy constant.
"""

_ROOT_NAMESPACE = UUID("00000000-0000-0000-0000-0000000000ca")
"""Stable ATI-owned UUIDv5 root namespace (shared with evaluation fixtures)."""


class InvestigationMaterializationError(ValueError):
    """A fixture cannot be materialized or a label cannot be resolved.

    Resolution fails closed: unknown fixture labels, unresolvable persisted
    entities, and missing root identities are deterministic errors.
    """

    def __init__(self, message: str) -> None:
        """Record the fail-closed materialization message."""
        super().__init__(message)


def _scenario_budget(scenario: InvestigationScenario) -> InvestigationBudget:
    """Build the initial InvestigationBudget from scenario envelopes.

    Every authored efficiency/trajectory envelope maps to its corresponding
    budget maximum so the production Coordinator/Analyst enforce the same
    bounds the evaluator checks; absent envelopes keep the production
    defaults.
    """
    expected = scenario.expected
    default = default_investigation_budget()
    return default.model_copy(
        update={
            "max_depth": (
                expected.trajectory.max_depth
                if expected.trajectory.max_depth is not None
                else default.max_depth
            ),
            "max_entities": _FIXED_MAX_ENTITIES,
            "max_provider_calls": (
                expected.efficiency.max_provider_calls
                if expected.efficiency.max_provider_calls is not None
                else default.max_provider_calls
            ),
            "max_replans": (
                expected.efficiency.max_replans
                if expected.efficiency.max_replans is not None
                else default.max_replans
            ),
            "max_llm_calls": (
                expected.efficiency.max_llm_calls
                if expected.efficiency.max_llm_calls is not None
                else default.max_llm_calls
            ),
        }
    )


def planned_investigation_id(
    *, root_entity_id: UUID, scenario_id: str, execution_id: UUID
) -> UUID:
    """Return the execution-scoped Investigation identity of one case run.

    Repeated executions of one scenario in the same database stay isolated
    (distinct Investigation worlds, distinct generated Assessment/Research/
    Report identities) while preserving every semantic label. The identity
    is deterministic for a fixed root/scenario/execution triple.
    """
    return uuid5(root_entity_id, f"{scenario_id}:{execution_id}")


class InvestigationScenarioMaterializer:
    """Own the initial Investigation persistence and post-run resolution."""

    @staticmethod
    def _validate_labels(
        scenario: InvestigationScenario, fixture: InvestigationFixture
    ) -> None:
        """Fail closed on expectation labels outside the fixture universe.

        Every required/forbidden entity label and research subject must be a
        fixture-declared world label; the root label must equal the fixture
        root label. A label cannot be required in one expectation and
        forbidden in another.
        """
        universe = set(fixture.world_entities)
        if scenario.root.entity_label not in universe:
            raise InvestigationMaterializationError(
                f"root label {scenario.root.entity_label!r} is outside fixture "
                f"{fixture.name!r} universe"
            )
        if scenario.root.entity_type is not fixture.root_type or (
            scenario.root.value != fixture.root_value
        ):
            raise InvestigationMaterializationError(
                f"scenario root {scenario.root.entity_type.value}:"
                f"{scenario.root.value} does not match fixture {fixture.name!r} root"
            )
        expected = scenario.expected
        required: set[str] = set(expected.evidence.required_entity_labels)
        required.update(expected.research.required_subject_labels)
        required.update(expected.trajectory.required_research)
        forbidden: set[str] = set(expected.evidence.forbidden_entity_labels)
        forbidden.update(expected.research.forbidden_subject_labels)
        forbidden.update(expected.trajectory.forbidden_research)
        referenced = required | forbidden
        unknown = referenced - universe
        if unknown:
            raise InvestigationMaterializationError(
                "unresolved fixture entity labels: " + ", ".join(sorted(unknown))
            )
        overlap = required & forbidden
        if overlap:
            raise InvestigationMaterializationError(
                "labels cannot be both required and forbidden: "
                + ", ".join(sorted(overlap))
            )

    @staticmethod
    def _required_labels(scenario: InvestigationScenario) -> set[str]:
        """Return the strictly required fixture labels of one scenario."""
        expected = scenario.expected
        required: set[str] = set(expected.evidence.required_entity_labels)
        required.update(expected.research.required_subject_labels)
        required.update(expected.trajectory.required_research)
        required.add(scenario.root.entity_label)
        return required

    async def materialize(
        self,
        scenario: InvestigationScenario,
        fixture: InvestigationFixture,
        uow_factory: Callable[[], UnitOfWork],
        *,
        execution_id: UUID,
    ) -> InvestigationScenarioResolution:
        """Persist the root Entity and the RUNNING Investigation once.

        Only the root Entity is created; provider-discovered entities are
        created by the production extraction/persistence path during the run.
        The Investigation starts RUNNING with the initial traversal metadata
        (root at depth 0) exactly as the production runner requires.
        """
        self._validate_labels(scenario, fixture)
        async with uow_factory() as uow:
            persisted_root = await uow.entities.upsert(
                Entity(
                    type=fixture.root_type,
                    value=fixture.root_value,
                )
            )
            root_id = persisted_root.id
            if root_id is None:
                raise InvestigationMaterializationError(
                    f"fixture root entity has no persisted identity: {fixture.name}"
                )
            investigation_id = planned_investigation_id(
                root_entity_id=root_id,
                scenario_id=scenario.id,
                execution_id=execution_id,
            )
            budget = _scenario_budget(scenario)
            traversal = EntityTraversalStateBuilder([root_id]).entries()
            initial = InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[root_id],
                objective=(
                    f"Execute investigation scenario {scenario.id} against the "
                    "deterministic fixture world."
                ),
                budget=budget,
                traversal=list(traversal),
                started_at=_FIXED_STARTED_AT,
            )
            created = await uow.investigations.create(initial)
        if created.version is None:
            raise InvestigationMaterializationError(
                f"investigation {investigation_id} has no persisted version"
            )
        return InvestigationScenarioResolution(
            investigation_id=investigation_id,
            entity_ids={fixture.root_label: root_id},
        )

    async def resolve_persisted(
        self,
        scenario: InvestigationScenario,
        fixture: InvestigationFixture,
        uow_factory: Callable[[], UnitOfWork],
        *,
        investigation_id: UUID,
    ) -> InvestigationScenarioResolution:
        """Resolve every fixture label from canonical persisted identities.

        Runs after the investigation completes; every declared label must
        resolve to a persisted visible Entity through the normal repository
        read seam, or resolution fails closed. The investigation identity is
        supplied by the caller (execution-scoped).
        """
        self._validate_labels(scenario, fixture)
        required = self._required_labels(scenario)
        runtime: dict[str, UUID] = {}
        async with uow_factory() as uow:
            root = await uow.entities.get_by_identity(
                fixture.root_type.value, fixture.root_value
            )
            if root is None or root.id is None:
                raise InvestigationMaterializationError(
                    f"persisted fixture root is unresolved: {fixture.root_label}"
                )
            runtime[fixture.root_label] = root.id
            for label, (entity_type, value) in fixture.world_entities.items():
                if label == fixture.root_label:
                    continue
                entity = await uow.entities.get_by_identity(entity_type.value, value)
                if entity is None or entity.id is None:
                    # Forbidden labels may legitimately resolve to entities the
                    # world never discovered; required labels fail closed.
                    if label in required:
                        raise InvestigationMaterializationError(
                            f"persisted fixture label is unresolved: {label}"
                        )
                    continue
                runtime[label] = entity.id
        return InvestigationScenarioResolution(
            investigation_id=investigation_id,
            entity_ids=runtime,
        )
