# SPDX-License-Identifier: AGPL-3.0-only
"""G26F-C matrix: deterministic GEOINT analysis context policy (PR 26F).

Proves the policy alone selects the bounded model-visible context: eligible
Entities come only from the authoritative analyst input, query/order and
bounds are deterministic, aggregate bounds fail closed with typed errors,
and truncation/continuation state is preserved explicitly. The fake query
service replaces only the read boundary.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.geoint.analysis_context import (
    GeointAnalysisContextPolicy,
    GeointAnalystContextLoader,
)
from agentic_threat_investigator.app.geoint.analysis_tools import GeointAnalysisTools
from agentic_threat_investigator.app.geoint.errors import (
    GeointAnalysisInputBoundsError,
    GeointObservationEvidenceError,
)
from agentic_threat_investigator.domain.analyst import (
    AnalystEntity,
    AnalystEvidenceItem,
    AnalystGeointContext,
    EvidenceAnalystInput,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from tests.support.geoint_fixtures import (
    FIXED,
    FakeGeointQueryService,
    entity_location_item,
    location_ref,
    observation_item,
    summary_with_top_locations,
    zero_summary,
)


def analyst_input(
    investigation_id: UUID,
    *,
    root_entity_ids: list[UUID] | None = None,
    evidence: tuple[AnalystEvidenceItem, ...] = (),
) -> EvidenceAnalystInput:
    """Build one deterministic analyst input over the given Entities."""
    return EvidenceAnalystInput(
        investigation_id=investigation_id,
        objective="Assess the root indicator.",
        root_entities=tuple(
            AnalystEntity(
                entity_id=entity_id,
                entity_type=EntityType.IP_ADDRESS,
                value=f"203.0.113.{index + 1}",
            )
            for index, entity_id in enumerate(root_entity_ids or [])
        ),
        evidence=evidence,
    )


def evidence_item(entity_id: UUID, evidence_id: UUID) -> AnalystEvidenceItem:
    """Build one analyst Evidence item bound to an Entity."""
    return AnalystEvidenceItem(
        evidence_id=evidence_id,
        type=EvidenceType.GEOLOCATION,
        subject=AnalystEntity(
            entity_id=entity_id,
            entity_type=EntityType.IP_ADDRESS,
            value="203.0.113.10",
        ),
        source="urn:ati:source:test",
        retrieved_at=FIXED,
        facts={},
    )


async def present_and_context(
    *,
    service: FakeGeointQueryService,
    investigation_id: UUID,
    root_entity_ids: list[UUID],
    max_entities: int = 10,
    max_observations_per_entity: int = 5,
    max_total_observations: int = 50,
    max_context_bytes: int = 262_144,
    evidence: tuple[AnalystEvidenceItem, ...] = (),
) -> tuple[AnalystGeointContext, FakeGeointQueryService]:
    """Run the policy and return the visible context plus the recording service."""
    policy = GeointAnalysisContextPolicy(
        max_entities=max_entities,
        max_observations_per_entity=max_observations_per_entity,
        max_total_observations=max_total_observations,
        max_context_bytes=max_context_bytes,
    )
    tools = GeointAnalysisTools(service)
    context = await policy.select(
        analyst_input(
            investigation_id, root_entity_ids=root_entity_ids, evidence=evidence
        ),
        tools,
    )
    return context, service


@pytest.mark.asyncio
async def test_g26f_c01_no_geoint_is_empty_context() -> None:
    """G26F-C01 no observations yield an all-zero context with no Entities."""
    investigation_id = uuid4()
    service = FakeGeointQueryService(summary_result=zero_summary())
    context, _ = await present_and_context(
        service=service,
        investigation_id=investigation_id,
        root_entity_ids=[uuid4()],
    )

    assert context.entities == ()
    assert context.summary.observation_count == 0
    assert context.summary.truncated is False


@pytest.mark.asyncio
async def test_g26f_c02_one_eligible_entity_current_and_history() -> None:
    """G26F-C02 one eligible Entity gets deterministic current and history."""
    investigation_id = uuid4()
    entity_id = uuid4()
    evidence_id = uuid4()
    current_observation = observation_item(entity_id=entity_id, evidence_id=evidence_id)
    current = entity_location_item(entity_id=entity_id, observation=current_observation)
    history = [
        observation_item(
            entity_id=entity_id,
            evidence_id=evidence_id,
            observation_id=current_observation.observation_id,
        ),
        observation_item(entity_id=entity_id, evidence_id=evidence_id),
        observation_item(entity_id=entity_id, evidence_id=evidence_id),
    ]
    service = FakeGeointQueryService(
        summary_result=summary_with_top_locations(current.current_observation.location),
        current_by_entity={entity_id: current},
        history_by_entity={entity_id: history},
    )

    context, _ = await present_and_context(
        service=service,
        investigation_id=investigation_id,
        root_entity_ids=[entity_id],
        evidence=(evidence_item(entity_id, evidence_id),),
    )

    [entity] = context.entities
    assert entity.entity_id == entity_id
    assert entity.current_observation is not None
    assert entity.current_observation.observation_id == (
        current.current_observation.observation_id
    )
    assert len(entity.history) == 2
    assert {item.observation_id for item in entity.history} == {
        history[1].observation_id,
        history[2].observation_id,
    }
    assert all(item.evidence_id == evidence_id for item in entity.history)


@pytest.mark.asyncio
async def test_g26f_c03_unrelated_entity_not_fanned_out() -> None:
    """G26F-C03 an Investigation Entity absent from the input is never queried."""
    investigation_id = uuid4()
    eligible_id = uuid4()
    unrelated_id = uuid4()
    eligible_evidence = uuid4()
    unrelated_evidence = uuid4()
    service = FakeGeointQueryService(
        summary_result=zero_summary(),
        current_by_entity={
            eligible_id: entity_location_item(
                entity_id=eligible_id, evidence_id=eligible_evidence
            ),
            unrelated_id: entity_location_item(
                entity_id=unrelated_id, evidence_id=unrelated_evidence
            ),
        },
        history_by_entity={
            eligible_id: [
                observation_item(entity_id=eligible_id, evidence_id=eligible_evidence)
            ],
            unrelated_id: [
                observation_item(entity_id=unrelated_id, evidence_id=unrelated_evidence)
            ],
        },
    )

    context, recorded = await present_and_context(
        service=service,
        investigation_id=investigation_id,
        root_entity_ids=[eligible_id],
        evidence=(evidence_item(eligible_id, eligible_evidence),),
    )

    assert [entity.entity_id for entity in context.entities] == [eligible_id]
    assert [call.entity_id for call in recorded.entity_calls] == [eligible_id]
    assert [call.entity_id for call in recorded.history_calls] == [eligible_id]


@pytest.mark.asyncio
async def test_g26f_c04_stable_input_order() -> None:
    """G26F-C04 eligible Entity order follows the authoritative analyst input."""
    investigation_id = uuid4()
    root_a, root_b, subject_c = uuid4(), uuid4(), uuid4()
    evidence_a, evidence_b, evidence_c = uuid4(), uuid4(), uuid4()
    service = FakeGeointQueryService(
        summary_result=zero_summary(),
        current_by_entity={
            root_a: entity_location_item(entity_id=root_a, evidence_id=evidence_a),
            root_b: entity_location_item(entity_id=root_b, evidence_id=evidence_b),
            subject_c: entity_location_item(
                entity_id=subject_c, evidence_id=evidence_c
            ),
        },
        history_by_entity={
            root_a: [observation_item(entity_id=root_a, evidence_id=evidence_a)],
            root_b: [observation_item(entity_id=root_b, evidence_id=evidence_b)],
            subject_c: [observation_item(entity_id=subject_c, evidence_id=evidence_c)],
        },
    )
    # The input order is roots (a, b) then Evidence subjects (c).
    evidence = (
        evidence_item(subject_c, evidence_c),
        evidence_item(root_a, evidence_a),
        evidence_item(root_b, evidence_b),
    )
    policy = GeointAnalysisContextPolicy()
    tools = GeointAnalysisTools(service)
    context = await policy.select(
        analyst_input(
            investigation_id,
            root_entity_ids=[root_a, root_b],
            evidence=evidence,
        ),
        tools,
    )

    assert [entity.entity_id for entity in context.entities] == [
        root_a,
        root_b,
        subject_c,
    ]
    assert [call.entity_id for call in service.entity_calls] == [
        root_a,
        root_b,
        subject_c,
    ]


@pytest.mark.asyncio
async def test_g26f_c05_entity_bound_fails_closed() -> None:
    """G26F-C05 more eligible Entities than the bound fail with the typed error."""
    investigation_id = uuid4()
    service = FakeGeointQueryService(summary_result=zero_summary())
    with pytest.raises(GeointAnalysisInputBoundsError, match="max_entities") as holder:
        await present_and_context(
            service=service,
            investigation_id=investigation_id,
            root_entity_ids=[uuid4() for _ in range(3)],
            max_entities=2,
        )
    assert holder.value.limit == 2
    assert holder.value.actual == 3
    # No Entity/observer query was ever issued after the bound tripped.
    assert service.entity_calls == []


@pytest.mark.asyncio
async def test_g26f_c06_observation_bound_no_page_draining() -> None:
    """G26F-C06 one bounded page per Entity; has_more never drains a cursor."""
    investigation_id = uuid4()
    entity_id = uuid4()
    evidence_id = uuid4()
    history_rows = [
        observation_item(entity_id=entity_id, evidence_id=evidence_id) for _ in range(7)
    ]
    service = FakeGeointQueryService(
        summary_result=zero_summary(),
        current_by_entity={
            entity_id: entity_location_item(
                entity_id=entity_id, observation=history_rows[0]
            )
        },
        history_by_entity={entity_id: history_rows},
    )

    context, recorded = await present_and_context(
        service=service,
        investigation_id=investigation_id,
        root_entity_ids=[entity_id],
        max_observations_per_entity=3,
        max_total_observations=3,
        evidence=(evidence_item(entity_id, evidence_id),),
    )

    [entity] = context.entities
    assert entity.current_observation is not None
    assert len(entity.history) == 2  # current plus strictly-older history = 3 unique
    assert entity.has_more_history is True
    assert len(recorded.history_calls) == 1
    assert recorded.history_calls[0].limit == 3
    assert recorded.history_calls[0].cursor is None


@pytest.mark.asyncio
async def test_g26f_c07_byte_bound_fails_without_model_call() -> None:
    """G26F-C07 an oversize serialized context fails with the typed error."""
    investigation_id = uuid4()
    entity_id = uuid4()
    evidence_id = uuid4()
    service = FakeGeointQueryService(
        summary_result=summary_with_top_locations(
            location_ref(canonical_name="A Very Long City Name " * 20)
        ),
        current_by_entity={
            entity_id: entity_location_item(
                entity_id=entity_id, evidence_id=evidence_id
            )
        },
        history_by_entity={
            entity_id: [
                observation_item(entity_id=entity_id, evidence_id=evidence_id)
                for _ in range(5)
            ]
        },
    )
    with pytest.raises(
        GeointAnalysisInputBoundsError, match="serialized_context_bytes"
    ) as holder:
        await present_and_context(
            service=service,
            investigation_id=investigation_id,
            root_entity_ids=[entity_id],
            max_context_bytes=1000,
            evidence=(evidence_item(entity_id, evidence_id),),
        )
    assert holder.value.bound == "serialized_context_bytes"


@pytest.mark.asyncio
async def test_g26f_c08_summary_truncated_flag_preserved() -> None:
    """G26F-C08 the explicit summary-truncation flag survives into the context."""
    investigation_id = uuid4()
    summary = summary_with_top_locations(location_ref())
    service = FakeGeointQueryService(
        summary_result=summary.model_copy(update={"truncated": True})
    )
    context, _ = await present_and_context(
        service=service,
        investigation_id=investigation_id,
        root_entity_ids=[uuid4()],
    )
    assert context.summary.truncated is True


@pytest.mark.asyncio
async def test_g26f_c09_history_has_more_flag_preserved() -> None:
    """G26F-C09 per-Entity history continuation state is explicit to the model."""
    investigation_id = uuid4()
    entity_id = uuid4()
    evidence_id = uuid4()
    history_rows = [
        observation_item(entity_id=entity_id, evidence_id=evidence_id) for _ in range(6)
    ]
    service = FakeGeointQueryService(
        summary_result=zero_summary(),
        current_by_entity={
            entity_id: entity_location_item(
                entity_id=entity_id, observation=history_rows[0]
            )
        },
        history_by_entity={entity_id: history_rows},
    )
    context, _ = await present_and_context(
        service=service,
        investigation_id=investigation_id,
        root_entity_ids=[entity_id],
        max_observations_per_entity=4,
        max_total_observations=4,
        evidence=(evidence_item(entity_id, evidence_id),),
    )
    entity = context.entities[0]
    assert entity.has_more_history is True
    assert entity.current_observation is not None
    assert len(entity.history) == 3  # one bounded page (4) minus the current


@pytest.mark.asyncio
async def test_g26f_c10_cross_scope_or_malformed_fails_closed() -> None:
    """G26F-C10 impossible cross-scope/malformed service results fail closed.

    An observation whose Evidence is outside the supplied analyst input makes
    the whole GEOINT context fail with a typed error before any LLM call.
    """
    investigation_id = uuid4()
    entity_id = uuid4()
    unrelated_evidence_id = uuid4()
    service = FakeGeointQueryService(
        summary_result=zero_summary(),
        current_by_entity={entity_id: entity_location_item(entity_id=entity_id)},
        history_by_entity={
            entity_id: [
                observation_item(entity_id=entity_id, evidence_id=unrelated_evidence_id)
            ]
        },
    )
    with pytest.raises(GeointObservationEvidenceError):
        await present_and_context(
            service=service,
            investigation_id=investigation_id,
            root_entity_ids=[entity_id],
        )


@pytest.mark.asyncio
async def test_total_observation_bound_fails_closed() -> None:
    """The aggregate observation bound fails closed with the typed error."""
    investigation_id = uuid4()
    entity_a, entity_b = uuid4(), uuid4()
    evidence_a, evidence_b = uuid4(), uuid4()
    history_a = [
        observation_item(entity_id=entity_a, evidence_id=evidence_a) for _ in range(3)
    ]
    history_b = [
        observation_item(entity_id=entity_b, evidence_id=evidence_b) for _ in range(3)
    ]
    service = FakeGeointQueryService(
        summary_result=zero_summary(),
        current_by_entity={
            entity_a: entity_location_item(
                entity_id=entity_a, observation=history_a[0]
            ),
            entity_b: entity_location_item(
                entity_id=entity_b, observation=history_b[0]
            ),
        },
        history_by_entity={entity_a: history_a, entity_b: history_b},
    )
    with pytest.raises(
        GeointAnalysisInputBoundsError, match="max_total_observations"
    ) as holder:
        await present_and_context(
            service=service,
            investigation_id=investigation_id,
            root_entity_ids=[entity_a, entity_b],
            max_observations_per_entity=3,
            max_total_observations=4,
            evidence=(
                evidence_item(entity_a, evidence_a),
                evidence_item(entity_b, evidence_b),
            ),
        )
    assert holder.value.bound == "max_total_observations"


@pytest.mark.asyncio
async def test_loader_closes_tools_scope_and_checks_binding() -> None:
    """The composition loader closes the tools scope and validates the binding."""
    investigation_id = uuid4()
    closed: list[str] = []

    async def close() -> None:
        """Record the tools-scope close."""
        closed.append("closed")

    service = FakeGeointQueryService(summary_result=zero_summary())

    def tools_factory() -> GeointAnalysisTools:
        """Build one facade with a recording close hook."""
        return GeointAnalysisTools(service, on_close=close)

    loader = GeointAnalystContextLoader(
        tools_factory=tools_factory,
        policy=GeointAnalysisContextPolicy(max_entities=2),
    )
    other_investigation = uuid4()
    with pytest.raises(ValueError, match="does not match"):
        await loader.load(other_investigation, analyst_input(investigation_id))
    assert closed == []

    context = await loader.load(
        investigation_id, analyst_input(investigation_id, root_entity_ids=[uuid4()])
    )
    assert context.summary.observation_count == 0
    assert closed == ["closed"]


def test_policy_constructor_validates_bounds() -> None:
    """Direct construction cannot bypass the aggregate bound ceilings."""
    with pytest.raises(ValueError, match="max_entities"):
        GeointAnalysisContextPolicy(max_entities=0)
    with pytest.raises(ValueError, match="max_entities"):
        GeointAnalysisContextPolicy(max_entities=201)
    with pytest.raises(ValueError, match="max_observations_per_entity"):
        GeointAnalysisContextPolicy(max_observations_per_entity=0)
    with pytest.raises(ValueError, match="max_total_observations"):
        GeointAnalysisContextPolicy(max_total_observations=0)
    with pytest.raises(ValueError, match="max_context_bytes"):
        GeointAnalysisContextPolicy(max_context_bytes=100)


def test_eligible_entity_order_is_deterministic() -> None:
    """The eligible Entity order never depends on set/hash iteration."""
    from agentic_threat_investigator.app.geoint.analysis_context import (
        _eligible_entity_ids,
    )

    root = uuid4()
    investigation_id = uuid4()
    evidence = (evidence_item(root, uuid4()),)
    ordered = _eligible_entity_ids(
        analyst_input(investigation_id, root_entity_ids=[root, root], evidence=evidence)
    )
    assert ordered == [root]
