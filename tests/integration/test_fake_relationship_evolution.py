# SPDX-License-Identifier: AGPL-3.0-only
"""F03 relationship-evolution integration test (PR 23D).

Runs the logistics-corp.test scenario at two distinct retrieval clocks over
real PostgreSQL: the first run observes three repetitions of the stable
``RESOLVES_TO`` relationship at distinct source-semantic ``observed_at``
times; the second run additionally observes a later new counterparty. The
retrieval clock (``retrieved_at``) stays independent of the scenario
timestamps, and benign temporal churn (MX/NS/TXT observations) surrounds the
signal without inventing relationship-end semantics.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.relationships import RelationshipType
from tests.integration.fake_runtime_helpers import (
    analysis_decision,
    build_fake_mode_runner,
)

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

F03_DOMAIN = "logistics-corp.test"
F03_STABLE_IP = "203.0.113.60"
F03_NEW_IP = "198.51.100.77"
EARLY_CLOCK = datetime(2026, 7, 1, tzinfo=UTC)
LATE_CLOCK = datetime(2026, 10, 1, tzinfo=UTC)


async def _seed_running_investigation(
    uow_factory: Callable[[], Any], *, clock: datetime
) -> tuple[UUID, UUID]:
    """Persist one RUNNING F03 investigation with its root entity.

    The canonical identity is shared across runs, so the durable Entity ID
    returned by the upsert (never a caller-invented UUID) is authoritative.
    """
    investigation_id = uuid4()
    root_id = uuid4()
    async with uow_factory() as uow:
        written = await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value=F03_DOMAIN)
        )
        durable_root_id = written.id if written.id is not None else root_id
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.API,
                root_entity_ids=[durable_root_id],
                objective="assess the logistics domain relationship evolution",
                budget=default_investigation_budget(),
                started_at=clock,
                created_at=clock,
            )
        )
        await uow.commit()
    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(investigation_id)
    assert durable is not None
    return investigation_id, durable_root_id


async def _run_investigation(
    uow_factory: Callable[[], Any],
    session_factory: Any,
    investigation_id: UUID,
    *,
    clock: datetime,
) -> LocalInvestigationRunner:
    """Execute one F03 investigation through the production fake-mode runner."""
    runner, llm = build_fake_mode_runner(uow_factory, session_factory, clock=clock)
    llm.set_default(
        analysis_decision(
            verdict="benign",
            confidence="medium",
            disposition="sufficient",
            summary="benign domain with stable hosting relationship",
        )
    )
    await runner.run(investigation_id)
    return runner


async def _evidence_rows(
    uow_factory: Callable[[], Any], investigation_id: UUID
) -> list[Any]:
    """Return persisted Evidence rows for one investigation."""
    async with uow_factory() as uow:
        rows: list[Any] = await uow.evidence.list_for_investigation(
            investigation_id, limit=100
        )
        return rows


async def test_f03_repeated_observations_and_later_counterparty(
    uow_factory: Callable[[], Any], session_factory: Any
) -> None:
    """Stable relationship repeats, then a new counterparty appears later."""
    first_id, _root = await _seed_running_investigation(uow_factory, clock=EARLY_CLOCK)
    await _run_investigation(uow_factory, session_factory, first_id, clock=EARLY_CLOCK)

    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(first_id)
        assert durable is not None
        assert durable.status is InvestigationStatus.COMPLETED
        first_observations = await uow.relationship_observations.list_for_investigation(
            first_id, limit=100
        )
        domain_entity = await uow.entities.get_by_identity(
            EntityType.DOMAIN.value, F03_DOMAIN
        )
        stable_ip = await uow.entities.get_by_identity(
            EntityType.IP_ADDRESS.value, F03_STABLE_IP
        )
    assert domain_entity is not None and stable_ip is not None
    async with uow_factory() as uow:
        relationship = await uow.relationships.get_by_identity(
            domain_entity.id,
            RelationshipType.RESOLVES_TO.value,
            stable_ip.id,
        )
    assert relationship is not None

    # Three A-record observations of the stable relationship at distinct
    # source-semantic times, all with retrieval times equal to the clock.
    resolves = [
        obs for obs in first_observations if obs.relationship_id == relationship.id
    ]
    assert len(resolves) == 3
    observed_times = {obs.observed_at for obs in resolves}
    assert len(observed_times) == 3
    for obs in resolves:
        assert obs.observed_at != obs.retrieved_at
        assert obs.retrieved_at == EARLY_CLOCK
    # Benign temporal churn: the mail-relay observation exists nearby.
    mail_relay = await _resolve_mail_relay_observation(uow_factory, first_id)
    assert mail_relay is not None

    # Second run at a later clock observes the new counterparty.
    second_id, _root2 = await _seed_running_investigation(uow_factory, clock=LATE_CLOCK)
    await _run_investigation(uow_factory, session_factory, second_id, clock=LATE_CLOCK)

    async with uow_factory() as uow:
        second_observations = (
            await uow.relationship_observations.list_for_investigation(
                second_id, limit=100
            )
        )
        new_ip = await uow.entities.get_by_identity(
            EntityType.IP_ADDRESS.value, F03_NEW_IP
        )
    assert new_ip is not None
    async with uow_factory() as uow:
        new_relationship = await uow.relationships.get_by_identity(
            domain_entity.id,
            RelationshipType.RESOLVES_TO.value,
            new_ip.id,
        )
    second_resolves = [
        obs for obs in second_observations if obs.relationship_id == new_relationship.id
    ]
    assert len(second_resolves) == 1
    assert second_resolves[0].observed_at == datetime(2026, 9, 1, 9, 0, tzinfo=UTC)
    assert second_resolves[0].retrieved_at == LATE_CLOCK


async def _resolve_mail_relay_observation(
    uow_factory: Callable[[], Any], investigation_id: UUID
) -> Any | None:
    """Return one USES_MAIL_SERVER observation for the investigation."""
    async with uow_factory() as uow:
        observations = await uow.relationship_observations.list_for_investigation(
            investigation_id, limit=100
        )
    for obs in observations:
        async with uow_factory() as uow:
            relationship = await uow.relationships.get_by_id(obs.relationship_id)
        if (
            relationship is not None
            and relationship.type is RelationshipType.USES_MAIL_SERVER
        ):
            return obs
    return None


async def test_f03_evidence_carries_distinct_observed_and_retrieved(
    uow_factory: Callable[[], Any], session_factory: Any
) -> None:
    """Every persisted A-record Evidence preserves observed_at separately."""
    investigation_id, _root = await _seed_running_investigation(
        uow_factory, clock=EARLY_CLOCK
    )
    await _run_investigation(
        uow_factory, session_factory, investigation_id, clock=EARLY_CLOCK
    )
    evidence_rows = await _evidence_rows(uow_factory, investigation_id)
    a_records = [
        row for row in evidence_rows if row.source == "urn:ati:source:google_public_dns"
    ]
    assert a_records
    for row in a_records:
        facts = row.facts
        assert facts.get("query_type") in ("A", "MX", "NS", "TXT")
        assert row.observed_at is not None
        assert row.observed_at != row.retrieved_at
