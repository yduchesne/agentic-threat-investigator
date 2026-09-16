# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26F Evidence Analyst execution tests (plan Part 14).

Reuses the shared in-memory persistence/accounting fakes and the extended
``AnalysisWorld`` (Seattle/Dallas resolved observations plus an independent
second Evidence row) with ``FakeLlmClient`` at the model boundary. Proves
the GEOINT context flows into one accounted model call, valid geographic
findings persist through the existing Assessment path with exact Evidence
support, invalid/substituted/cross-scope references never move the pointer,
bound failures consume zero LLM reservations, and persistence failures leave
no partial geographic state.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst import (
    EvidenceAnalyst,
    EvidenceAnalystInputLoader,
    LlmAccountingService,
)
from agentic_threat_investigator.app.evidence_analyst.geoint_validation import (
    GeographicFindingValidationError,
)
from agentic_threat_investigator.app.geoint.analysis_context import (
    GeointAnalysisContextPolicy,
    GeointAnalystContextLoader,
)
from agentic_threat_investigator.app.geoint.analysis_tools import GeointAnalysisTools
from agentic_threat_investigator.app.geoint.errors import GeointAnalysisInputBoundsError
from agentic_threat_investigator.domain.analyst import (
    AnalystGeointContext,
    EvidenceAnalystInput,
)
from agentic_threat_investigator.domain.assessment import (
    Assessment,
    EvidenceSupport,
    FindingCategory,
    Verdict,
)
from tests.support.geoint_fixtures import FakeGeointQueryService, zero_summary
from tests.support.llm_fixtures import FakeLlmClient
from tests.unit.app.test_evidence_analyst import (
    AnalysisWorld,
    FakeAccountingInvestigationRepository,
    FakeAccountingUnitOfWork,
    FakeAssessmentRepository,
    FakeAuditRepository,
    FakeInvestigationRepository,
    FakePersistenceUnitOfWork,
)


class Harness:
    """One fully-bound analyst over a GEOINT world with observable fakes."""

    def __init__(self, world: AnalysisWorld) -> None:
        """Bind the analyst and every observable fake over the world."""
        self.world = world
        self.llm = FakeLlmClient()
        self.persistence_uow = FakePersistenceUnitOfWork(
            world=world,
            assessments=FakeAssessmentRepository(),
            audit_events=FakeAuditRepository(),
            investigations=FakeInvestigationRepository(world.investigation),
        )
        self.accounting_uow = FakeAccountingUnitOfWork(world.investigation)
        self.accounting_repo = FakeAccountingInvestigationRepository(
            world.investigation
        )
        self.accounting_uow.investigations = self.accounting_repo
        self.accounting = LlmAccountingService(lambda: self.accounting_uow)
        self.assessments = AssessmentPersistenceService(
            lambda: self.persistence_uow, batch_size=100
        )
        self.analyst = EvidenceAnalyst(
            input_loader=FakeLoaderGeoint(world.analyst_input()),
            llm_client=self.llm,
            assessment_persistence=self.assessments,
            llm_accounting=self.accounting,
            max_structured_output_attempts=2,
        )


class FakeLoaderGeoint(EvidenceAnalystInputLoader):
    """Loader stand-in serving a prebuilt input with the GEOINT context."""

    def __init__(self, analyst_input: EvidenceAnalystInput) -> None:
        """Bind the prebuilt input; the base factory stays unused."""
        from agentic_threat_investigator.app.persistence.repositories import UnitOfWork

        super().__init__(cast(Callable[[], UnitOfWork], lambda: None))
        self._analyst_input = analyst_input

    async def load(self, investigation_id: UUID) -> EvidenceAnalystInput:
        """Return the prebuilt input regardless of the requested identity."""
        del investigation_id
        return self._analyst_input


@pytest.mark.asyncio
async def test_geoint_context_one_normal_accounted_model_call() -> None:
    """GEOINT context flows into one normal accounted invocation (step 14.2)."""
    world = AnalysisWorld(with_geoint=True)
    harness = Harness(world)
    harness.llm.set_default(world.geoint_decision())

    await harness.analyst.analyze(world.investigation_id)

    assert len(harness.llm.calls) == 1
    assert len(harness.accounting_repo.budget_writes) == 1
    assert "<geographic_context>" in harness.llm.calls[0].user_prompt
    assert str(world.geoint_obs_seattle_id) in harness.llm.calls[0].user_prompt
    assert str(world.geoint_obs_dallas_id) in harness.llm.calls[0].user_prompt


@pytest.mark.asyncio
async def test_valid_geographic_finding_is_validated_then_persisted() -> None:
    """Valid geographic findings persist with exact Evidence support (14.3)."""
    world = AnalysisWorld(with_geoint=True)
    harness = Harness(world)
    harness.llm.set_default(world.geoint_decision())

    persisted = await harness.analyst.analyze(world.investigation_id)

    assert isinstance(persisted, Assessment)
    assert persisted.verdict is Verdict.INCONCLUSIVE
    assert tuple(persisted.analyzed_evidence_ids) == (
        world.evidence_id,
        world.geoint_evidence_id,
    )
    [finding] = persisted.findings
    assert finding.category is FindingCategory.GEOLOCATION
    assert [
        s.evidence_id for s in finding.support if isinstance(s, EvidenceSupport)
    ] == [
        world.evidence_id,
        world.geoint_evidence_id,
    ]
    assert len(harness.persistence_uow.assessments.inserted) == 1
    assert harness.persistence_uow.commits == 1
    # Exactly one durable LLM reservation was written (analyze disposition).
    assert harness.accounting_repo.budget_writes[0].llm_calls_used == 1


@pytest.mark.asyncio
async def test_invalid_geographic_support_leaves_no_pointer() -> None:
    """Unknown observation support is rejected with no pointer update (14.4)."""
    world = AnalysisWorld(with_geoint=True)
    harness = Harness(world)
    harness.llm.set_default(
        world.geoint_decision(observation_ids=(uuid4(), world.geoint_obs_dallas_id))
    )

    with pytest.raises(GeographicFindingValidationError):
        await harness.analyst.analyze(world.investigation_id)

    assert harness.persistence_uow.assessments.inserted == []
    assert harness.persistence_uow.investigations.pointer_calls == []
    assert harness.persistence_uow.commits == 0


@pytest.mark.asyncio
async def test_substitute_evidence_rejected() -> None:
    """A swapped Evidence pair cannot support the cited observation (14.5)."""
    world = AnalysisWorld(with_geoint=True)
    harness = Harness(world)
    harness.llm.set_default(
        world.geoint_decision(
            evidence_ids=(world.geoint_evidence_id, world.evidence_id)
        )
    )

    with pytest.raises(GeographicFindingValidationError):
        await harness.analyst.analyze(world.investigation_id)

    assert harness.persistence_uow.assessments.inserted == []
    assert harness.persistence_uow.investigations.pointer_calls == []


@pytest.mark.asyncio
async def test_cross_scope_reference_rejected() -> None:
    """Another world's observation ID fails closed (14.6 cross-scope)."""
    world = AnalysisWorld(with_geoint=True)
    other = AnalysisWorld(with_geoint=True)
    harness = Harness(world)
    harness.llm.set_default(
        world.geoint_decision(
            observation_ids=(other.geoint_obs_seattle_id, world.geoint_obs_dallas_id),
            evidence_ids=(other.evidence_id, world.geoint_evidence_id),
        )
    )

    with pytest.raises(GeographicFindingValidationError):
        await harness.analyst.analyze(world.investigation_id)

    assert harness.persistence_uow.assessments.inserted == []
    assert harness.persistence_uow.investigations.pointer_calls == []


@pytest.mark.asyncio
async def test_context_bound_failure_consumes_zero_reservations() -> None:
    """A GEOINT context-bound failure reserves zero LLM calls (14.7)."""
    world = AnalysisWorld(with_geoint=True)
    fake_llm = FakeLlmClient()
    persistence_uow = FakePersistenceUnitOfWork(
        world=world,
        assessments=FakeAssessmentRepository(),
        audit_events=FakeAuditRepository(),
        investigations=FakeInvestigationRepository(world.investigation),
    )
    accounting_uow = FakeAccountingUnitOfWork(world.investigation)
    accounting_repo = FakeAccountingInvestigationRepository(world.investigation)
    accounting_uow.investigations = accounting_repo
    analyst = EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(
            lambda: persistence_uow,
            geoint_context_loader=_FailingGeointContextLoader(),
        ),
        llm_client=fake_llm,
        assessment_persistence=AssessmentPersistenceService(
            lambda: persistence_uow, batch_size=100
        ),
        llm_accounting=LlmAccountingService(lambda: accounting_uow),
        max_structured_output_attempts=2,
    )

    with pytest.raises(GeointAnalysisInputBoundsError, match="max_entities"):
        await analyst.analyze(world.investigation_id)

    assert fake_llm.calls == []
    assert accounting_repo.budget_writes == []
    assert persistence_uow.assessments.inserted == []


@pytest.mark.asyncio
async def test_geoint_foundings_persist_with_independent_support() -> None:
    """A MALICIOUS verdict requires independent support; GEOINT stays context."""
    world = AnalysisWorld(with_geoint=True)
    harness = Harness(world)
    harness.llm.set_default(
        world.geoint_decision(verdict=Verdict.MALICIOUS, independent=True)
    )

    persisted = await harness.analyst.analyze(world.investigation_id)

    assert persisted.verdict is Verdict.MALICIOUS
    assert len(persisted.findings) == 2
    categories = {finding.category for finding in persisted.findings}
    assert categories == {FindingCategory.NETWORK, FindingCategory.GEOLOCATION}


@pytest.mark.asyncio
async def test_geography_only_positive_verdict_rejected_conservatively() -> None:
    """GEOINT-only support cannot drive a MALICIOUS verdict (independent gate)."""
    world = AnalysisWorld(with_geoint=True)
    harness = Harness(world)
    harness.llm.set_default(
        world.geoint_decision(verdict=Verdict.MALICIOUS, independent=False)
    )

    with pytest.raises(GeographicFindingValidationError):
        await harness.analyst.analyze(world.investigation_id)

    assert harness.persistence_uow.assessments.inserted == []
    assert harness.persistence_uow.investigations.pointer_calls == []


@pytest.mark.asyncio
async def test_geoint_repair_stays_within_one_repair_ceiling() -> None:
    """Invalid structured output repairs once; GEOINT stays accounted (14.9)."""
    from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode

    world = AnalysisWorld(with_geoint=True)
    harness = Harness(world)
    harness.llm.enqueue(
        LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True)
    )
    harness.llm.enqueue(world.geoint_decision())

    persisted = await harness.analyst.analyze(world.investigation_id)

    assert persisted.id is not None
    assert len(harness.llm.calls) == 2
    assert len(harness.accounting_repo.budget_writes) == 2


@pytest.mark.asyncio
async def test_persistence_failure_leaves_no_geographic_mutation() -> None:
    """A persistence failure never mutates geographic state (14.12)."""
    world = AnalysisWorld(with_geoint=True)
    harness = Harness(world)
    harness.persistence_uow.assessments.fail = RuntimeError("disk full")
    harness.llm.set_default(world.geoint_decision())

    with pytest.raises(RuntimeError, match="disk full"):
        await harness.analyst.analyze(world.investigation_id)

    assert harness.persistence_uow.investigations.pointer_calls == []
    assert harness.persistence_uow.assessments.inserted == []


class _FailingGeointContextLoader(GeointAnalystContextLoader):
    """Deterministic stub whose ``load`` always fails the entity bound."""

    def __init__(self) -> None:
        """Bind a real (unused) tools scope and a one-Entity policy bound."""
        service = FakeGeointQueryService(summary_result=zero_summary())
        super().__init__(
            tools_factory=lambda: GeointAnalysisTools(service),
            policy=GeointAnalysisContextPolicy(max_entities=1),
        )

    async def load(
        self, investigation_id: UUID, analyst_input: EvidenceAnalystInput
    ) -> AnalystGeointContext:
        """Raise the typed bound failure before any model call."""
        del investigation_id, analyst_input
        raise GeointAnalysisInputBoundsError("max_entities", 1, 11)
