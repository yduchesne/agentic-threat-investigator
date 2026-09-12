# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical PR 23B offline vertical slice against real PostgreSQL.

Executes the full production Report Writer path against an isolated migrated
database: persisted Investigation/Evidence/Assessment/ResearchResult, the
production :class:`ReportWriterInputLoader`, the deterministic prompt
builder, :class:`FakeLlmClient` ONLY at the model boundary, the production
Report Writer service, deterministic provenance validation, report
persistence with the Investigation report pointer, and the deterministic
Markdown formatter. No live Internet or live LLM participates.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from agentic_threat_investigator.app.report_writer.formatter import (
    format_investigation_report_markdown,
)
from agentic_threat_investigator.evaluation.report_writer.loader import (
    load_report_writer_scenarios_directory,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.report_writer_composition import (
    build_report_writer,
)
from tests.support.llm_fixtures import FakeLlmClient
from tests.support.report_writer_fixtures import (
    ReportWriterScenarioMaterializer,
    build_canonical_report_output,
)
from tests.support.report_writer_scenarios import report_writer_fixture

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

UOW_FACTORY = Callable[[], PostgresUnitOfWork]


async def test_canonical_report_writer_vertical_slice(
    uow_factory: UOW_FACTORY,
) -> None:
    """The production Report Writer path works end-to-end on real PostgreSQL."""
    scenario = next(
        scenario
        for scenario in load_report_writer_scenarios_directory(
            "evals/scenarios/report_writer"
        )
        if scenario.id == "rpt-s01-clearly-malicious"
    )
    fixture = report_writer_fixture(scenario.fixture)
    resolution = await ReportWriterScenarioMaterializer(uow_factory).materialize(
        scenario, fixture
    )

    fake_llm = FakeLlmClient()
    fake_llm.set_default(build_canonical_report_output(scenario, resolution, fixture))
    writer = build_report_writer(
        uow_factory=uow_factory,
        llm_client=fake_llm,
        batch_size=100,
    )

    persisted = await writer.write(resolution.investigation_id)

    # The exact persisted report is returned.
    assert persisted.id is not None
    assert persisted.investigation_id == resolution.investigation_id
    assert persisted.assessment_id == resolution.assessment_id
    # Verdict/confidence equal the Assessment exactly.
    assert persisted.verdict is fixture.verdict
    assert persisted.confidence is fixture.confidence
    # Findings snapshot the Assessment findings.
    assert [f.assessment_finding_ordinal for f in persisted.findings] == [1]
    assert persisted.findings[0].statement == fixture.findings[0].statement
    # Research context snapshots the persisted claim.
    assert len(persisted.research_context) == 1
    assert (
        persisted.research_context[0].research_claim_id
        == resolution.research_claim_ids["malicious_context"]
    )
    # Provenance references resolve.
    assert persisted.source_evidence_ids == (resolution.evidence_ids["reputation_hit"],)
    assert persisted.source_research_result_ids == (
        resolution.research_result_ids["result_1"],
    )
    # The report pointer advanced.
    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(resolution.investigation_id)
        assert state is not None
        assert state.report_id == persisted.id

    # Markdown is deterministic.
    first_render = format_investigation_report_markdown(persisted)
    second_render = format_investigation_report_markdown(persisted)
    assert first_render == second_render
    assert "malicious" in first_render
    assert "Verdict" in first_render

    # No raw model response is stored: the persisted report contains only the
    # stamped authoritative fields.
    assert persisted.executive_summary[0].text == (
        "malicious indicator with high confidence"
    )
    serialized = persisted.model_dump_json()
    assert "research_claim" in serialized
    assert "chain_of_thought" not in serialized


async def test_report_writer_second_generation_new_version(
    uow_factory: UOW_FACTORY,
) -> None:
    """Repeated explicit generation appends a new report version."""
    scenario = next(
        scenario
        for scenario in load_report_writer_scenarios_directory(
            "evals/scenarios/report_writer"
        )
        if scenario.id == "rpt-s05-no-research"
    )
    fixture = report_writer_fixture(scenario.fixture)
    resolution = await ReportWriterScenarioMaterializer(uow_factory).materialize(
        scenario, fixture
    )
    fake_llm = FakeLlmClient()
    fake_llm.set_default(build_canonical_report_output(scenario, resolution, fixture))
    writer = build_report_writer(uow_factory=uow_factory, llm_client=fake_llm)

    first = await writer.write(resolution.investigation_id)
    second = await writer.write(resolution.investigation_id)

    assert first.id != second.id
    assert second.version is not None and first.version is not None
    assert second.version > first.version
    assert len(fake_llm.calls) == 2
