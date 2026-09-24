# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared deterministic Report Writer evaluation helpers for PR 30E unit tests.

Builds in-memory scenarios, resolutions, and authoritative reports from the
committed corpus and the repository-owned fixture builders — no database, no
provider, no LLM. The report input mirrors exactly what the production input
loader assembles from a materialized fixture.
"""

from __future__ import annotations

from pathlib import Path

from agentic_threat_investigator.app.report_writer.validator import (
    build_investigation_report,
)
from agentic_threat_investigator.domain.report import InvestigationReport
from agentic_threat_investigator.evaluation.report_writer.fixtures import (
    build_canonical_report_output,
    build_fixture_report_input,
    report_scenario_resolution,
)
from agentic_threat_investigator.evaluation.report_writer.loader import (
    load_report_writer_scenarios_directory,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ReportWriterScenario,
    ReportWriterScenarioResolution,
)
from agentic_threat_investigator.evaluation.report_writer.scenarios import (
    report_writer_fixture,
)

REPORT_WRITER_CORPUS = Path("evals/scenarios/report_writer")
"""Repository-relative root of the committed Report Writer scenario corpus."""


def corpus_scenario(scenario_id: str) -> ReportWriterScenario:
    """Load one exact scenario from the committed corpus by stable id."""
    return next(
        scenario
        for scenario in load_report_writer_scenarios_directory(REPORT_WRITER_CORPUS)
        if scenario.id == scenario_id
    )


def scenario_resolution(
    scenario: ReportWriterScenario,
    *,
    execution_id: object = None,
) -> ReportWriterScenarioResolution:
    """Return the planned in-memory resolution for one scenario."""
    return report_scenario_resolution(
        scenario,
        report_writer_fixture(scenario.fixture),
        execution_id=execution_id,  # type: ignore[arg-type]
    )


def canonical_report(
    scenario: ReportWriterScenario,
    resolution: ReportWriterScenarioResolution,
) -> InvestigationReport:
    """Build the deterministic authoritative report satisfying the envelope."""
    fixture = report_writer_fixture(scenario.fixture)
    report_input = build_fixture_report_input(fixture, resolution)
    output = build_canonical_report_output(scenario, resolution, fixture)
    return build_investigation_report(report_input, output)
