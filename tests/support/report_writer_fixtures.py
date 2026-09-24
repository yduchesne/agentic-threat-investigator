# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Thin test-only re-export of the repository-owned Report Writer fixtures (PR 30E).

PR 30E promoted the canonical fixture/materializer implementation into
``agentic_threat_investigator.evaluation.report_writer.fixtures`` so
production evaluation code and tests share one implementation and tests
never import fixture logic from ``tests.support``. This module is a
deprecated test-only compatibility alias; new code should import from the
canonical evaluation package.
"""

from __future__ import annotations

from agentic_threat_investigator.evaluation.report_writer.fixtures import (
    REPORT_SCENARIO_NAMESPACE,
    FixtureFinding,
    FixtureResearchCitation,
    FixtureResearchClaim,
    FixtureResearchResult,
    ReportWriterFixture,
    ReportWriterScenarioMaterializer,
    build_canonical_report_output,
    planned_report_identity,
    report_scenario_resolution,
)

__all__ = [
    "FixtureFinding",
    "FixtureResearchCitation",
    "FixtureResearchClaim",
    "FixtureResearchResult",
    "REPORT_SCENARIO_NAMESPACE",
    "ReportWriterFixture",
    "ReportWriterScenarioMaterializer",
    "build_canonical_report_output",
    "planned_report_identity",
    "report_scenario_resolution",
]
