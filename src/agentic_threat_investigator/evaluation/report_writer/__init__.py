# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned Report Writer evaluation baseline (PR 23B, PR 30E).

The Report Writer evaluation answers a deterministic question about the
delivered PR 23B runtime: given a known persisted investigation snapshot and
the production Report Writer execution path, is the final persisted report
acceptably grounded and faithful to the authoritative Assessment/Research
inputs? It is deliberately NOT the generic PR 27 evaluator platform and uses
no LLM-as-judge, embeddings, regex fact extraction, or fuzzy similarity.

PR 30E adds the real-target execution layer: repository-owned fixtures and
materialization (``fixtures``/``scenarios``), the production Report Writer
target (``target``), the thin PR 30 evaluator adapter (``pr30``), the
evaluation composition seam (``composition``), and the LangSmith-free run
service (``run``).
"""

from agentic_threat_investigator.evaluation.report_writer.composition import (
    CountingLlmClient,
    compose_report_writer_target,
    default_writer_factory,
)
from agentic_threat_investigator.evaluation.report_writer.evaluator import (
    ReportWriterEvaluator,
)
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
from agentic_threat_investigator.evaluation.report_writer.loader import (
    ReportWriterScenarioLoadError,
    load_report_writer_scenarios_directory,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ExpectedReportWriterOutput,
    ReportWriterEvaluationInput,
    ReportWriterEvaluationResult,
    ReportWriterFailureCode,
    ReportWriterMetrics,
    ReportWriterScenario,
    ReportWriterScenarioResolution,
)
from agentic_threat_investigator.evaluation.report_writer.pr30 import (
    REPORT_WRITER_CONTRACT_EVALUATOR_ID,
    ReportWriterContractEvaluator,
)
from agentic_threat_investigator.evaluation.report_writer.scenarios import (
    REPORT_WRITER_FIXTURES,
    report_writer_fixture,
)
from agentic_threat_investigator.evaluation.report_writer.target import (
    ReportWriterEvaluationOutput,
    ReportWriterScenarioLookup,
    ReportWriterScenarioLookupError,
    ReportWriterTargetExecutor,
    stable_report_execution_error,
)

__all__ = [
    "CountingLlmClient",
    "ExpectedReportWriterOutput",
    "FixtureFinding",
    "FixtureResearchCitation",
    "FixtureResearchClaim",
    "FixtureResearchResult",
    "REPORT_SCENARIO_NAMESPACE",
    "REPORT_WRITER_CONTRACT_EVALUATOR_ID",
    "REPORT_WRITER_FIXTURES",
    "ReportWriterContractEvaluator",
    "ReportWriterEvaluationInput",
    "ReportWriterEvaluationOutput",
    "ReportWriterEvaluationResult",
    "ReportWriterEvaluator",
    "ReportWriterFailureCode",
    "ReportWriterFixture",
    "ReportWriterMetrics",
    "ReportWriterScenario",
    "ReportWriterScenarioLoadError",
    "ReportWriterScenarioLookup",
    "ReportWriterScenarioLookupError",
    "ReportWriterScenarioMaterializer",
    "ReportWriterScenarioResolution",
    "ReportWriterTargetExecutor",
    "build_canonical_report_output",
    "compose_report_writer_target",
    "default_writer_factory",
    "load_report_writer_scenarios_directory",
    "planned_report_identity",
    "report_scenario_resolution",
    "report_writer_fixture",
    "stable_report_execution_error",
]
