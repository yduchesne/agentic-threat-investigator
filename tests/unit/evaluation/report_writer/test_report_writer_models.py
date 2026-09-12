# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for Report Writer evaluation scenario contracts (PR 23B)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.assessment import AssessmentConfidence, Verdict
from agentic_threat_investigator.evaluation.report_writer.loader import (
    ReportWriterScenarioLoadError,
    load_report_writer_scenarios_directory,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ExpectedReportWriterOutput,
    ReportWriterScenario,
)

_CORPUS = Path(__file__).parents[4] / "evals/scenarios/report_writer"


def _scenarios() -> dict[str, ReportWriterScenario]:
    """Load the repository report-writer corpus into a stable id-keyed map."""
    return {
        scenario.id: scenario
        for scenario in load_report_writer_scenarios_directory(_CORPUS)
    }


def test_corpus_loads_all_eight_scenarios() -> None:
    """The canonical corpus carries the eight required scenarios."""
    scenarios = _scenarios()
    assert set(scenarios) == {
        "rpt-s01-clearly-malicious",
        "rpt-s02-inconclusive-sparse",
        "rpt-s03-conflicting-evidence",
        "rpt-s04-research-is-context",
        "rpt-s05-no-research",
        "rpt-s06-unsupported-reference",
        "rpt-s07-verdict-override-attempt",
        "rpt-s08-stale-assessment-race",
    }


def test_corpus_versions_positive() -> None:
    """Every scenario carries a positive version."""
    for scenario in _scenarios().values():
        assert scenario.version >= 1


def test_duplicate_json_key_rejected(tmp_path: Path) -> None:
    """Duplicate JSON object keys fail closed at load time."""
    payload = (
        '{"id": "dup", "version": 1, "fixture": "x", "id": "dup", '
        '"expected": {"verdict": "malicious", "confidence": "high", '
        '"min_narrative_statements": 0}}'
    )
    path = tmp_path / "dup.json"
    path.write_text(payload)
    with pytest.raises(ReportWriterScenarioLoadError):
        load_report_writer_scenarios_directory(tmp_path)


def test_unknown_field_rejected() -> None:
    """Unknown scenario fields fail closed."""
    with pytest.raises(ValidationError):
        ReportWriterScenario.model_validate(
            {
                "id": "bad",
                "version": 1,
                "fixture": "x",
                "expected": {
                    "verdict": "malicious",
                    "confidence": "high",
                    "sneaky_field": True,
                },
            }
        )


def test_expected_no_report_requires_error_code() -> None:
    """A declared no-report outcome must carry an execution error code."""
    with pytest.raises(ValidationError):
        ExpectedReportWriterOutput.model_validate(
            {
                "verdict": "malicious",
                "confidence": "high",
                "expected_no_report": True,
            }
        )


def test_disjoint_expectations_enforced() -> None:
    """A finding cannot be both required and forbidden."""
    with pytest.raises(ValidationError):
        ExpectedReportWriterOutput.model_validate(
            {
                "verdict": Verdict.MALICIOUS,
                "confidence": AssessmentConfidence.HIGH,
                "required_assessment_finding_ordinals": [1],
                "forbidden_assessment_finding_ordinals": [1],
            }
        )


def test_narrative_bounds_coherent() -> None:
    """The max statement bound must not sit below the min bound."""
    with pytest.raises(ValidationError):
        ExpectedReportWriterOutput.model_validate(
            {
                "verdict": Verdict.MALICIOUS,
                "confidence": AssessmentConfidence.HIGH,
                "min_narrative_statements": 3,
                "max_narrative_statements": 2,
            }
        )


def test_scenario_id_stable() -> None:
    """Scenario identifiers must be stable lowercase labels."""
    with pytest.raises(ValidationError):
        ReportWriterScenario.model_validate(
            {
                "id": "Not Valid!",
                "version": 1,
                "fixture": "x",
                "expected": {
                    "verdict": "malicious",
                    "confidence": "high",
                },
            }
        )
