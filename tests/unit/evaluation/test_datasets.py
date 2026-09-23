# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A repository dataset loading tests.

The canonical corpus (committed JSON under ``evals/scenarios/``) must load
through the dataset registry with deterministic case ordering, uniform
versions, and fail-closed identity enforcement — all offline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationDatasetId,
    EvaluationTarget,
)
from agentic_threat_investigator.evaluation.datasets import (
    load_dataset,
    validate_dataset_directory,
)

REPO_ROOT = Path(__file__).parents[3]
SCENARIOS_ROOT = REPO_ROOT / "evals" / "scenarios"


@pytest.mark.parametrize(
    ("target", "expected_count"),
    [
        (EvaluationTarget.EVIDENCE_ANALYST, 8),
        (EvaluationTarget.COORDINATOR, 17),
        (EvaluationTarget.GEOINT, 16),
        (EvaluationTarget.REPORT_WRITER, 8),
        (EvaluationTarget.RESEARCH_AGENT, 11),
    ],
)
def test_load_dataset_counts_and_ordering(
    target: EvaluationTarget, expected_count: int
) -> None:
    """Every registered dataset loads deterministically with uniform version."""
    dataset_id = EvaluationDatasetId(target=target, version=1)
    cases = load_dataset(dataset_id, corpus_root=SCENARIOS_ROOT)
    assert len(cases) == expected_count
    assert [case.version for case in cases] == [1] * expected_count
    assert all(case.specification.target is target for case in cases)
    # Deterministic ordering: sorted file names per family, families in
    # registered directory order.
    again = load_dataset(dataset_id, corpus_root=SCENARIOS_ROOT)
    assert [case.case_id for case in again] == [case.case_id for case in cases]


def test_load_dataset_research_agent_concatenates_both_families() -> None:
    """The research-agent dataset concatenates retrieval then synthesis."""
    from agentic_threat_investigator.evaluation.research.loader import (
        load_retrieval_scenarios_directory,
        load_synthesis_scenarios_directory,
    )

    cases = load_dataset(
        EvaluationDatasetId(target=EvaluationTarget.RESEARCH_AGENT, version=1),
        corpus_root=SCENARIOS_ROOT,
    )
    expected_ids = [
        scenario.id
        for scenario in load_retrieval_scenarios_directory(
            SCENARIOS_ROOT / "research" / "retrieval"
        )
    ] + [
        scenario.id
        for scenario in load_synthesis_scenarios_directory(
            SCENARIOS_ROOT / "research" / "synthesis"
        )
    ]
    assert [case.case_id for case in cases] == expected_ids
    assert "real-mitre-technique-relevant" in expected_ids
    assert "rag-s01-relevant-context" in expected_ids


def test_load_dataset_refuses_unregistered_target() -> None:
    """The investigation target has no PR 30A corpus and refuses loading."""
    dataset_id = EvaluationDatasetId(target=EvaluationTarget.INVESTIGATION, version=1)
    with pytest.raises(DatasetLoadError, match="no corpus"):
        load_dataset(dataset_id, corpus_root=SCENARIOS_ROOT)


def test_load_dataset_refuses_version_mismatch() -> None:
    """A dataset identity whose version mismatches the corpus fails closed."""
    dataset_id = EvaluationDatasetId(target=EvaluationTarget.GEOINT, version=99)
    with pytest.raises(DatasetLoadError, match="does not match"):
        load_dataset(dataset_id, corpus_root=SCENARIOS_ROOT)


def test_load_dataset_refuses_missing_corpus_root(tmp_path: Path) -> None:
    """A missing corpus root fails closed."""
    dataset_id = EvaluationDatasetId(target=EvaluationTarget.GEOINT, version=1)
    with pytest.raises(DatasetLoadError):
        load_dataset(dataset_id, corpus_root=tmp_path / "absent")


def test_all_committed_cases_carry_scenario_specific_metadata() -> None:
    """No committed case hides behind boilerplate purpose/relevance/risk.

    The frozen scenario-quality contract forbids generic filler such as
    "This scenario is relevant to ATI."; every field must be technically
    meaningful prose.
    """
    for target in (
        EvaluationTarget.EVIDENCE_ANALYST,
        EvaluationTarget.COORDINATOR,
        EvaluationTarget.GEOINT,
        EvaluationTarget.REPORT_WRITER,
        EvaluationTarget.RESEARCH_AGENT,
    ):
        for case in load_dataset(
            EvaluationDatasetId(target=target, version=1),
            corpus_root=SCENARIOS_ROOT,
        ):
            specification = case.specification
            assert (
                specification.title.endswith((".", "!"))
                or "." not in specification.title
            )
            assert specification.purpose.strip()
            assert specification.operational_relevance.strip()
            assert specification.regression_risk.strip()
            for field in (
                specification.purpose,
                specification.operational_relevance,
                specification.regression_risk,
                specification.description,
            ):
                lowered = field.lower()
                for banned in (
                    "relevant to ati",
                    "this scenario is relevant",
                    "this scenario tests",
                    "this scenario is about",
                    "unit test",
                ):
                    assert banned not in lowered, (case.case_id, field[:80])
            assert specification.expected_behavior.required
            assert specification.expected_behavior.forbidden


def test_validate_dataset_directory_matches_identity() -> None:
    """Directory validation returns the same identity as dataset loading."""
    for relative in [
        "analyst",
        "coordinator",
        "geoint",
        "report_writer",
        "research/retrieval",
        "research/synthesis",
    ]:
        dataset_id = validate_dataset_directory(SCENARIOS_ROOT / relative)
        cases = load_dataset(dataset_id, corpus_root=SCENARIOS_ROOT)
        assert len(cases) >= 1


def test_validate_dataset_directory_rejects_mixed_versions(tmp_path: Path) -> None:
    """A directory mixing versions is rejected as one dataset."""
    import json

    source = (
        SCENARIOS_ROOT / "geoint" / "01_g26g_s01_country_precision_only.json"
    ).read_bytes()
    first = json.loads(source)
    second = json.loads(source)
    first["id"] = "mixed-a"
    second["id"] = "mixed-b"
    second["version"] = 2
    (tmp_path / "a.json").write_text(json.dumps(first))
    (tmp_path / "b.json").write_text(json.dumps(second))
    with pytest.raises(DatasetLoadError, match="mixes versions"):
        validate_dataset_directory(tmp_path)


def test_validate_dataset_directory_rejects_missing_directory(tmp_path: Path) -> None:
    """A nonexistent directory fails closed."""
    with pytest.raises(DatasetLoadError):
        validate_dataset_directory(tmp_path / "absent")
