# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A scenario-quality validation tests (EVAL-S01..S15).

These tests freeze the canonical scenario-quality contract: every case must
carry the mandatory descriptive fields, a nonempty required/forbidden
behavior contract, valid architecture references, and strict
unknown-field rejection; the dataset loader additionally enforces unique
case IDs, dataset version/target consistency, and fail-closed strict
loading.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    DuplicateJsonKeyError,
    EvaluationCase,
    EvaluationDatasetId,
    EvaluationTarget,
    ExpectedBehavior,
    ScenarioSpecification,
    read_json_object,
)
from agentic_threat_investigator.evaluation.common.loader import (
    infer_target,
    validate_dataset_cases,
)
from tests.support.evaluation_common import unit_specification

TARGET = EvaluationTarget.EVIDENCE_ANALYST


def _case(
    *,
    case_id: str = "unit-case",
    version: int = 1,
    spec: ScenarioSpecification | None = None,
) -> EvaluationCase:
    """Build one canonical common case for dataset validation tests."""
    return EvaluationCase.from_scenario(
        case_id=case_id,
        version=version,
        specification=spec or unit_specification(),
    )


def _dataset(version: int = 1) -> EvaluationDatasetId:
    """Build one dataset identity."""
    return EvaluationDatasetId(target=TARGET, version=version)


# EVAL-S01 fully described case loads.


def test_s01_fully_described_case_loads() -> None:
    """A fully described case loads with all mandatory fields present."""
    spec = unit_specification()
    case = _case(spec=spec)
    assert case.case_id == "unit-case"
    assert case.specification.title
    assert case.specification.description
    assert case.specification.purpose
    assert case.specification.operational_relevance
    assert case.specification.regression_risk
    assert case.specification.expected_behavior.required
    assert case.specification.expected_behavior.forbidden
    assert case.specification.architecture_refs


# EVAL-S02..S06 missing mandatory narrative fields are rejected.


@pytest.mark.parametrize(
    "field",
    [
        "title",
        "description",
        "purpose",
        "operational_relevance",
        "regression_risk",
    ],
)
def test_s02_to_s06_missing_narrative_field_rejected(field: str) -> None:
    """A missing mandatory narrative field fails closed."""
    payload = unit_specification().model_dump()
    del payload[field]
    with pytest.raises(ValidationError):
        ScenarioSpecification.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    [
        "title",
        "description",
        "purpose",
        "operational_relevance",
        "regression_risk",
    ],
)
def test_blank_narrative_field_rejected(field: str) -> None:
    """A blank mandatory narrative field fails closed."""
    with pytest.raises(ValidationError):
        unit_specification(**{field: "   "})


# EVAL-S07..S09 expected-behavior contract.


def test_s07_both_required_and_forbidden_empty_rejected() -> None:
    """An expected behavior with both lists empty is rejected."""
    with pytest.raises(ValidationError):
        unit_specification(expected_behavior=ExpectedBehavior())


def test_s08_blank_behavior_item_rejected() -> None:
    """A blank required or forbidden behavior item is rejected."""
    with pytest.raises(ValidationError):
        unit_specification(
            expected_behavior=ExpectedBehavior(required=("ok",), forbidden=(" ",))
        )
    with pytest.raises(ValidationError):
        unit_specification(
            expected_behavior=ExpectedBehavior(required=("   ",), forbidden=("ok",))
        )


def test_s09_normalized_duplicate_behavior_rejected() -> None:
    """Behavior duplicates after whitespace normalization are rejected."""
    with pytest.raises(ValidationError):
        unit_specification(
            expected_behavior=ExpectedBehavior(
                required=("same statement", "  same  statement "),
                forbidden=("other",),
            )
        )


def test_expected_behavior_statements_canonical() -> None:
    """Statements are canonicalized prose, never blank or duplicate."""
    behavior = unit_specification().expected_behavior
    assert all(
        statement == " ".join(statement.split()) for statement in behavior.required
    )
    assert all(
        statement == " ".join(statement.split()) for statement in behavior.forbidden
    )


# EVAL-S11 invalid dataset version/target vocabulary.


def test_s11_invalid_dataset_version_rejected() -> None:
    """A non-positive dataset version is rejected by the identity model."""
    with pytest.raises(ValidationError):
        EvaluationDatasetId(target=TARGET, version=0)


def test_unknown_target_rejected() -> None:
    """An unknown target string fails closed during canonical parsing."""
    with pytest.raises(ValueError):
        EvaluationDatasetId.from_canonical("unknown-target/v1")


# EVAL-S10 unique case IDs within a dataset version.


def test_s10_duplicate_case_id_rejected() -> None:
    """Duplicate case IDs within one dataset version are rejected."""
    cases = (_case(case_id="dup"), _case(case_id="dup"))
    with pytest.raises(DatasetLoadError):
        validate_dataset_cases(cases, dataset_id=_dataset())


def test_case_id_must_be_stable() -> None:
    """Case ids follow the stable lowercase identifier contract."""
    with pytest.raises(ValueError):
        _case(case_id="Not Stable!")


# EVAL-S12 target/version mismatch rejected.


def test_s12_target_mismatch_rejected() -> None:
    """A case whose specification target differs from the dataset is rejected."""
    other_spec = unit_specification(target=EvaluationTarget.COORDINATOR)
    with pytest.raises(DatasetLoadError):
        validate_dataset_cases((_case(spec=other_spec),), dataset_id=_dataset())


def test_version_mismatch_rejected() -> None:
    """A case carrying a version different from the dataset is rejected."""
    with pytest.raises(DatasetLoadError):
        validate_dataset_cases((_case(version=2),), dataset_id=_dataset())


def test_empty_dataset_rejected() -> None:
    """A dataset with zero cases is rejected."""
    with pytest.raises(DatasetLoadError):
        validate_dataset_cases((), dataset_id=_dataset())


# EVAL-S13 architecture references.


def test_s13_invalid_or_duplicate_architecture_refs_rejected() -> None:
    """Invalid and duplicate architecture references fail closed."""
    with pytest.raises(ValidationError):
        unit_specification(architecture_refs=("Invalid Ref!",))
    with pytest.raises(ValidationError):
        unit_specification(architecture_refs=("dup", "dup"))


# EVAL-S14 unknown fields fail closed.


def test_s15_target_specific_validation_still_executes() -> None:
    """Target-specific fixture and expectation validation still runs.

    Composing the common specification must never disable the target
    envelope's fail-closed validation: an otherwise well-described case
    with an empty typed verdict envelope is still rejected.
    """
    import json

    from agentic_threat_investigator.evaluation.analyst.models import (
        AnalystScenario,
    )
    from tests.support.evaluation_fixtures import unit_scenario

    raw = json.loads(unit_scenario().model_dump_json())
    raw["expected"]["allowed_verdicts"] = []
    with pytest.raises(ValidationError):
        AnalystScenario.model_validate(raw)
    # The same raw document with a valid typed envelope still loads.
    raw["expected"]["allowed_verdicts"] = ["malicious"]
    assert AnalystScenario.model_validate(raw).specification.title == "Unit scenario"


def test_s14_unknown_fields_fail_closed() -> None:
    """Unknown specification fields are rejected under the strict model."""
    payload = unit_specification().model_dump()
    payload["sneaky_field"] = True
    with pytest.raises(ValidationError):
        ScenarioSpecification.model_validate(payload)


def test_tags_normalized_and_unique() -> None:
    """Tags are normalized, unique, and bounded while never correctness."""
    spec = unit_specification(tags=("  descriptive  tag ", "unit"))
    assert "descriptive tag" in spec.tags
    with pytest.raises(ValidationError):
        unit_specification(tags=("dup", "dup"))
    with pytest.raises(ValidationError):
        unit_specification(tags=("   ",))


# Strict JSON document loading.


def test_read_json_object_rejects_duplicate_keys(tmp_path: Path) -> None:
    """Duplicate JSON object keys fail closed at any nesting depth."""
    path = tmp_path / "dup.json"
    path.write_text(
        '{"id": "a", "specification": {"target": "geoint", "target": "nope"}}'
    )
    with pytest.raises(DuplicateJsonKeyError):
        read_json_object(path)


def test_read_json_object_rejects_malformed(tmp_path: Path) -> None:
    """Malformed JSON and non-object documents fail closed."""
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    with pytest.raises(ValueError):
        read_json_object(broken)
    array = tmp_path / "array.json"
    array.write_text("[1, 2]")
    with pytest.raises(ValueError):
        read_json_object(array)


def test_infer_target_requires_agreement(tmp_path: Path) -> None:
    """A directory mixing targets is rejected during target inference."""
    (tmp_path / "a.json").write_text(
        json.dumps({"specification": {"target": "geoint"}})
    )
    (tmp_path / "b.json").write_text(
        json.dumps({"specification": {"target": "coordinator"}})
    )
    with pytest.raises(DatasetLoadError):
        infer_target(tmp_path)


def test_infer_target_detects_single_target(tmp_path: Path) -> None:
    """A directory with one declared target infers deterministically."""
    (tmp_path / "a.json").write_text(
        json.dumps({"specification": {"target": "geoint"}})
    )
    assert infer_target(tmp_path) is EvaluationTarget.GEOINT


def test_infer_target_rejects_empty_directory(tmp_path: Path) -> None:
    """An empty scenario directory has no inferable target."""
    with pytest.raises(DatasetLoadError):
        infer_target(tmp_path)


def test_validate_dataset_id_canonical() -> None:
    """Dataset identity validation accepts the canonical identity."""
    from agentic_threat_investigator.evaluation.common.loader import (
        validate_dataset_id,
    )

    validate_dataset_id(_dataset())
