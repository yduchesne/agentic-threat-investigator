# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A strict scenario/dataset loading and common validation.

Scenario loading is fail-closed: invalid UTF-8, malformed JSON, duplicate
JSON object keys at any nesting depth, non-object documents, unknown
fields (enforced by the strict typed models), and dataset-level identity
violations all raise typed errors. Discovery order is deterministic, and
no loader performs network I/O or invokes an LLM.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCase,
    EvaluationDatasetId,
    EvaluationTarget,
)


class DuplicateJsonKeyError(ValueError):
    """A JSON object repeats one key at any nesting depth."""

    def __init__(self, key: str) -> None:
        """Record the duplicated key name."""
        super().__init__(f"duplicate JSON object key: {key!r}")
        self.key = key


class DatasetLoadError(ValueError):
    """A dataset directory or identity cannot be loaded or validated.

    The runner refuses to start on a malformed dataset; this error type is
    the deterministic fail-closed seam for dataset validation.
    """

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        """Record the message and optional offending path."""
        suffix = f" ({path})" if path is not None else ""
        super().__init__(f"{message}{suffix}")
        self.path = path


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    """Build a dict from JSON object pairs, rejecting any repeated key.

    ``json.loads`` applies this hook at every nesting depth automatically,
    so a duplicated key anywhere in the document fails closed.
    """
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(key)
        result[key] = value
    return result


def read_json_object(path: Path) -> dict[str, object]:
    """Decode one strict JSON object document.

    Invalid UTF-8, malformed JSON, duplicate keys, and non-object documents
    raise :class:`ValueError` with the offending path in the message.
    """
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    try:
        raw: object = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"scenario document must be a JSON object: {path}")
    return raw


class _SpecificationIdentity(BaseModel):
    """Raw ``specification`` identity probe used for target inference.

    The probe intentionally ignores every field except ``target`` so it can
    run before the strict typed loader; unknown fields are never an error
    here because full strict validation is the typed model's job.
    """

    model_config = ConfigDict(extra="ignore")

    target: EvaluationTarget


class _DatasetIdentity(BaseModel):
    """Raw top-level dataset identity extracted from one scenario document.

    This narrow probe only infers a directory's target before the strict
    typed loader runs; full strict validation remains the typed model's
    job.
    """

    model_config = ConfigDict(extra="ignore")

    specification: _SpecificationIdentity


def infer_target(path: Path) -> EvaluationTarget:
    """Infer the single target of a scenario directory.

    Every ``*.json`` file must declare the same valid
    ``specification.target`` value; a directory mixing targets (for example
    research retrieval and synthesis files together) is rejected because it
    cannot be validated as one dataset.
    """
    root = Path(path)
    if not root.is_dir():
        raise DatasetLoadError("scenario directory does not exist", path=root)
    ordered_paths = sorted(root.glob("*.json"), key=lambda item: item.name)
    if not ordered_paths:
        raise DatasetLoadError("scenario directory contains no JSON files", path=root)
    target: EvaluationTarget | None = None
    for scenario_path in ordered_paths:
        try:
            raw = read_json_object(scenario_path)
        except ValueError as exc:
            raise DatasetLoadError(str(exc), path=scenario_path) from exc
        try:
            detected = _DatasetIdentity.model_validate(raw).specification.target
        except (ValidationError, ValueError) as exc:
            raise DatasetLoadError(
                f"cannot detect target: {exc}", path=scenario_path
            ) from exc
        if target is None:
            target = detected
        elif detected is not target:
            raise DatasetLoadError(
                "scenario directory mixes targets: "
                f"{target.value} and {detected.value}",
                path=scenario_path,
            )
    if target is None:  # pragma: no cover - directory nonempty above
        raise DatasetLoadError("scenario directory has no target", path=root)
    return target


def validate_dataset_id(value: EvaluationDatasetId) -> None:
    """Validate that a dataset identity round-trips through canonical form.

    The identity model already enforces the target vocabulary and a
    positive version at construction; this seam gives dataset validation one
    stable check site and can grow PR 30B immutability rules without
    touching callers.
    """
    parsed = EvaluationDatasetId.from_canonical(value.canonical)
    if parsed != value:
        raise DatasetLoadError(f"dataset identity is not canonical: {value.canonical}")


def validate_dataset_cases(
    cases: Sequence[EvaluationCase],
    *,
    dataset_id: EvaluationDatasetId,
) -> None:
    """Fail closed on dataset-level identity violations.

    Enforces: case IDs unique within the dataset version; every case
    carrying the dataset version; and every case's specification target
    matching the dataset target. A dataset with no cases is rejected.
    """
    if not cases:
        raise DatasetLoadError("a dataset must contain at least one case")
    seen: set[str] = set()
    for case in cases:
        if case.case_id in seen:
            raise DatasetLoadError(f"duplicate case id in dataset: {case.case_id}")
        seen.add(case.case_id)
        if case.version != dataset_id.version:
            raise DatasetLoadError(
                f"case {case.case_id!r} version {case.version} does not match "
                f"dataset version {dataset_id.version}"
            )
        if case.specification.target is not dataset_id.target:
            raise DatasetLoadError(
                f"case {case.case_id!r} target {case.specification.target.value} "
                f"does not match dataset target {dataset_id.target.value}"
            )
