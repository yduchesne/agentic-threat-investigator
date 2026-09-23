# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A repository-owned dataset discovery and loading.

A dataset is the unit of benchmark identity: one
:class:`~agentic_threat_investigator.evaluation.common.models.EvaluationTarget`
plus one version, canonical form ``<target>/v<version>``. A target may own
several scenario families (``research-agent`` owns retrieval and synthesis);
loading concatenates every family's corpus in deterministic directory and
sorted-filename order and validates the dataset-level identity contract
(unique case IDs, uniform version, matching target).

Discovery is fully offline: no LangSmith, no LLM, no network.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from agentic_threat_investigator.evaluation.analyst.loader import (
    load_scenarios_directory,
)
from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationCase,
    EvaluationDatasetId,
    EvaluationTarget,
    evaluation_case_from,
    validate_dataset_cases,
)
from agentic_threat_investigator.evaluation.common.loader import infer_target
from agentic_threat_investigator.evaluation.common.models import ScenarioLike
from agentic_threat_investigator.evaluation.coordinator import (
    load_coordinator_scenarios_directory,
)
from agentic_threat_investigator.evaluation.geoint.loader import (
    load_geoint_scenarios_directory,
)
from agentic_threat_investigator.evaluation.report_writer.loader import (
    load_report_writer_scenarios_directory,
)
from agentic_threat_investigator.evaluation.research.loader import (
    load_retrieval_scenarios_directory,
    load_synthesis_scenarios_directory,
)

SCENARIOS_ROOT = Path("evals/scenarios")
"""Repository-relative root of the canonical scenario corpus."""

_TARGET_CORPORA: Mapping[EvaluationTarget, tuple[Path, ...]] = {
    EvaluationTarget.EVIDENCE_ANALYST: (Path("analyst"),),
    EvaluationTarget.COORDINATOR: (Path("coordinator"),),
    EvaluationTarget.GEOINT: (Path("geoint"),),
    EvaluationTarget.REPORT_WRITER: (Path("report_writer"),),
    EvaluationTarget.RESEARCH_AGENT: (
        Path("research/retrieval"),
        Path("research/synthesis"),
    ),
    EvaluationTarget.INVESTIGATION: (),
}
"""Deterministic target-to-corpus-directory mapping, mirroring the evaluator families."""

_FamilyLoader = Callable[[Path], tuple[ScenarioLike, ...]]

_FAMILY_LOADERS: Mapping[tuple[EvaluationTarget, Path], _FamilyLoader] = {
    (EvaluationTarget.EVIDENCE_ANALYST, Path("analyst")): load_scenarios_directory,
    (EvaluationTarget.COORDINATOR, Path("coordinator")): (
        load_coordinator_scenarios_directory
    ),
    (EvaluationTarget.GEOINT, Path("geoint")): load_geoint_scenarios_directory,
    (EvaluationTarget.REPORT_WRITER, Path("report_writer")): (
        load_report_writer_scenarios_directory
    ),
    (EvaluationTarget.RESEARCH_AGENT, Path("research/retrieval")): (
        load_retrieval_scenarios_directory
    ),
    (EvaluationTarget.RESEARCH_AGENT, Path("research/synthesis")): (
        load_synthesis_scenarios_directory
    ),
}


def load_evaluation_scenarios(
    dataset_id: EvaluationDatasetId,
    *,
    corpus_root: Path = SCENARIOS_ROOT,
) -> tuple[ScenarioLike, ...]:
    """Strictly load the fully typed scenarios of one canonical dataset.

    PR 30B's LangSmith projection needs the complete authored scenario
    objects (``AnalystScenario``, ``CoordinatorScenario``, ...) rather than
    only their common :class:`EvaluationCase` projection, because the
    truthful semantic digest covers every typed semantic field (including
    target-specific fixtures and expectation envelopes). The common
    projection alone would silently hide a target-specific semantic
    change. Dataset-level identity validation still runs exactly as in
    :func:`load_evaluation_dataset`.

    Raises :class:`DatasetLoadError` under the same fail-closed conditions
    as :func:`load_evaluation_dataset`.
    """
    relatives = _TARGET_CORPORA[dataset_id.target]
    if not relatives:
        raise DatasetLoadError(
            f"no corpus is registered for target {dataset_id.target.value}: "
            f"{dataset_id.canonical}"
        )
    scenarios: list[ScenarioLike] = []
    for relative in relatives:
        loader = _FAMILY_LOADERS[(dataset_id.target, relative)]
        directory = Path(corpus_root) / relative
        try:
            scenarios.extend(loader(directory))
        except Exception as exc:
            raise DatasetLoadError(
                f"cannot load {dataset_id.canonical} corpus "
                f"{relative}: {type(exc).__name__}: {exc}",
                path=directory,
            ) from exc
    validate_dataset_cases(
        [evaluation_case_from(scenario) for scenario in scenarios],
        dataset_id=dataset_id,
    )
    return tuple(scenarios)


def load_evaluation_dataset(
    dataset_id: EvaluationDatasetId,
    *,
    corpus_root: Path = SCENARIOS_ROOT,
) -> tuple[EvaluationCase, ...]:
    """Strictly load one canonical dataset and validate its identity.

    Note: the explicit ``evaluation`` name keeps this repository dataloader
    distinct from third-party ``load_dataset`` APIs (for example Hugging
    Face Hub), so the security scanner never confuses the two.

    Raises :class:`DatasetLoadError` when the target owns no corpus, a
    family fails to load, or the loaded cases violate the dataset-level
    identity contract (empty dataset, duplicate case IDs, mixed versions,
    or a target mismatch).
    """
    return tuple(
        evaluation_case_from(scenario)
        for scenario in load_evaluation_scenarios(dataset_id, corpus_root=corpus_root)
    )


def _common_version(cases: list[EvaluationCase]) -> int:
    """Return the uniform case version, refusing a mixed-version directory."""
    versions = {case.version for case in cases}
    if len(versions) != 1:
        raise DatasetLoadError(
            "scenario directory mixes versions: "
            + ", ".join(str(version) for version in sorted(versions))
        )
    return next(iter(versions))


def validate_dataset_directory(
    directory: Path | str,
) -> EvaluationDatasetId:
    """Strictly validate one scenario directory as a dataset.

    The target is inferred from the directory's ``specification.target``
    declarations; the appropriate typed family loader then validates every
    file strict-fail-closed, and the dataset-level identity contract is
    enforced. Returns the canonical dataset identity on success and raises
    :class:`DatasetLoadError` otherwise.
    """
    root = Path(directory)
    target = infer_target(root)
    failures: list[str] = []
    for relative, loader in _FAMILY_LOADERS.items():
        if relative[0] is not target:
            continue
        try:
            scenarios = loader(root)
        except Exception as exc:  # noqa: BLE001 - typed load errors are collected below
            failures.append(f"{relative[1]}: {type(exc).__name__}: {exc}")
            continue
        cases = [evaluation_case_from(scenario) for scenario in scenarios]
        try:
            version = _common_version(cases)
        except DatasetLoadError as exc:
            raise DatasetLoadError(str(exc), path=root) from exc
        dataset_id = EvaluationDatasetId(target=target, version=version)
        validate_dataset_cases(cases, dataset_id=dataset_id)
        return dataset_id
    raise DatasetLoadError(
        "cannot load scenario directory as a dataset: " + "; ".join(failures),
        path=root,
    )
