# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C minimum LangSmith experiment execution adapter.

Associates one completed ATI benchmark execution with one LangSmith
experiment without ever re-executing the target: ATI runs the real Evidence
Analyst once per case through the common runner, and this module only wraps
the resulting :class:`EvaluationRunResult`:

.. code-block:: text

    EvaluationRunResult
     -> create one experiment run (semantic name + execution identity)
     -> publish PR 30B categorical feedback onto that run
     -> confirm remote state (experiment exists, association present,
        categorical feedback accepted)

No data/evaluator is passed to LangSmith, ``evaluate()``/``aevaluate()`` are
never invoked (they would execute the target a second time), and remote
averages never determine ATI correctness. The dataset mirror must already
have been verified by the caller before any model execution; this module
never silently syncs drift.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from agentic_threat_investigator.evaluation.backends.langsmith.client import (
    LangSmithEvaluationClient,
)
from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
    DEFAULT_NAMESPACE,
    PROJECTION_SCHEMA_VERSION,
    project_dataset_name,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithExperimentConfirmation,
    LangSmithExperimentRef,
    LangSmithFeedbackItem,
)
from agentic_threat_investigator.evaluation.backends.langsmith.results import (
    build_publication,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationDatasetId,
    EvaluationRunResult,
    JsonValue,
)

_EXECUTION_ID_RE = re.compile(r"^[a-f0-9]{8,64}$")
"""Stable lowercase hexadecimal execution identifier of bounded length."""


class LangSmithExperimentError(RuntimeError):
    """A fail-closed LangSmith experiment publication/confirmation failure.

    The message is bounded and sanitized by the caller; credentials and raw
    API payloads are never included.
    """


def experiment_name(
    dataset_id: EvaluationDatasetId,
    *,
    execution_id: str,
    commit_sha: str | None = None,
    namespace: str = DEFAULT_NAMESPACE,
) -> str:
    """Return the deterministic semantic experiment name.

    Shape: ``<namespace>/<dataset>/<short-sha|local>/<execution-id>``. The
    namespace is validated through PR 30B's projection contract so an
    invalid namespace fails before any remote call.
    """
    if not _EXECUTION_ID_RE.fullmatch(execution_id):
        raise LangSmithExperimentError(
            "execution_id must be a stable lowercase hexadecimal identity"
        )
    short_sha = (commit_sha or "").strip()[:12] or "local"
    return f"{project_dataset_name(dataset_id, namespace=namespace)}/{short_sha}/{execution_id}"


def confirm_experiment(
    *,
    ref: LangSmithExperimentRef,
    observed: LangSmithExperimentRef | None,
    feedback: Sequence[LangSmithFeedbackItem],
    expected_feedback: Mapping[str, str],
) -> LangSmithExperimentConfirmation:
    """Confirm the remote state of one published experiment.

    Fails closed unless: the experiment run exists under the exact created
    identity and name; and the categorical feedback read back equals exactly
    the publication that ATI projected (which itself carries the run-level
    status, every case association, and every evaluator result). No score,
    average, or threshold is ever involved.
    """
    if observed is None or observed.run_id != ref.run_id:
        raise LangSmithExperimentError(
            f"remote experiment run {ref.run_id!r} does not exist"
        )
    if observed.name != ref.name:
        raise LangSmithExperimentError(
            f"remote experiment name {observed.name!r} does not match the "
            f"created experiment {ref.name!r}"
        )
    if not expected_feedback:
        raise LangSmithExperimentError("a publication must carry feedback")
    remote = {item.key: item.value for item in feedback}
    if remote != dict(expected_feedback):
        missing = sorted(set(expected_feedback) - set(remote))
        changed = sorted(
            key for key, value in expected_feedback.items() if remote.get(key) != value
        )
        raise LangSmithExperimentError(
            "categorical feedback was not fully accepted: "
            f"missing={missing or 'none'} changed={changed or 'none'}"
        )
    return LangSmithExperimentConfirmation(
        run_id=ref.run_id,
        experiment_name=ref.name,
        feedback_count=len(feedback),
        status="confirmed",
    )


def build_experiment_metadata_envelope(
    *,
    dataset_id: EvaluationDatasetId,
    run: EvaluationRunResult,
    extra: Mapping[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """Build the bounded ``ati.`` metadata envelope of one experiment run.

    Combines the dataset identity, projection schema version, every case
    identity (the expected case/run association), and the optional bounded
    experiment metadata produced by PR 30B's ``build_experiment_metadata``.
    No secrets, prompts, raw outputs, or chain-of-thought are accepted.
    """
    envelope: dict[str, JsonValue] = {
        "ati.dataset_id": dataset_id.canonical,
        "ati.projection_schema_version": PROJECTION_SCHEMA_VERSION,
        "ati.experiment.case_ids": [case.case_id for case in run.cases],
    }
    envelope.update(extra or {})
    return envelope


async def publish_experiment(
    *,
    dataset_id: EvaluationDatasetId,
    run: EvaluationRunResult,
    client: LangSmithEvaluationClient,
    execution_id: str,
    namespace: str = DEFAULT_NAMESPACE,
    commit_sha: str | None = None,
    metadata: Mapping[str, JsonValue] | None = None,
) -> LangSmithExperimentConfirmation:
    """Create one experiment run, publish categorical feedback, and confirm.

    Never re-executes the target: the run payload records the ATI execution
    identity and the publication is built from the already-completed
    :class:`EvaluationRunResult`. The dataset mirror is never synced here;
    the caller verifies it before any model execution.
    """
    name = experiment_name(
        dataset_id,
        execution_id=execution_id,
        commit_sha=commit_sha,
        namespace=namespace,
    )
    publication = build_publication(run)
    envelope = build_experiment_metadata_envelope(
        dataset_id=dataset_id, run=run, extra=metadata
    )
    ref = await client.create_experiment(name=name, metadata=envelope)
    await client.publish_feedback(run_id=ref.run_id, publication=publication)
    observed = await client.read_experiment(run_id=ref.run_id)
    feedback = await client.list_feedback(run_id=ref.run_id)
    return confirm_experiment(
        ref=ref,
        observed=observed,
        feedback=feedback,
        expected_feedback={item.key: item.value for item in publication.feedback},
    )
