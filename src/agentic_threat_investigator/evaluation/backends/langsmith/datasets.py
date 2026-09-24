# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed dataset synchronization and read-only verification (PR 30B).

One-way projection only (``ATI repository -> LangSmith``): missing remote
datasets/examples are created, identical examples are no-ops, and any drift
(changed semantic digest, remote extra ATI identity, duplicate identity,
malformed metadata, unsupported projection schema, dataset identity
mismatch) fails closed instead of overwriting or deleting remote benchmark
content. Verification performs the same comparisons without any write.

Common models never acquire LangSmith identifiers; every remote UUID stays
inside bounded adapter DTOs.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from agentic_threat_investigator.evaluation.backends.langsmith.client import (
    LangSmithEvaluationClient,
)
from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
    DEFAULT_NAMESPACE,
    PROJECTION_SCHEMA_VERSION,
    LangSmithProjectionError,
    parse_dataset_metadata,
    parse_remote_metadata,
    project_dataset_metadata,
    project_dataset_name,
    projection_index,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithDatasetRef,
    LangSmithExampleMetadata,
    LangSmithExampleProjection,
    LangSmithExampleRef,
    LangSmithSyncReceipt,
    LangSmithVerifyReport,
)
from agentic_threat_investigator.evaluation.common.loader import (
    DatasetLoadError,
    validate_dataset_cases,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCase,
    EvaluationDatasetId,
    ScenarioLike,
    evaluation_case_from,
)

CaseIdentity = tuple[str, int]
"""Stable remote identity of one case: ``(case_id, case_version)``."""


class LangSmithSyncError(RuntimeError):
    """A fail-closed synchronization/verification failure.

    Drift (semantic digest mismatch), remote extra ATI identities,
    duplicate/malformed remote identities, unsupported projection schemas,
    and dataset identity mismatches all surface through this type; the
    command exits nonzero and nothing is overwritten or deleted.
    """


def _validate_local(
    scenarios: Sequence[ScenarioLike], *, dataset_id: EvaluationDatasetId
) -> tuple[EvaluationCase, ...]:
    """Strictly validate the loaded local scenarios as one dataset.

    Runs before any remote operation: a malformed local dataset means no
    LangSmith mutation attempt at all.
    """
    cases = tuple(evaluation_case_from(scenario) for scenario in scenarios)
    try:
        validate_dataset_cases(cases, dataset_id=dataset_id)
    except DatasetLoadError as exc:
        raise LangSmithSyncError(f"local dataset validation failed: {exc}") from exc
    if not cases:
        raise LangSmithSyncError("local dataset contains no cases")
    return cases


def _check_dataset_compatible(
    ref: LangSmithDatasetRef, *, dataset_id: EvaluationDatasetId
) -> None:
    """Fail closed unless the remote dataset is a compatible ATI mirror.

    A dataset that lacks ATI metadata is treated as foreign content;
    a metadata identity mismatch or an unsupported projection schema also
    fails closed. This is what prevents silently writing into or mutating
    a published/foreign dataset.
    """
    try:
        remote_dataset_id, schema_version = parse_dataset_metadata(ref.metadata)
    except LangSmithProjectionError as exc:
        raise LangSmithSyncError(
            f"remote dataset {ref.name!r} is not an ATI-managed mirror: {exc}"
        ) from exc
    if remote_dataset_id != dataset_id.canonical:
        raise LangSmithSyncError(
            f"remote dataset {ref.name!r} metadata identity {remote_dataset_id!r} "
            f"does not match {dataset_id.canonical}"
        )
    if schema_version != PROJECTION_SCHEMA_VERSION:
        raise LangSmithSyncError(
            f"remote dataset {ref.name!r} uses unsupported projection schema "
            f"v{schema_version} (supported: v{PROJECTION_SCHEMA_VERSION})"
        )


def _remote_index(
    refs: Sequence[LangSmithExampleRef],
) -> dict[CaseIdentity, LangSmithExampleMetadata]:
    """Index remote examples by stable ATI identity, failing on malformed/duplicate.

    Any example in an ATI dataset that does not carry a valid complete ATI
    identity is a fail-closed condition: the adapter never guesses what a
    foreign or malformed example means.
    """
    index: dict[CaseIdentity, LangSmithExampleMetadata] = {}
    for ref in refs:
        try:
            parsed = parse_remote_metadata(ref.metadata)
        except LangSmithProjectionError as exc:
            raise LangSmithSyncError(
                f"remote example {ref.example_id!r} has malformed ATI metadata: {exc}"
            ) from exc
        identity = (parsed.ati_case_id, parsed.ati_case_version)
        if identity in index:
            raise LangSmithSyncError(
                f"remote dataset carries duplicate ATI identity: "
                f"{identity[0]}@v{identity[1]}"
            )
        index[identity] = parsed
    return index


def _check_remote_identity(
    parsed: LangSmithExampleMetadata,
    *,
    dataset_id: EvaluationDatasetId,
    identity: CaseIdentity,
) -> None:
    """Fail closed when one remote example's ATI identity is inconsistent."""
    if parsed.ati_dataset_id != dataset_id.canonical:
        raise LangSmithSyncError(
            f"remote example {identity[0]}@v{identity[1]} belongs to dataset "
            f"{parsed.ati_dataset_id!r}, not {dataset_id.canonical}"
        )
    if parsed.ati_target != dataset_id.target.value:
        raise LangSmithSyncError(
            f"remote example {identity[0]}@v{identity[1]} declares target "
            f"{parsed.ati_target!r}, not {dataset_id.target.value}"
        )
    if parsed.ati_projection_schema_version != PROJECTION_SCHEMA_VERSION:
        raise LangSmithSyncError(
            f"remote example {identity[0]}@v{identity[1]} uses unsupported "
            f"projection schema v{parsed.ati_projection_schema_version} "
            f"(supported: v{PROJECTION_SCHEMA_VERSION})"
        )


def _diff_sync(
    *,
    dataset_id: EvaluationDatasetId,
    projections: Mapping[CaseIdentity, LangSmithExampleProjection],
    remote_refs: Sequence[LangSmithExampleRef],
) -> tuple[tuple[LangSmithExampleProjection, ...], int, int]:
    """Compare local projections against remote examples.

    Returns ``(missing_projections, created_count, unchanged_count)`` and
    fails closed on digest drift, remote extras, duplicates, malformed
    remote metadata, and identity mismatches. No overwrite and no delete is
    ever performed.
    """
    remote = _remote_index(remote_refs)
    missing: list[LangSmithExampleProjection] = []
    unchanged = 0
    for identity, projection in projections.items():
        parsed = remote.pop(identity, None)
        if parsed is None:
            missing.append(projection)
            continue
        _check_remote_identity(parsed, dataset_id=dataset_id, identity=identity)
        if parsed.ati_content_digest != projection.metadata.ati_content_digest:
            raise LangSmithSyncError(
                "drift detected: case "
                f"{identity[0]}@v{identity[1]} changed semantic content "
                "(digest mismatch); refusing to overwrite the published example"
            )
        unchanged += 1
    if remote:
        extras = ", ".join(
            sorted(f"{case_id}@v{version}" for case_id, version in remote)
        )
        raise LangSmithSyncError(
            "remote dataset owns ATI identities absent locally: "
            f"{extras}; refusing to delete remote content"
        )
    created = len(missing)
    return tuple(missing), created, unchanged


async def synchronize_dataset(
    *,
    dataset_id: EvaluationDatasetId,
    client: LangSmithEvaluationClient,
    scenarios: Sequence[ScenarioLike],
    namespace: str = DEFAULT_NAMESPACE,
) -> LangSmithSyncReceipt:
    """Idempotently synchronize one canonical ATI dataset onto LangSmith.

    Local validation always runs first (malformed local => no remote
    operation). Missing datasets/examples are created batched; identical
    examples are no-ops; drift/extras/duplicates fail closed. Repeated exact
    synchronization performs zero semantic changes, zero updates, and zero
    deletes.
    """
    _validate_local(scenarios, dataset_id=dataset_id)
    projections = projection_index(scenarios, dataset_id=dataset_id)
    name = project_dataset_name(dataset_id, namespace=namespace)
    existing = await client.find_dataset(name=name)
    if existing is None:
        dataset_ref = await client.create_dataset(
            name=name, metadata=project_dataset_metadata(dataset_id)
        )
        created = len(projections)
        unchanged = 0
        if projections:
            await client.create_examples(
                dataset=dataset_ref, examples=tuple(projections.values())
            )
    else:
        _check_dataset_compatible(existing, dataset_id=dataset_id)
        remote_refs = await client.list_examples(dataset=existing)
        missing, created, unchanged = _diff_sync(
            dataset_id=dataset_id,
            projections=projections,
            remote_refs=remote_refs,
        )
        if missing:
            await client.create_examples(dataset=existing, examples=missing)
    return LangSmithSyncReceipt(
        dataset=name,
        local_cases=len(projections),
        created=created,
        unchanged=unchanged,
        status="synchronized",
    )


async def verify_dataset(
    *,
    dataset_id: EvaluationDatasetId,
    client: LangSmithEvaluationClient,
    scenarios: Sequence[ScenarioLike],
    namespace: str = DEFAULT_NAMESPACE,
) -> LangSmithVerifyReport:
    """Read-only exact-mirror verification of one ATI dataset on LangSmith.

    Checks: dataset exists; dataset identity metadata matches; projection
    schema supported; identity sets match exactly; every digest matches;
    no duplicate or malformed remote ATI identities. Performs no writes.
    """
    _validate_local(scenarios, dataset_id=dataset_id)
    projections = projection_index(scenarios, dataset_id=dataset_id)
    name = project_dataset_name(dataset_id, namespace=namespace)
    existing = await client.find_dataset(name=name)
    if existing is None:
        raise LangSmithSyncError(f"remote dataset {name!r} does not exist")
    _check_dataset_compatible(existing, dataset_id=dataset_id)
    remote_refs = await client.list_examples(dataset=existing)
    remote = _remote_index(remote_refs)
    local_identities = set(projections)
    remote_identities = set(remote)
    if remote_identities != local_identities:
        missing = sorted(
            f"{case_id}@v{version}"
            for case_id, version in (local_identities - remote_identities)
        )
        extras = sorted(
            f"{case_id}@v{version}"
            for case_id, version in (remote_identities - local_identities)
        )
        raise LangSmithSyncError(
            "remote identity set differs from the local dataset: "
            f"missing {missing or 'none'}; extra {extras or 'none'}"
        )
    for identity, projection in projections.items():
        parsed = remote[identity]
        _check_remote_identity(parsed, dataset_id=dataset_id, identity=identity)
        if parsed.ati_content_digest != projection.metadata.ati_content_digest:
            raise LangSmithSyncError(
                f"digest mismatch for case {identity[0]}@v{identity[1]}: "
                "remote content differs from the authored semantics"
            )
    return LangSmithVerifyReport(
        dataset=name,
        local_cases=len(projections),
        remote_examples=len(remote_refs),
        status="verified",
    )
