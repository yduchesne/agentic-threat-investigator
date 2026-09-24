# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Narrow injectable LangSmith evaluation client boundary (PR 30B/30C).

The :class:`LangSmithEvaluationClient` protocol declares only the operations
PR 30B and PR 30C need (dataset/examples sync and verification, categorical
feedback publication, and the PR 30C experiment-run operations); SDK-specific
objects stay behind the wrapper and unit tests inject an in-memory fake. The
real :class:`LangSmithSdkEvaluationClient` constructs the installed
``langsmith.Client`` from the standard environment, runs blocking SDK calls
off the event loop, converts ordinary failures into bounded
:class:`LangSmithBackendError` failures (fail-closed for explicit operator
commands), never logs credentials, and never catches ``CancelledError`` so
cancellation propagates unchanged.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import Mapping, Sequence
from typing import Any, Protocol
from uuid import uuid4

from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithDatasetRef,
    LangSmithEvaluationPublication,
    LangSmithExampleProjection,
    LangSmithExampleRef,
    LangSmithExperimentRef,
    LangSmithFeedbackItem,
    bound_remote_metadata,
)
from agentic_threat_investigator.evaluation.common.models import (
    JsonValue,
    sanitize_explanation,
)

LANGSMITH_DEFAULT_SPLIT = "train"
"""LangSmith default dataset split into which ATI projections are written."""


class LangSmithBackendError(RuntimeError):
    """A bounded, fail-closed failure of the LangSmith evaluation backend.

    The message is sanitized and bounds-length-truncated; resolved
    credentials and arbitrary API payloads are never included.
    """


class LangSmithEvaluationClient(Protocol):
    """Narrow ATI-owned boundary over whatever LangSmith SDK is installed.

    All operations are async and take/return bounded adapter DTOs only;
    implementations must never leak raw SDK objects through this interface.
    Implementations must propagate :class:`asyncio.CancelledError`
    unchanged and raise :class:`LangSmithBackendError` for bounded backend
    failures.
    """

    async def find_dataset(self, *, name: str) -> LangSmithDatasetRef | None:
        """Return exactly one dataset named ``name``, ``None`` when absent.

        An ambiguous match (more than one dataset resolving to the name)
        fails closed.
        """
        ...

    async def create_dataset(
        self, *, name: str, metadata: Mapping[str, JsonValue]
    ) -> LangSmithDatasetRef:
        """Create one dataset with the bounded ATI dataset metadata."""
        ...

    async def list_examples(
        self, *, dataset: LangSmithDatasetRef
    ) -> tuple[LangSmithExampleRef, ...]:
        """Return every example of one dataset as bounded refs."""
        ...

    async def create_examples(
        self,
        *,
        dataset: LangSmithDatasetRef,
        examples: Sequence[LangSmithExampleProjection],
    ) -> int:
        """Create exactly the supplied examples and return the reported count.

        Batch creation only: no per-example retry policy is implemented in
        PR 30B.
        """
        ...

    async def publish_feedback(
        self,
        *,
        run_id: str,
        publication: LangSmithEvaluationPublication,
    ) -> None:
        """Publish one categorical ATI publication onto an existing run.

        The run is the PR 30C+ experiment run; PR 30B only defines the
        boundary and the mapping, never a real target execution.
        """
        ...

    async def create_experiment(
        self, *, name: str, metadata: Mapping[str, JsonValue]
    ) -> LangSmithExperimentRef:
        """Create one ATI experiment run and return its adapter-owned reference.

        The run records the ATI execution identity; categorical feedback is
        published separately through :meth:`publish_feedback`. No target is
        executed here and no data/evaluator is ever re-run.
        """
        ...

    async def read_experiment(self, *, run_id: str) -> LangSmithExperimentRef | None:
        """Return one experiment run's bounded reference, ``None`` when absent.

        Only the run identity, name, and bounded ``ati.`` metadata are
        retained; untrusted run payloads never escape the adapter.
        """
        ...

    async def list_feedback(self, *, run_id: str) -> tuple[LangSmithFeedbackItem, ...]:
        """Return every bounded categorical feedback item published on a run."""
        ...


def _default_sdk() -> Any:
    """Construct the installed ``langsmith.Client`` from the standard environment."""
    from langsmith import Client

    return Client()


def _bounded_error(operation: str, exc: Exception) -> LangSmithBackendError:
    """Convert one SDK exception into a sanitized bounded backend error."""
    message = sanitize_explanation(f"{type(exc).__name__}: {exc}")
    return LangSmithBackendError(f"LangSmith {operation} failed: {message}")


def _dataset_dto(dataset: Any) -> LangSmithDatasetRef:
    """Convert one SDK dataset object into its bounded adapter DTO."""
    metadata: dict[str, JsonValue] = bound_remote_metadata(
        getattr(dataset, "metadata", None)
    )
    return LangSmithDatasetRef(
        name=str(getattr(dataset, "name", "")),
        dataset_id=str(getattr(dataset, "id", "")),
        example_count=getattr(dataset, "example_count", None),
        metadata=metadata,
    )


def _example_dto(example: Any) -> LangSmithExampleRef:
    """Convert one SDK example object into its bounded adapter DTO.

    Remote inputs/outputs are deliberately discarded: ATI compares remote
    examples by stable identity and semantic digest only, and no untrusted
    payload may escape the adapter boundary.
    """
    metadata: dict[str, JsonValue] = bound_remote_metadata(
        getattr(example, "metadata", None)
    )
    return LangSmithExampleRef(
        example_id=str(getattr(example, "id", "")),
        dataset_id=str(getattr(example, "dataset_id", "")),
        metadata=metadata,
    )


def _find_datasets(sdk: Any, name: str) -> list[LangSmithDatasetRef]:
    """Collect bounded dataset refs matching ``name`` (at most two)."""
    return [
        _dataset_dto(dataset)
        for dataset in itertools.islice(sdk.list_datasets(dataset_name=name), 2)
    ]


def _projection_payload(projection: LangSmithExampleProjection) -> dict[str, Any]:
    """Serialize one projection onto the SDK example-create wire payload."""
    from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
        project_remote_metadata,
    )

    return {
        "inputs": dict(projection.inputs),
        "outputs": {key: list(values) for key, values in projection.outputs.items()},
        "metadata": project_remote_metadata(projection.metadata),
        "split": LANGSMITH_DEFAULT_SPLIT,
    }


class LangSmithSdkEvaluationClient:
    """Real LangSmith SDK wrapper used by explicit operator commands.

    ``sdk`` may be injected for deterministic tests (a duck-typed object
    exposing ``list_datasets``/``create_dataset``/``list_examples``/
    ``create_examples``/``create_feedback``); when absent a
    ``langsmith.Client`` is constructed from the standard LangSmith
    environment. Every SDK call is a bounded adapter operation: ordinary
    exceptions become :class:`LangSmithBackendError`, cancellation
    propagates, and no credential is ever logged or included in a message.
    """

    def __init__(self, sdk: Any | None = None) -> None:
        """Bind the optional injected SDK object."""
        self._sdk = sdk if sdk is not None else _default_sdk()

    async def find_dataset(self, *, name: str) -> LangSmithDatasetRef | None:
        """Return the single dataset named ``name`` or ``None`` when absent."""
        try:
            matches = await asyncio.to_thread(_find_datasets, self._sdk, name)
        except Exception as exc:
            raise _bounded_error("find_dataset", exc) from exc
        if not matches:
            return None
        if len(matches) > 1:
            raise LangSmithBackendError(
                f"ambiguous LangSmith dataset name {name!r}: {len(matches)} matches"
            )
        return matches[0]

    async def create_dataset(
        self, *, name: str, metadata: Mapping[str, JsonValue]
    ) -> LangSmithDatasetRef:
        """Create one dataset carrying the bounded ATI metadata."""
        try:
            dataset = await asyncio.to_thread(
                _create_dataset, self._sdk, name, dict(metadata)
            )
        except Exception as exc:
            raise _bounded_error("create_dataset", exc) from exc
        return _dataset_dto(dataset)

    async def list_examples(
        self, *, dataset: LangSmithDatasetRef
    ) -> tuple[LangSmithExampleRef, ...]:
        """Return every example of one dataset as bounded refs."""
        try:
            examples = await asyncio.to_thread(
                _list_examples, self._sdk, dataset.dataset_id
            )
        except Exception as exc:
            raise _bounded_error("list_examples", exc) from exc
        return tuple(_example_dto(example) for example in examples)

    async def create_examples(
        self,
        *,
        dataset: LangSmithDatasetRef,
        examples: Sequence[LangSmithExampleProjection],
    ) -> int:
        """Create the supplied examples in one batch and return the count."""
        payload = [_projection_payload(example) for example in examples]
        try:
            response = await asyncio.to_thread(
                _create_examples, self._sdk, dataset.dataset_id, payload
            )
        except Exception as exc:
            raise _bounded_error("create_examples", exc) from exc
        count = response.get("count") if isinstance(response, Mapping) else None
        if not isinstance(count, int) or count < 0:
            raise LangSmithBackendError(
                "LangSmith create_examples failed: no valid count in response"
            )
        return count

    async def publish_feedback(
        self,
        *,
        run_id: str,
        publication: LangSmithEvaluationPublication,
    ) -> None:
        """Publish every categorical feedback item of one publication."""
        for item in publication.feedback:
            try:
                await asyncio.to_thread(
                    _publish_feedback,
                    self._sdk,
                    run_id,
                    item.key,
                    item.value,
                    item.comment,
                )
            except Exception as exc:
                raise _bounded_error("publish_feedback", exc) from exc

    async def create_experiment(
        self, *, name: str, metadata: Mapping[str, JsonValue]
    ) -> LangSmithExperimentRef:
        """Create one ATI experiment run with bounded metadata.

        The run id is adapter-generated; no target executes here, so one ATI
        benchmark execution still corresponds to exactly one model call per
        case on the ATI side.
        """
        run_id = str(uuid4())
        try:
            await asyncio.to_thread(
                _create_experiment, self._sdk, run_id, name, dict(metadata)
            )
        except Exception as exc:
            raise _bounded_error("create_experiment", exc) from exc
        return LangSmithExperimentRef(run_id=run_id, name=name, metadata=dict(metadata))

    async def read_experiment(self, *, run_id: str) -> LangSmithExperimentRef | None:
        """Return one experiment run's bounded reference or ``None`` when absent."""
        from langsmith.utils import LangSmithNotFoundError

        try:
            run = await asyncio.to_thread(_read_run, self._sdk, run_id)
        except LangSmithNotFoundError:
            return None
        except Exception as exc:
            raise _bounded_error("read_experiment", exc) from exc
        return _experiment_dto(run)

    async def list_feedback(self, *, run_id: str) -> tuple[LangSmithFeedbackItem, ...]:
        """Return every bounded categorical feedback item published on a run."""
        try:
            items = await asyncio.to_thread(_list_feedback, self._sdk, run_id)
        except Exception as exc:
            raise _bounded_error("list_feedback", exc) from exc
        return tuple(_feedback_dto(item) for item in items)


def _create_dataset(sdk: Any, name: str, metadata: dict[str, JsonValue]) -> Any:
    """Run the blocking dataset-creation SDK call."""
    return sdk.create_dataset(name, metadata=metadata or None)


def _list_examples(sdk: Any, dataset_id: str) -> list[Any]:
    """Run the blocking example-listing SDK call for the ATI split."""
    return list(
        sdk.list_examples(dataset_id=dataset_id, splits=[LANGSMITH_DEFAULT_SPLIT])
    )


def _create_examples(sdk: Any, dataset_id: str, payload: list[dict[str, Any]]) -> Any:
    """Run the blocking batched example-creation SDK call."""
    return sdk.create_examples(dataset_id=dataset_id, examples=payload)


def _publish_feedback(sdk: Any, run_id: str, key: str, value: str, comment: str) -> Any:
    """Run the blocking categorical feedback SDK call."""
    return sdk.create_feedback(run_id=run_id, key=key, value=value, comment=comment)


def _experiment_dto(run: Any) -> LangSmithExperimentRef:
    """Convert one SDK run object into its bounded experiment reference.

    Only the run identity, name, and bounded ``ati.`` metadata are retained;
    run inputs/outputs and any foreign metadata never escape the adapter.
    """
    metadata: dict[str, JsonValue] = bound_remote_metadata(
        getattr(run, "metadata", None)
    )
    return LangSmithExperimentRef(
        run_id=str(getattr(run, "id", "")),
        name=str(getattr(run, "name", "")),
        metadata=metadata,
    )


def _feedback_dto(item: Any) -> LangSmithFeedbackItem:
    """Convert one SDK feedback object into its bounded categorical item."""
    return LangSmithFeedbackItem(
        key=str(getattr(item, "key", "")),
        value=str(getattr(item, "value", "")),
    )


def _create_experiment(
    sdk: Any, run_id: str, name: str, metadata: dict[str, JsonValue]
) -> Any:
    """Run the blocking experiment-run creation SDK call.

    The run records the ATI execution identity with a bounded ``ati.``
    metadata envelope; no example reference, data, or evaluator is attached
    because ATI already executed the target exactly once.
    """
    from datetime import UTC, datetime
    from uuid import UUID

    now = datetime.now(UTC)

    return sdk.create_run(
        id=UUID(run_id),
        name=name,
        run_type="chain",
        inputs={"ati.experiment": True},
        start_time=now,
        end_time=now,
        metadata=metadata or None,
    )


def _read_run(sdk: Any, run_id: str) -> Any:
    """Run the blocking read-run SDK call."""
    return sdk.read_run(run_id)


def _list_feedback(sdk: Any, run_id: str) -> list[Any]:
    """Run the blocking feedback-listing SDK call for one run id."""
    return list(sdk.list_feedback(run_ids=[run_id]))
