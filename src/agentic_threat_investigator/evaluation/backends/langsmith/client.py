# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Narrow injectable LangSmith evaluation client boundary (PR 30B).

The :class:`LangSmithEvaluationClient` protocol declares only the five
operations PR 30B needs; SDK-specific objects stay behind the wrapper and
unit tests inject an in-memory fake. The real
:class:`LangSmithSdkEvaluationClient` constructs the installed
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

from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithDatasetRef,
    LangSmithEvaluationPublication,
    LangSmithExampleProjection,
    LangSmithExampleRef,
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
