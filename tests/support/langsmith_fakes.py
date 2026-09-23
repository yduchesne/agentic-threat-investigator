# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic LangSmith evaluation-adapter test doubles (PR 30B/30C).

All PR 30B/30C adapter tests are network-free and credential-free: the
:class:`FakeLangSmithClient` implements the narrow
:class:`LangSmithEvaluationClient` protocol in memory (including the PR 30C
experiment-run operations), and :class:`FakeSdkClient` mimics the duck-typed
installed ``langsmith.Client`` surface the real SDK wrapper calls.
``ScenarioStub`` is a minimal fully typed scenario stand-in carrying the
common specification plus one extra target-specific semantic field so tests
can prove the digest covers target-specific content.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentic_threat_investigator.evaluation.backends.langsmith.client import (
    LangSmithBackendError,
)
from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
    project_remote_metadata,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithDatasetRef,
    LangSmithEvaluationPublication,
    LangSmithExampleProjection,
    LangSmithExampleRef,
    LangSmithExperimentRef,
    LangSmithFeedbackItem,
)
from agentic_threat_investigator.evaluation.common.models import (
    JsonValue,
    ScenarioSpecification,
)


class ScenarioStub(BaseModel):
    """Minimal typed scenario stand-in satisfying the adapter's scenario view.

    Mirror of the repository typed scenario models (stable id/version, the
    common specification, plus one extra target-specific semantic field);
    pydantic freezing and serialization keep the digest contract identical.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: int = Field(ge=1)
    specification: ScenarioSpecification
    extra_semantic: str = "target-specific"


def test_scenario(
    case_id: str = "unit-case",
    *,
    version: int = 1,
    specification: ScenarioSpecification | None = None,
    extra_semantic: str = "target-specific",
) -> ScenarioStub:
    """Build one deterministic typed scenario stand-in."""
    from tests.support.evaluation_common import unit_specification

    return ScenarioStub(
        id=case_id,
        version=version,
        specification=specification or unit_specification(),
        extra_semantic=extra_semantic,
    )


class FakeLangSmithClient:
    """In-memory implementation of the narrow LangSmith client protocol.

    Records every operation and can be configured to fail individual
    operations (bounded :class:`LangSmithBackendError`) or to block so
    tests can cancel pending work and prove cancellation propagates.
    Writing to a non-created dataset or re-creating an existing one fails
    like the real backend would.
    """

    def __init__(self) -> None:
        """Initialize the empty in-memory mirror state."""
        self.datasets: dict[str, dict[str, Any]] = {}
        self.published: list[tuple[str, LangSmithEvaluationPublication]] = []
        self.experiments: dict[str, dict[str, Any]] = {}
        self.calls: list[str] = []
        self.fail_operations: set[str] = set()
        self.block_operations: set[str] = set()

    def _record(self, operation: str) -> None:
        """Record one operation and honor configured failure modes."""
        self.calls.append(operation)
        if operation in self.fail_operations:
            raise LangSmithBackendError(f"{operation} failed (fake)")

    async def _maybe_block(self, operation: str) -> None:
        """Honor configured blocking without swallowing cancellation."""
        if operation in self.block_operations:
            await asyncio.sleep(3600)

    async def find_dataset(self, *, name: str) -> LangSmithDatasetRef | None:
        """Return the stored dataset ref or ``None`` when absent."""
        self._record("find_dataset")
        await self._maybe_block("find_dataset")
        entry = self.datasets.get(name)
        return None if entry is None else entry["ref"]

    async def create_dataset(
        self, *, name: str, metadata: Mapping[str, JsonValue]
    ) -> LangSmithDatasetRef:
        """Create and store one dataset; conflict fails like the backend."""
        self._record("create_dataset")
        await self._maybe_block("create_dataset")
        if name in self.datasets:
            raise LangSmithBackendError("dataset already exists (fake)")
        ref = LangSmithDatasetRef(
            name=name,
            dataset_id=f"ds-{len(self.datasets) + 1}",
            metadata=dict(metadata),
        )
        self.datasets[name] = {"ref": ref, "examples": {}}
        return ref

    async def list_examples(
        self, *, dataset: LangSmithDatasetRef
    ) -> tuple[LangSmithExampleRef, ...]:
        """Return the stored example refs of one dataset."""
        self._record("list_examples")
        await self._maybe_block("list_examples")
        entry = self.datasets.get(dataset.name)
        return () if entry is None else tuple(entry["examples"].values())

    async def create_examples(
        self,
        *,
        dataset: LangSmithDatasetRef,
        examples: Sequence[LangSmithExampleProjection],
    ) -> int:
        """Create the supplied examples; an existing identity fails like the backend."""
        self._record("create_examples")
        await self._maybe_block("create_examples")
        entry = self.datasets[dataset.name]
        existing_identities = {
            (ref.metadata.get("ati.case_id"), ref.metadata.get("ati.case_version"))
            for ref in entry["examples"].values()
        }
        for projection in examples:
            remote = project_remote_metadata(projection.metadata)
            identity = (remote["ati.case_id"], remote["ati.case_version"])
            if identity in existing_identities:
                raise LangSmithBackendError("example already exists (fake)")
            existing_identities.add(identity)
            entry["examples"][f"ex-{len(entry['examples']) + 1}"] = LangSmithExampleRef(
                example_id=f"ex-{len(entry['examples']) + 1}",
                dataset_id=dataset.dataset_id,
                metadata=dict(remote),
            )
        return len(examples)

    async def publish_feedback(
        self,
        *,
        run_id: str,
        publication: LangSmithEvaluationPublication,
    ) -> None:
        """Record one publication for later assertions."""
        self._record("publish_feedback")
        await self._maybe_block("publish_feedback")
        if run_id not in self.experiments:
            raise LangSmithBackendError("feedback target run does not exist (fake)")
        entry = self.experiments[run_id]
        entry["feedback"] = list(publication.feedback)
        entry["publication"] = publication
        self.published.append((run_id, publication))

    async def create_experiment(
        self, *, name: str, metadata: Mapping[str, JsonValue]
    ) -> LangSmithExperimentRef:
        """Create one experiment run and return its adapter-owned reference."""
        self._record("create_experiment")
        await self._maybe_block("create_experiment")
        if any(entry["ref"].name == name for entry in self.experiments.values()):
            raise LangSmithBackendError("experiment name already exists (fake)")
        ref = LangSmithExperimentRef(
            run_id=f"run-{len(self.experiments) + 1}",
            name=name,
            metadata=dict(metadata),
        )
        self.experiments[ref.run_id] = {"ref": ref, "feedback": []}
        return ref

    async def read_experiment(self, *, run_id: str) -> LangSmithExperimentRef | None:
        """Return one experiment run's bounded reference or ``None`` when absent."""
        self._record("read_experiment")
        await self._maybe_block("read_experiment")
        entry = self.experiments.get(run_id)
        return None if entry is None else entry["ref"]

    async def list_feedback(self, *, run_id: str) -> tuple[LangSmithFeedbackItem, ...]:
        """Return every bounded categorical feedback item published on a run."""
        self._record("list_feedback")
        await self._maybe_block("list_feedback")
        entry = self.experiments.get(run_id)
        if entry is None:
            raise LangSmithBackendError("feedback target run does not exist (fake)")
        return tuple(
            LangSmithFeedbackItem(key=item.key, value=item.value)
            for item in entry["feedback"]
        )

    def seed_experiment(self, ref: LangSmithExperimentRef) -> None:
        """Seed an existing remote experiment (confirmation scenarios)."""
        self.experiments[ref.run_id] = {"ref": ref, "feedback": []}

    def seed_examples(
        self, dataset: LangSmithDatasetRef, refs: Sequence[LangSmithExampleRef]
    ) -> None:
        """Seed existing remote examples (drift/extras scenarios)."""
        entry = self.datasets.setdefault(dataset.name, {"ref": dataset, "examples": {}})
        for ref in refs:
            entry["examples"][ref.example_id] = ref


class FakeDataset:
    """Duck-typed SDK dataset object stand-in."""

    def __init__(
        self,
        name: str,
        id: str,
        *,
        metadata: dict[str, Any] | None = None,
        example_count: int | None = None,
    ) -> None:
        """Bind the SDK-shaped attributes."""
        self.name = name
        self.id = id
        self.metadata = metadata
        self.example_count = example_count


class FakeExample:
    """Duck-typed SDK example object stand-in."""

    def __init__(
        self,
        id: str,
        dataset_id: str,
        *,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        outputs: dict[str, Any] | None = None,
    ) -> None:
        """Bind the SDK-shaped attributes."""
        self.id = id
        self.dataset_id = dataset_id
        self.metadata = metadata
        self.inputs = inputs
        self.outputs = outputs


class FakeRun:
    """Duck-typed SDK run object stand-in."""

    def __init__(
        self,
        id: str,
        *,
        name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Bind the SDK-shaped run attributes."""
        self.id = id
        self.name = name
        self.metadata = metadata


class FakeFeedback:
    """Duck-typed SDK feedback object stand-in."""

    def __init__(
        self,
        *,
        key: str = "",
        value: str | None = None,
        comment: str | None = None,
        run_id: str | None = None,
    ) -> None:
        """Bind the SDK-shaped feedback attributes."""
        self.key = key
        self.value = value
        self.comment = comment
        self.run_id = run_id


class FakeSdkClient:
    """Duck-typed stand-in for the installed ``langsmith.Client`` surface.

    Implements exactly the SDK operations the real wrapper calls:
    ``list_datasets``, ``create_dataset``, ``list_examples``,
    ``create_examples``, ``create_feedback`` (PR 30B), plus
    ``create_run``/``read_run``/``list_feedback`` (PR 30C experiment
    association). Object values are the SDK shapes the wrapper reads through
    ``getattr``.
    """

    def __init__(self) -> None:
        """Initialize the empty SDK-shaped store."""
        self.datasets: dict[str, FakeDataset] = {}
        self.examples: list[FakeExample] = []
        self.feedback: list[dict[str, Any]] = []
        self.runs: dict[str, dict[str, Any]] = {}
        self.fail_operations: set[str] = set()

    def list_datasets(
        self, *, dataset_name: str | None = None, limit: int | None = None
    ) -> Any:
        """Return matching SDK dataset objects in insertion order."""
        matches = [
            dataset
            for name, dataset in self.datasets.items()
            if dataset_name is None or name == dataset_name
        ]
        return iter(matches[:limit] if limit is not None else matches)

    def create_dataset(
        self,
        name: str,
        *,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> FakeDataset:
        """Create one SDK dataset object."""
        if "create_dataset" in self.fail_operations:
            raise RuntimeError("create_dataset backend boom")
        if name in self.datasets:
            raise RuntimeError("409 dataset already exists")
        dataset = FakeDataset(
            name, f"ds-uuid-{len(self.datasets) + 1}", metadata=metadata
        )
        self.datasets[name] = dataset
        return dataset

    def list_examples(
        self,
        dataset_id: str | None = None,
        *,
        splits: list[str] | None = None,
        limit: int | None = None,
    ) -> Any:
        """Return matching SDK example objects."""
        del splits
        matches = [
            example
            for example in self.examples
            if dataset_id is None or example.dataset_id == dataset_id
        ]
        return iter(matches[:limit] if limit is not None else matches)

    def create_examples(
        self,
        *,
        dataset_id: str | None = None,
        examples: Sequence[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Create SDK example objects and return the upsert response shape."""
        if "create_examples" in self.fail_operations:
            raise RuntimeError("create_examples backend boom")
        count = len(examples or ())
        ids: list[str] = []
        for example in examples or ():
            payload = {key: value for key, value in example.items() if key != "split"}
            created = FakeExample(
                f"ex-uuid-{len(self.examples) + 1}", dataset_id or "", **payload
            )
            self.examples.append(created)
            ids.append(created.id)
        return {"count": count, "example_ids": ids}

    def create_feedback(
        self,
        run_id: str,
        key: str,
        *,
        value: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Record one SDK feedback call."""
        if "create_feedback" in self.fail_operations:
            raise RuntimeError("create_feedback backend boom")
        self.feedback.append(
            {"run_id": run_id, "key": key, "value": value, "comment": comment}
        )
        return {"id": f"fb-{len(self.feedback)}"}

    def create_run(
        self,
        name: str,
        inputs: dict[str, Any],
        run_type: str,
        *,
        id: str | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Create one SDK run object, recording its id/name/metadata."""
        del inputs, run_type, kwargs
        if "create_run" in self.fail_operations:
            raise RuntimeError("create_run backend boom")
        run_id = str(id) if id else f"run-uuid-{len(self.runs) + 1}"
        if run_id in self.runs:
            raise RuntimeError("409 run already exists")
        self.runs[run_id] = {"id": run_id, "name": name, "metadata": metadata}

    def read_run(self, run_id: str) -> FakeRun:
        """Return one SDK run object or raise a not-found error."""
        if "read_run" in self.fail_operations:
            raise RuntimeError("read_run backend boom")
        entry = self.runs.get(run_id)
        if entry is None:
            from langsmith.utils import LangSmithNotFoundError

            raise LangSmithNotFoundError(f"run {run_id} not found")
        return FakeRun(**entry)

    def list_feedback(
        self,
        *,
        run_ids: list[str] | None = None,
        limit: int | None = None,
        **kwargs: Any,
    ) -> Any:
        """Return SDK feedback objects matching the run ids."""
        del kwargs
        selected = [
            item
            for item in self.feedback
            if run_ids is None or item.get("run_id") in run_ids
        ]
        if limit is not None:
            selected = selected[:limit]
        return iter([FakeFeedback(**item) for item in selected])
