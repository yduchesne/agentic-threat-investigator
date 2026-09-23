# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A backend-neutral evaluator and target-execution seams.

The common runner drives these two protocols and nothing else:

- :class:`Evaluator` decides, for one executed output, whether the case's
  expected observable behavior passed or failed (or could not be
  determined);
- :class:`TargetExecutor` produces that output from a canonical case.

Both seams are async-capable (future judge evaluators must stay async),
carry no LangSmith/provider SDK types, and take explicit inputs instead of
hidden global state. The runner converts ordinary exceptions into ERROR
results and never catches ``BaseException``, so cancellation propagates.

The judge decision seam is defined in models (:class:`JudgeDecision`) but a
real LLM judge is never invoked in PR 30A; future judge evaluators must use
ATI's :class:`~agentic_threat_investigator.app.llm.LlmClient` abstraction,
return no numeric quality score, expose no chain-of-thought, and follow
explicit scenario-specific binary rubrics.
"""

from __future__ import annotations

from typing import Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator

from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCase,
    EvaluationResult,
)

EvaluatorOutputT = TypeVar("EvaluatorOutputT", contravariant=True)
"""Payload consumed by one evaluator (contravariant: consumers generalize)."""

TargetOutputT = TypeVar("TargetOutputT", covariant=True)
"""Payload produced by one target executor (covariant: producers specialize)."""


def _require_nonblank(value: str, field: str) -> str:
    """Trim and reject blank canonical text values."""
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field} must not be blank")
    return stripped


class EvaluationContext(BaseModel):
    """Per-case execution context passed to evaluators and executors.

    The context carries stable identity only; any target-specific runtime
    data belongs in the typed ``output`` passed from the executor to the
    evaluators.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    dataset_id: str
    """Canonical dataset identity this case belongs to."""

    case_id: str
    """Stable case identifier under evaluation."""

    @field_validator("dataset_id", "case_id", mode="after")
    @classmethod
    def identity_not_blank(cls, value: str, info: ValidationInfo) -> str:
        """Require nonblank context identity values."""
        return _require_nonblank(value, info.field_name or "field")


class Evaluator(Protocol[EvaluatorOutputT]):
    """Backend-neutral binary evaluator seam.

    Implementations expose a stable nonblank ``evaluator_id`` and an
    asynchronous :meth:`evaluate` returning exactly one
    :class:`EvaluationResult`. Implementations must not depend on LangSmith,
    provider SDKs, or LLM clients, and must never raise to express ``FAIL``:
    a verdict of ``FAIL`` is a deterministic decision, while an exception is
    converted by the runner into an ERROR result.
    """

    @property
    def evaluator_id(self) -> str:
        """Return the stable identifier of this evaluator."""
        ...

    async def evaluate(
        self,
        *,
        case: EvaluationCase,
        output: EvaluatorOutputT,
        context: EvaluationContext,
    ) -> EvaluationResult:
        """Decide PASS/FAIL (or ERROR via raised exception) for one output."""
        ...


class TargetExecutor(Protocol[TargetOutputT]):
    """Backend-neutral target-execution seam.

    Implementations run the target under evaluation for one canonical case
    and return the typed output payload evaluators consume. A raised
    exception produces a case ERROR result; cancellation propagates.
    """

    async def execute(
        self,
        *,
        case: EvaluationCase,
        context: EvaluationContext,
    ) -> TargetOutputT:
        """Execute one case and return the target output payload."""
        ...
