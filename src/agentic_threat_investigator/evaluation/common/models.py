# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A common evaluation result and scenario-quality models.

The canonical PR 30 correctness contract has exactly two verdicts
(:class:`EvaluationVerdict`) for a completed binary evaluator, one
execution status (:class:`EvaluationExecutionStatus`) that is deliberately
distinct from ``FAIL``, and no float score, percentage, weighting,
confidence, partial pass, severity, or threshold-derived result anywhere in
the common contract.

Valid status/verdict combinations are frozen:

.. code-block:: text

    COMPLETED + PASS
    COMPLETED + FAIL
    ERROR      + no verdict

and rejected combinations fail closed at model construction.

The module also owns the repository-owned scenario-quality contract
(:class:`ScenarioSpecification` and :class:`ExpectedBehavior`): every
canonical case must state what scenario it describes, why it matters, what
behavior is required or forbidden, and where it traces in the architecture.
These models are evaluation DTOs only; they extend no runtime domain model
and never import LangSmith, provider SDKs, or LLM client types.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any, Protocol, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

JsonScalar: TypeAlias = str | int | float | bool | None
"""One leaf JSON value accepted inside evaluation diagnostics."""

type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
"""A JSON-safe value accepted inside evaluation diagnostics."""

_NONBLANK_FIELDS = (
    "title",
    "description",
    "purpose",
    "operational_relevance",
    "regression_risk",
)
"""ScenarioSpecification fields that must be nonblank."""

_ARCHITECTURE_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable architecture-reference identifiers: lowercase, dotted, dashed or underscored."""

_CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable case identifiers: lowercase letters, digits, dot, dash, underscore."""

_MAX_CASE_ID_LENGTH = 64
"""Bounded common case identifier length."""

_MAX_TAGS = 10
"""Bounded number of descriptive tags a scenario may carry."""

_MAX_ARCHITECTURE_REFS = 10
"""Bounded number of architecture references a scenario may carry."""

_MAX_STATES_PER_AGGREGATE = 100_000
"""Sane upper bound defending the aggregate validators against pathological input."""


class EvaluationVerdict(str, Enum):
    """The binary correctness verdict a completed canonical evaluator returns.

    PR 30 correctness has exactly two verdicts; there is no numeric score,
    partial pass, or threshold-derived verdict.
    """

    PASS = "pass"  # nosec B105 - canonical PR 30 wire value for a passing verdict (frozen in docs/EVALUATION.md); never a credential
    """The expected behavior was satisfied."""

    FAIL = "fail"
    """An expected behavior was violated."""


class EvaluationExecutionStatus(str, Enum):
    """Whether an evaluation stage executed or could not execute.

    An evaluator that cannot execute did not determine that expected
    behavior failed: ``ERROR`` is deliberately distinct from ``FAIL``.
    """

    COMPLETED = "completed"
    """The evaluator (or case/dataset) ran to a verdict."""

    ERROR = "error"
    """The evaluator (or case/dataset) could not determine behavior."""


class EvaluationTarget(str, Enum):
    """Stable repository-owned benchmark target vocabulary.

    Dataset identity is ``<target>/v<version>``; a target may own several
    scenario families (for example ``research-agent`` owns retrieval and
    synthesis), and new targets must be added explicitly rather than routed
    through an inaccurate existing category.
    """

    EVIDENCE_ANALYST = "evidence-analyst"
    """The Evidence Analyst behavioral benchmark."""

    COORDINATOR = "coordinator"
    """The Investigation Coordinator behavioral benchmark."""

    RESEARCH_AGENT = "research-agent"
    """The Threat Research Agent retrieval/synthesis benchmark."""

    REPORT_WRITER = "report-writer"
    """The Report Writer behavioral benchmark."""

    INVESTIGATION = "investigation"
    """The end-to-end investigation benchmark (future suites)."""

    GEOINT = "geoint"
    """The GEOINT resolution/geographic-reasoning benchmark."""


_URL_CREDENTIALS_RE = re.compile(r"(://)[^/\s@]*@")
"""Match credentials embedded in a URI's user-info component."""


def _require_nonblank(value: str, field: str) -> str:
    """Trim and reject blank canonical text values."""
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field} must not be blank")
    return stripped


def _reject_raw_duplicates(value: object, field: str) -> object:
    """Reject duplicate raw list/tuple entries before tuple/set conversion.

    Pydantic converts list inputs silently, hiding duplicates such as
    ``["a", "a"]``; this helper rejects them deterministically before the
    declared collection type is constructed. Already-constructed
    set/frozenset values are returned unchanged because their duplicates
    were already lost at construction.
    """
    if isinstance(value, (list, tuple)):
        seen: list[object] = []
        for entry in value:
            if entry in seen:
                raise ValueError(f"{field} must not contain duplicate entries")
            seen.append(entry)
    return value


def normalize_statement(value: str) -> str:
    """Return the normalized form of one behavior statement or tag.

    Normalization collapses internal whitespace runs to single spaces and
    trims the result. No case folding, stemming, or fuzzy matching is ever
    performed, matching the repository's documented canonical-phrase
    contract.
    """
    return " ".join(value.split())


def _require_json_safe(value: object, field: str) -> None:
    """Recursively require a JSON-safe value (no NaN/infinity, string keys)."""
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError(f"{field} must not contain NaN or infinite floats")
        return
    if isinstance(value, list):
        for item in value:
            _require_json_safe(item, field)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{field} keys must be strings")
            _require_json_safe(item, field)
        return
    raise ValueError(f"{field} must contain only JSON-safe values")


def sanitize_explanation(message: str, *, max_length: int = 200) -> str:
    """Return a bounded, control-character-free explanation for ERROR results.

    Exception-derived messages may embed environment details, secrets, or
    unbounded provider output; the sanitized form collapses whitespace,
    strips control characters, redacts URL-embedded credentials, and
    truncates deterministically. A blank result maps to a stable nonblank
    fallback so an ERROR result always satisfies the nonblank explanation
    contract. This is applied only when the runner converts an unexpected
    evaluator/target failure into an ERROR result; author-declared
    explanations are never rewritten.
    """
    collapsed = "".join(character for character in message if character >= " ")
    sanitized = " ".join(collapsed.split())
    sanitized = _URL_CREDENTIALS_RE.sub(r"\1***@", sanitized)
    if not sanitized:
        return "evaluation failed; no explanation is available."
    if len(sanitized) > max_length:
        return sanitized[:max_length].rstrip() + "[truncated]"
    return sanitized


class ExpectedBehavior(BaseModel):
    """Explicit narrative required/forbidden behavior statements.

    Statements describe observable, reviewable investigative behavior, not
    test implementation. At least one list must be nonempty, no item may be
    blank, duplicates are rejected after canonical whitespace
    normalization, and a statement cannot be simultaneously required and
    forbidden. Target-specific typed expectation models remain authoritative
    beside this common narrative contract.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    required: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()

    @field_validator("required", "forbidden", mode="before")
    @classmethod
    def reject_raw_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before tuple conversion."""
        return _reject_raw_duplicates(value, info.field_name or "field")

    @field_validator("required", "forbidden", mode="after")
    @classmethod
    def statements_normalized(
        cls, value: tuple[str, ...], info: ValidationInfo
    ) -> tuple[str, ...]:
        """Canonicalize statements and reject blank entries."""
        field = info.field_name or "field"
        result: list[str] = []
        for statement in value:
            normalized = normalize_statement(statement)
            if not normalized:
                raise ValueError(f"{field} statements must not be blank")
            result.append(normalized)
        return tuple(result)

    @model_validator(mode="after")
    def behaviors_nonempty(self) -> "ExpectedBehavior":
        """Require at least one required or forbidden statement."""
        if not self.required and not self.forbidden:
            raise ValueError(
                "expected_behavior requires at least one required or forbidden statement"
            )
        return self

    @model_validator(mode="after")
    def statements_unique(self) -> "ExpectedBehavior":
        """Reject duplicate statements after normalization."""
        for field, statements in (
            ("required", self.required),
            ("forbidden", self.forbidden),
        ):
            if len(statements) != len(set(statements)):
                raise ValueError(f"{field} statements must be unique")
        overlap = set(self.required) & set(self.forbidden)
        if overlap:
            raise ValueError(
                "a statement cannot be both required and forbidden: "
                + ", ".join(sorted(overlap))
            )
        return self


class ScenarioSpecification(BaseModel):
    """The repository-owned scenario-quality contract shared by every target.

    A canonical PR 30 case is not valid unless a reviewer can understand the
    investigative scenario, why it matters, the behavior it exercises, and
    what constitutes acceptable/unacceptable behavior without reading
    evaluator code. ``expected_behavior`` states that in words;
    target-specific typed expectation models (for example an Analyst
    expected-Assessment envelope) remain authoritative for detailed
    deterministic checks.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str
    """Short human-readable scenario name."""

    description: str
    """The investigation situation, not the test implementation."""

    target: EvaluationTarget
    """The benchmark target this case belongs to."""

    purpose: str
    """The ATI behavior being exercised."""

    operational_relevance: str
    """Why this scenario matters in a real threat-investigation workflow."""

    regression_risk: str
    """The plausible implementation/model failure the case protects against."""

    expected_behavior: ExpectedBehavior
    """Narrative required/forbidden observable behavior."""

    tags: frozenset[str] = frozenset()
    """Normalized descriptive tags; never correctness semantics."""

    architecture_refs: tuple[str, ...] = ()
    """Stable repository-owned architecture invariant identifiers."""

    @field_validator(
        "title",
        "description",
        "purpose",
        "operational_relevance",
        "regression_risk",
        mode="after",
    )
    @classmethod
    def text_not_blank(cls, value: str, info: ValidationInfo) -> str:
        """Reject blank mandatory narrative fields."""
        return _require_nonblank(value, info.field_name or "field")

    @field_validator("tags", mode="before")
    @classmethod
    def tags_reject_duplicates_and_bound(
        cls, value: object, info: ValidationInfo
    ) -> object:
        """Reject duplicate raw tags and enforce the raw count bound."""
        if isinstance(value, (list, tuple)) and len(value) > _MAX_TAGS:
            raise ValueError(f"tags are bounded to {_MAX_TAGS} entries")
        return _reject_raw_duplicates(value, info.field_name or "tags")

    @field_validator("tags", mode="after")
    @classmethod
    def tags_normalized(cls, value: frozenset[str]) -> frozenset[str]:
        """Normalize descriptive tags and reject blank entries."""
        normalized = frozenset(normalize_statement(tag) for tag in value)
        if any(not tag for tag in normalized):
            raise ValueError("tags must not be blank")
        if len(normalized) != len(value):
            raise ValueError("tags must not normalize to duplicates")
        return normalized

    @field_validator("architecture_refs", mode="before")
    @classmethod
    def architecture_refs_reject_duplicates(
        cls, value: object, info: ValidationInfo
    ) -> object:
        """Reject duplicate raw architecture references."""
        return _reject_raw_duplicates(value, info.field_name or "field")

    @field_validator("architecture_refs", mode="after")
    @classmethod
    def architecture_refs_valid(
        cls, value: tuple[str, ...], info: ValidationInfo
    ) -> tuple[str, ...]:
        """Require stable, syntactic, unique architecture references."""
        field = info.field_name or "field"
        if len(value) > _MAX_ARCHITECTURE_REFS:
            raise ValueError(f"{field} are bounded to {_MAX_ARCHITECTURE_REFS} entries")
        for reference in value:
            if not _ARCHITECTURE_REF_RE.fullmatch(reference):
                raise ValueError(
                    f"{field} entries must match " + _ARCHITECTURE_REF_RE.pattern
                )
        if len(value) != len(set(value)):
            raise ValueError(f"{field} entries must not be duplicated")
        return value


class EvaluationDatasetId(BaseModel):
    """LangSmith-independent logical benchmark identity.

    The canonical form is ``<target>/v<version>``; the version is part of
    the benchmark identity and a materially changed semantic contract
    requires a new version, never silent redefinition of a published case.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target: EvaluationTarget
    version: int = Field(ge=1)

    @property
    def canonical(self) -> str:
        """Return the canonical ``<target>/v<version>`` identity string."""
        return f"{self.target.value}/v{self.version}"

    def __str__(self) -> str:
        """Render the canonical identity string."""
        return self.canonical

    @classmethod
    def from_canonical(cls, value: str) -> "EvaluationDatasetId":
        """Parse one canonical dataset identity string.

        Raises :class:`ValueError` when the string is not a well-formed
        ``<target>/v<version>`` identity or names an unknown target.
        """
        target_text, separator, version_text = value.partition("/")
        if (
            not separator
            or not version_text.startswith("v")
            or not version_text[1:].isdigit()
        ):
            raise ValueError(
                "dataset identity must look like '<target>/v<version>', got "
                + repr(value)
            )
        return cls(target=EvaluationTarget(target_text), version=int(version_text[1:]))


class EvaluationCase(BaseModel):
    """One canonical case projected for a common run.

    Target-specific scenario models carry the same identity/specification
    contract; :func:`evaluation_case_from` projects them without losing the
    typed target model, which remains the input to target-specific
    evaluators.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    version: int = Field(ge=1)
    specification: ScenarioSpecification

    @field_validator("case_id", mode="after")
    @classmethod
    def case_id_valid(cls, value: str) -> str:
        """Require a stable lowercase case identifier of bounded length."""
        if len(value) > _MAX_CASE_ID_LENGTH or not _CASE_ID_RE.fullmatch(value):
            raise ValueError("case_id must match " + _CASE_ID_RE.pattern)
        return value

    @classmethod
    def from_scenario(
        cls,
        *,
        case_id: str,
        version: int,
        specification: ScenarioSpecification,
    ) -> "EvaluationCase":
        """Build a common case from explicit identity and specification."""
        return cls(case_id=case_id, version=version, specification=specification)


class ScenarioLike(Protocol):
    """Structural view of any repository scenario carrying the common contract.

    The optional canonical serialization seam (:meth:`model_dump`) is the PR
    30B addition needed for the truthful semantic digest of the complete
    authored scenario object: every repository typed scenario model already
    provides ``model_dump``, so the protocol only widens the structural
    contract without changing any scenario semantics.
    """

    id: str
    version: int
    specification: ScenarioSpecification

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        """Return the canonical python-mode serialization of this scenario."""
        ...


def evaluation_case_from(scenario: ScenarioLike) -> EvaluationCase:
    """Project one repository scenario onto the common :class:`EvaluationCase`.

    The typed target scenario remains the authoritative case object for
    target-specific evaluators; the projection is the deterministic stable
    case identity plus its common specification.
    """
    return EvaluationCase(
        case_id=scenario.id,
        version=scenario.version,
        specification=scenario.specification,
    )


class EvaluationResult(BaseModel):
    """The immutable result of one evaluator decision.

    A completed result carries exactly ``PASS`` or ``FAIL`` plus a nonblank
    explanation; an ERROR result carries no verdict. Diagnostics are
    JSON-safe measurements, never chain-of-thought, raw prompts, raw model
    responses, or secrets; they never alter aggregation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evaluator_id: str
    execution_status: EvaluationExecutionStatus
    verdict: EvaluationVerdict | None = None
    explanation: str
    diagnostics: Mapping[str, JsonValue] = Field(default_factory=dict)

    @field_validator("evaluator_id", mode="after")
    @classmethod
    def evaluator_id_valid(cls, value: str) -> str:
        """Require a stable, nonblank evaluator identifier."""
        return _require_nonblank(value, "evaluator_id")

    @field_validator("explanation", mode="after")
    @classmethod
    def explanation_not_blank(cls, value: str) -> str:
        """Require a nonblank explanation for PASS, FAIL, and ERROR."""
        return _require_nonblank(value, "explanation")

    @model_validator(mode="after")
    def status_verdict_combo(self) -> "EvaluationResult":
        """Enforce the frozen status/verdict combinations."""
        if self.execution_status is EvaluationExecutionStatus.COMPLETED and (
            self.verdict is None
        ):
            raise ValueError("a COMPLETED evaluator result must carry a verdict")
        if self.execution_status is EvaluationExecutionStatus.ERROR and (
            self.verdict is not None
        ):
            raise ValueError("an ERROR evaluator result cannot carry a verdict")
        return self

    @model_validator(mode="after")
    def diagnostics_json_safe(self) -> "EvaluationResult":
        """Require JSON-safe diagnostics without NaN/infinite floats."""
        _require_json_safe(self.diagnostics, "diagnostics")
        return self

    @classmethod
    def error(cls, *, evaluator_id: str, message: str) -> "EvaluationResult":
        """Build an ERROR result with a sanitized explanation.

        Used by the runner when an ordinary evaluator/target failure occurs;
        never for author-declared explanations.
        """
        return cls(
            evaluator_id=evaluator_id,
            execution_status=EvaluationExecutionStatus.ERROR,
            explanation=sanitize_explanation(message),
        )


def case_aggregate(
    evaluator_results: Sequence[EvaluationResult],
) -> tuple[EvaluationExecutionStatus, EvaluationVerdict | None]:
    """Apply the frozen case-aggregation rules over evaluator results.

    Rules: all results COMPLETED/PASS produce a COMPLETED/PASS case; one or
    more COMPLETED/FAIL with no ERROR produces COMPLETED/FAIL; one or more
    ERROR (or zero results, meaning the target never produced output)
    produces an ERROR case with no verdict. Every evaluator attached to a
    case is required; there is no informational category.
    """
    if not evaluator_results:
        return EvaluationExecutionStatus.ERROR, None
    if any(
        result.execution_status is EvaluationExecutionStatus.ERROR
        for result in evaluator_results
    ):
        return EvaluationExecutionStatus.ERROR, None
    if all(result.verdict is EvaluationVerdict.PASS for result in evaluator_results):
        return EvaluationExecutionStatus.COMPLETED, EvaluationVerdict.PASS
    return EvaluationExecutionStatus.COMPLETED, EvaluationVerdict.FAIL


def dataset_aggregate(
    case_results: Sequence["EvaluationCaseResult"],
) -> tuple[EvaluationExecutionStatus, EvaluationVerdict | None]:
    """Apply the frozen dataset-aggregation rules over case results.

    Rules: all cases COMPLETED/PASS produce a COMPLETED/PASS dataset; one
    or more case FAIL with no ERROR produces COMPLETED/FAIL; one or more
    case ERROR produces an ERROR dataset with no verdict. Aggregate counts
    may be displayed as diagnostics, but never change the aggregate
    verdict.
    """
    if not case_results:
        return EvaluationExecutionStatus.ERROR, None
    if any(
        result.execution_status is EvaluationExecutionStatus.ERROR
        for result in case_results
    ):
        return EvaluationExecutionStatus.ERROR, None
    if all(result.verdict is EvaluationVerdict.PASS for result in case_results):
        return EvaluationExecutionStatus.COMPLETED, EvaluationVerdict.PASS
    return EvaluationExecutionStatus.COMPLETED, EvaluationVerdict.FAIL


class EvaluationCaseResult(BaseModel):
    """The immutable aggregated result of one case in a run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    execution_status: EvaluationExecutionStatus
    verdict: EvaluationVerdict | None = None
    evaluator_results: tuple[EvaluationResult, ...] = ()

    @field_validator("case_id", mode="after")
    @classmethod
    def case_id_not_blank(cls, value: str) -> str:
        """Require a nonblank case identifier."""
        return _require_nonblank(value, "case_id")

    @model_validator(mode="after")
    def status_verdict_combo(self) -> "EvaluationCaseResult":
        """Enforce the frozen status/verdict combinations."""
        if self.execution_status is EvaluationExecutionStatus.COMPLETED and (
            self.verdict is None
        ):
            raise ValueError("a COMPLETED case must carry a verdict")
        if self.execution_status is EvaluationExecutionStatus.ERROR and (
            self.verdict is not None
        ):
            raise ValueError("an ERROR case cannot carry a verdict")
        if not self.evaluator_results and (
            self.execution_status is EvaluationExecutionStatus.COMPLETED
        ):
            raise ValueError("a COMPLETED case must have run at least one evaluator")
        return self

    @model_validator(mode="after")
    def aggregate_consistent(self) -> "EvaluationCaseResult":
        """Require the declared status/verdict to equal the frozen aggregation."""
        if len(self.evaluator_results) > _MAX_STATES_PER_AGGREGATE:
            raise ValueError("evaluator result count exceeds the supported bound")
        expected_status, expected_verdict = case_aggregate(self.evaluator_results)
        if (self.execution_status, self.verdict) != (expected_status, expected_verdict):
            raise ValueError(
                "case status/verdict must equal the deterministic case aggregation"
            )
        return self


class EvaluationRunResult(BaseModel):
    """The immutable result of one common evaluation run.

    Timestamps are intentionally absent so deterministic tests never depend
    on wall-clock values; PR 30B may add correlation metadata outside the
    common models.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    dataset_id: EvaluationDatasetId
    execution_status: EvaluationExecutionStatus
    verdict: EvaluationVerdict | None = None
    cases: tuple[EvaluationCaseResult, ...]

    @model_validator(mode="after")
    def cases_nonempty(self) -> "EvaluationRunResult":
        """Require at least one case in a run result."""
        if not self.cases:
            raise ValueError("an evaluation run must contain at least one case")
        return self

    @model_validator(mode="after")
    def status_verdict_combo(self) -> "EvaluationRunResult":
        """Enforce the frozen status/verdict combinations."""
        if self.execution_status is EvaluationExecutionStatus.COMPLETED and (
            self.verdict is None
        ):
            raise ValueError("a COMPLETED run must carry a verdict")
        if self.execution_status is EvaluationExecutionStatus.ERROR and (
            self.verdict is not None
        ):
            raise ValueError("an ERROR run cannot carry a verdict")
        return self

    @model_validator(mode="after")
    def aggregate_consistent(self) -> "EvaluationRunResult":
        """Require the declared run status/verdict to equal the frozen aggregation."""
        if len(self.cases) > _MAX_STATES_PER_AGGREGATE:
            raise ValueError("case count exceeds the supported bound")
        expected_status, expected_verdict = dataset_aggregate(self.cases)
        if (self.execution_status, self.verdict) != (expected_status, expected_verdict):
            raise ValueError(
                "run status/verdict must equal the deterministic dataset aggregation"
            )
        return self


class JudgeDecision(BaseModel):
    """One judge decision produced by a rubric-guided evaluator.

    Defined now as the seam for PR 30B/30C judge evaluators; PR 30A never
    invokes a real judge. Future judge evaluators must use ATI's
    :class:`~agentic_threat_investigator.app.llm.LlmClient` abstraction,
    return no numeric score, expose no chain-of-thought, and follow explicit
    scenario-specific binary rubrics.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: EvaluationVerdict
    explanation: str

    @field_validator("explanation", mode="after")
    @classmethod
    def explanation_not_blank(cls, value: str) -> str:
        """Require a nonblank judge explanation."""
        return _require_nonblank(value, "explanation")
