# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned Report Writer evaluation contracts (PR 23B).

The Report Writer behavioral baseline answers a deterministic question:

> Given a known persisted investigation snapshot and the production Report
> Writer execution path, is the final persisted
> :class:`InvestigationReport` acceptably grounded and faithful to the
> authoritative Assessment/Research inputs?

This is deliberately NOT semantic entailment proof. Deterministic provenance
validation proves reference integrity and source closure; these scenarios
prove expected *behavior* on known inputs: verdict/confidence preservation,
finding selection boundaries, research-context epistemic boundaries, caveat
preservation, narrative envelope bounds, and failure behavior for
unsupported references, verdict-override attempts, and stale Assessment
races.

Scenarios are data only: stable identifiers, positive versions, bounded
semantic labels, canonical phrase expectations, and structured failure
expectations. They never contain runtime UUIDs, model prompt text, secrets,
executable callbacks, or scoring weights. These are evaluation DTOs only;
they extend no runtime model.
"""

from __future__ import annotations

import re
from enum import Enum
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from agentic_threat_investigator.domain.assessment import AssessmentConfidence, Verdict
from agentic_threat_investigator.domain.report import InvestigationReport

_SCENARIO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable lowercase scenario identifiers: letters, digits, dot, dash, underscore."""

_SEMANTIC_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable lowercase semantic fixture labels: letters, digits, dot, dash, underscore."""

_MAX_SCENARIO_ID_LENGTH = 64
"""Bounded scenario identifier length."""

_MAX_SEMANTIC_LABEL_LENGTH = 64
"""Bounded semantic fixture-label length."""


def _scenario_id(value: str) -> str:
    """Require a stable lowercase scenario identifier of bounded length."""
    if len(value) > _MAX_SCENARIO_ID_LENGTH or not _SCENARIO_ID_RE.fullmatch(value):
        raise ValueError("scenario id must match " + _SCENARIO_ID_RE.pattern)
    return value


def _semantic_label(value: str) -> str:
    """Require one stable, bounded, lowercase semantic fixture label."""
    if len(value) > _MAX_SEMANTIC_LABEL_LENGTH or not _SEMANTIC_LABEL_RE.fullmatch(
        value
    ):
        raise ValueError("semantic label must match " + _SEMANTIC_LABEL_RE.pattern)
    return value


def _not_blank(value: str) -> str:
    """Trim and reject blank scenario text values."""
    stripped = value.strip()
    if not stripped:
        raise ValueError("value must not be blank")
    return stripped


def normalize_phrase(value: str) -> str:
    """Collapse all runs of whitespace to single spaces and trim.

    Phrase membership is evaluated after this normalization; no stemming,
    embeddings, fuzzy similarity, or strict whole-text equality is used.
    """
    return " ".join(value.split())


def _reject_duplicates(value: object, field: str) -> object:
    """Reject duplicate entries in a JSON list/tuple before tuple conversion."""
    if isinstance(value, (list, tuple)):
        seen: list[object] = []
        for entry in value:
            if entry in seen:
                raise ValueError(f"{field} must not contain duplicate entries")
            seen.append(entry)
    return value


class ReportWriterFailureCode(str, Enum):
    """Stable machine-readable Report Writer failure categories (PR 23B).

    Codes describe structural/behavioral acceptability only; they carry no
    scenario identity and never inspect free-form prose for relevance except
    through author-declared canonical phrase envelopes.
    """

    VERDICT_MISMATCH = "verdict_mismatch"
    """The persisted report verdict differs from the scenario/Assessment."""

    CONFIDENCE_MISMATCH = "confidence_mismatch"
    """The persisted report confidence differs from the scenario/Assessment."""

    REQUIRED_ASSESSMENT_FINDING_MISSING = "required_assessment_finding_missing"
    """A required Assessment finding ordinal is absent from the report."""

    FORBIDDEN_ASSESSMENT_FINDING_INCLUDED = "forbidden_assessment_finding_included"
    """A forbidden Assessment finding ordinal appears in the report."""

    REQUIRED_RESEARCH_CLAIM_MISSING = "required_research_claim_missing"
    """A required research claim label is absent from the report context."""

    FORBIDDEN_RESEARCH_CLAIM_INCLUDED = "forbidden_research_claim_included"
    """A forbidden research claim label appears in the report context."""

    UNSUPPORTED_SOURCE_REFERENCE = "unsupported_source_reference"
    """The writer referenced material that was not supplied to it."""

    REQUIRED_LIMITATION_MISSING = "required_limitation_missing"
    """A required Assessment limitation is absent from the report."""

    REQUIRED_UNRESOLVED_QUESTION_MISSING = "required_unresolved_question_missing"
    """A required unresolved question is absent from the report."""

    REQUIRED_NEXT_STEP_MISSING = "required_next_step_missing"
    """A required recommended next step is absent from the report."""

    REPORT_STATEMENT_ENVELOPE_VIOLATION = "report_statement_envelope_violation"
    """The narrative statement count or phrase envelope is violated."""

    REPORT_STRUCTURE_INVALID = "report_structure_invalid"
    """The persisted report shape violates the scenario's structural contract."""


class ExpectedReportWriterOutput(BaseModel):
    """The acceptable deterministic envelope for one persisted report.

    The envelope is structural: exact verdict/confidence, exact finding
    ordinal membership, exact research-claim label membership, canonical
    phrase membership after whitespace normalization, bounded narrative
    statement counts, exact caveat membership, and explicit no-report
    semantics for failure scenarios. It never encodes whole-report text
    similarity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Verdict
    confidence: AssessmentConfidence

    required_assessment_finding_ordinals: tuple[int, ...] = ()
    forbidden_assessment_finding_ordinals: tuple[int, ...] = ()

    required_research_claim_labels: tuple[str, ...] = ()
    forbidden_research_claim_labels: tuple[str, ...] = ()

    required_limitations: tuple[str, ...] = ()
    required_unresolved_questions: tuple[str, ...] = ()
    required_next_steps: tuple[str, ...] = ()

    min_narrative_statements: int = Field(default=0, ge=0)
    max_narrative_statements: int | None = Field(default=None, ge=0)
    required_phrases: tuple[str, ...] = ()
    forbidden_phrases: tuple[str, ...] = ()

    expected_no_report: bool = False
    expected_execution_error_code: str | None = None

    @field_validator(
        "required_assessment_finding_ordinals",
        "required_limitations",
        "required_unresolved_questions",
        "required_next_steps",
        mode="before",
    )
    @classmethod
    def reject_duplicate_ordinals_and_text(
        cls, value: object, info: ValidationInfo
    ) -> object:
        """Reject duplicate raw entries before tuple conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator(
        "required_research_claim_labels",
        "forbidden_research_claim_labels",
        mode="before",
    )
    @classmethod
    def reject_duplicate_labels(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before tuple conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator(
        "required_research_claim_labels",
        "forbidden_research_claim_labels",
        mode="after",
    )
    @classmethod
    def labels_stable(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable, bounded semantic labels."""
        for label in value:
            _semantic_label(label)
        return value

    @field_validator("required_assessment_finding_ordinals", mode="after")
    @classmethod
    def ordinals_positive(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        """Require positive finding ordinals."""
        if any(ordinal < 1 for ordinal in value):
            raise ValueError("required finding ordinals must be positive")
        return value

    @field_validator("required_phrases", "forbidden_phrases", mode="before")
    @classmethod
    def reject_duplicate_phrases(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before tuple conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator("required_phrases", "forbidden_phrases", mode="after")
    @classmethod
    def phrases_normalized(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Canonicalize and reject blank phrase entries."""
        result: list[str] = []
        for phrase in value:
            normalized = normalize_phrase(phrase)
            if not normalized:
                raise ValueError("expectation phrases must not be blank")
            result.append(normalized)
        return tuple(result)

    @field_validator(
        "required_limitations",
        "required_unresolved_questions",
        "required_next_steps",
        mode="after",
    )
    @classmethod
    def text_not_blank(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject blank caveat expectation entries."""
        if any(not entry.strip() for entry in value):
            raise ValueError("caveat expectations must not contain blank entries")
        return value

    @model_validator(mode="after")
    def narrative_bounds_coherent(self) -> "ExpectedReportWriterOutput":
        """Reject a max statement bound below the min bound."""
        if (
            self.max_narrative_statements is not None
            and self.max_narrative_statements < self.min_narrative_statements
        ):
            raise ValueError(
                "max_narrative_statements must not be below min_narrative_statements"
            )
        return self

    @model_validator(mode="after")
    def expectations_disjoint(self) -> "ExpectedReportWriterOutput":
        """Reject a finding/claim/phrase that is simultaneously required and forbidden."""
        finding_overlap = set(self.required_assessment_finding_ordinals) & set(
            self.forbidden_assessment_finding_ordinals
        )
        if finding_overlap:
            raise ValueError(
                "a finding ordinal cannot be both required and forbidden: "
                + ", ".join(str(ordinal) for ordinal in sorted(finding_overlap))
            )
        claim_overlap = set(self.required_research_claim_labels) & set(
            self.forbidden_research_claim_labels
        )
        if claim_overlap:
            raise ValueError(
                "a research claim label cannot be both required and forbidden: "
                + ", ".join(sorted(claim_overlap))
            )
        phrase_overlap = set(self.required_phrases) & set(self.forbidden_phrases)
        if phrase_overlap:
            raise ValueError(
                "a phrase cannot be both required and forbidden: "
                + ", ".join(sorted(phrase_overlap))
            )
        return self

    @model_validator(mode="after")
    def no_report_coherent(self) -> "ExpectedReportWriterOutput":
        """Require a declared no-report outcome to carry an execution error code."""
        if self.expected_no_report and not self.expected_execution_error_code:
            raise ValueError(
                "expected_no_report requires expected_execution_error_code"
            )
        return self


class ReportWriterScenario(BaseModel):
    """One repository-owned, versioned Report Writer evaluation scenario.

    The scenario pairs one deterministic fixture reference with one expected
    envelope. It never contains model prompt text, runtime UUIDs, or secrets.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: int = Field(ge=1)
    description: str | None = None
    fixture: str
    expected: ExpectedReportWriterOutput

    @field_validator("id", mode="after")
    @classmethod
    def id_valid(cls, value: str) -> str:
        """Require a stable lowercase scenario identifier."""
        return _scenario_id(value)

    @field_validator("fixture", mode="after")
    @classmethod
    def fixture_valid(cls, value: str) -> str:
        """Require a stable lowercase fixture reference."""
        return _semantic_label(value)

    @field_validator("description", mode="after")
    @classmethod
    def description_not_blank(cls, value: str | None) -> str | None:
        """Reject blank scenario descriptions."""
        if value is None:
            return None
        return _not_blank(value)


class ReportWriterScenarioResolution(BaseModel):
    """Immutable mapping of semantic labels to exact runtime identities.

    Produced when a scenario is materialized: ``research_claim_ids`` maps
    each declared research-claim label to its exact persisted
    ``ResearchClaim.id``, ``research_result_ids`` maps the ordered result
    labels, and the remaining maps resolve fixture labels to their persisted
    graph identities. Assessment finding ordinals are stable already and need
    no resolution. The evaluator resolves every expectation label exactly
    once and fails closed on unknown labels.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    assessment_id: UUID
    entity_ids: dict[str, UUID] = Field(default_factory=dict)
    evidence_ids: dict[str, UUID] = Field(default_factory=dict)
    relationship_ids: dict[str, UUID] = Field(default_factory=dict)
    observation_ids: dict[str, UUID] = Field(default_factory=dict)
    research_result_ids: dict[str, UUID] = Field(default_factory=dict)
    research_claim_ids: dict[str, UUID] = Field(default_factory=dict)
    citation_ids: dict[str, UUID] = Field(default_factory=dict)


class ReportWriterEvaluationInput(BaseModel):
    """Envelope facts for one Report Writer evaluation.

    ``report`` is the persisted :class:`InvestigationReport` when the
    execution succeeded; ``execution_error_code`` and ``llm_calls`` record
    safe failure metadata for scenarios that must fail before persistence
    (unsupported references, verdict-override rejection, stale Assessment
    races). No raw model output or prompt content ever appears.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    report: InvestigationReport | None = None
    execution_error_code: str | None = None
    llm_calls: int = Field(default=0, ge=0)


class ReportWriterMetrics(BaseModel):
    """Small structural metrics derived from the same comparisons as failures."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    narrative_statement_count: int = Field(ge=0)
    included_finding_ordinals: tuple[int, ...] = ()
    included_research_claim_count: int = Field(ge=0)
    required_finding_coverage: float = Field(ge=0.0, le=1.0)
    required_research_coverage: float = Field(ge=0.0, le=1.0)


class ReportWriterEvaluationResult(BaseModel):
    """The immutable result of one Report Writer evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    scenario_version: int
    passed: bool
    failures: tuple[ReportWriterFailureCode, ...]
    metrics: ReportWriterMetrics

    @model_validator(mode="after")
    def passed_consistent(self) -> "ReportWriterEvaluationResult":
        """Require ``passed`` to equal the absence of failures."""
        if self.passed != (not self.failures):
            raise ValueError("passed must equal the absence of failures")
        return self
