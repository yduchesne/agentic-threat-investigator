# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned Threat Research evaluation contracts (PR 22D).

PR 22D answers deterministic questions about the delivered PR 22 runtime:

* **Retrieval** — did the production retriever return the expected relevant
  material inside bounded rank/filter constraints?
* **Synthesis** — does the persisted :class:`ResearchResult` satisfy the
  scenario's citation/provenance/context envelope without silently promoting
  research into Evidence, RelationshipObservation, or Assessment?

Scenarios are data only: stable identifiers, positive versions, bounded
semantic labels, deterministic retrieval queries, and structured expectations.
They never contain runtime UUIDs, model prompt text, secrets, executable
callbacks, or scoring weights. These are evaluation DTOs only; they extend no
runtime model.
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

from agentic_threat_investigator.domain.investigation import ResearchExecutionStatus
from agentic_threat_investigator.domain.research import ResearchResult

_SCENARIO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable lowercase scenario identifiers: letters, digits, dot, dash, underscore."""

_SEMANTIC_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable lowercase semantic fixture labels: letters, digits, dot, dash, underscore."""

_MAX_SCENARIO_ID_LENGTH = 64
"""Bounded scenario identifier length."""

_MAX_SEMANTIC_LABEL_LENGTH = 64
"""Bounded semantic fixture-label length."""


def _reject_duplicates(value: object, field: str) -> object:
    """Reject duplicate entries in a JSON list/tuple before tuple conversion.

    Pydantic converts list inputs silently, which would otherwise hide
    duplicates such as ``["a", "a"]``. List/tuple inputs are compared with
    deterministic equality-based membership so malformed, unhashable members
    never raise raw ``TypeError`` from a ``set()`` call.
    """
    if isinstance(value, (list, tuple)):
        seen: list[object] = []
        for entry in value:
            if entry in seen:
                raise ValueError(f"{field} must not contain duplicate entries")
            seen.append(entry)
    return value


def _require_semantic_label(value: str, field: str) -> str:
    """Require one stable, bounded, lowercase semantic fixture label."""
    if len(value) > _MAX_SEMANTIC_LABEL_LENGTH or not _SEMANTIC_LABEL_RE.fullmatch(
        value
    ):
        raise ValueError(
            f"{field} must be a stable semantic label matching "
            + _SEMANTIC_LABEL_RE.pattern
        )
    return value


def _scenario_id(value: str) -> str:
    """Require a stable lowercase scenario identifier of bounded length."""
    if len(value) > _MAX_SCENARIO_ID_LENGTH or not _SCENARIO_ID_RE.fullmatch(value):
        raise ValueError("scenario id must match " + _SCENARIO_ID_RE.pattern)
    return value


def _not_blank(value: str) -> str:
    """Trim and reject blank scenario text values."""
    stripped = value.strip()
    if not stripped:
        raise ValueError("value must not be blank")
    return stripped


class ResearchRetrievalScenario(BaseModel):
    """One repository-owned, versioned retrieval expectation.

    The scenario declares a deterministic query and retrieval-context filters,
    plus the exact stable **upstream** identities expected and forbidden in
    the ordered retrieval response: ``source_record_id`` values (for example
    MITRE ATT&CK STIX object ids), ``source_id`` values (durable source
    URNs), and ``document_type`` values. Runtime UUIDs never appear in
    scenario files.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: int = Field(ge=1)
    description: str | None = None
    query: str
    max_results: int = Field(ge=1, le=100)

    source_ids: tuple[str, ...] = ()
    document_types: tuple[str, ...] = ()

    expected_relevant_source_records: tuple[str, ...] = ()
    expected_forbidden_source_records: tuple[str, ...] = ()
    expected_source_ids: tuple[str, ...] = ()
    expected_document_types: tuple[str, ...] = ()
    expected_max_source_rank: int | None = Field(default=None, ge=1)
    expected_retrieval_gap: bool = False

    @field_validator("id", mode="after")
    @classmethod
    def id_valid(cls, value: str) -> str:
        """Require a stable lowercase scenario identifier."""
        return _scenario_id(value)

    @field_validator("query", mode="after")
    @classmethod
    def query_not_blank(cls, value: str) -> str:
        """Reject blank retrieval queries."""
        return _not_blank(value)

    @field_validator("description", mode="after")
    @classmethod
    def description_not_blank(cls, value: str | None) -> str | None:
        """Reject blank scenario descriptions."""
        if value is None:
            return None
        return _not_blank(value)

    @field_validator(
        "source_ids",
        "document_types",
        "expected_relevant_source_records",
        "expected_forbidden_source_records",
        "expected_source_ids",
        "expected_document_types",
        mode="before",
    )
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before tuple conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @model_validator(mode="after")
    def labels_not_blank(self) -> "ResearchRetrievalScenario":
        """Reject blank filter and expectation identifiers."""
        for field in (
            "source_ids",
            "document_types",
            "expected_relevant_source_records",
            "expected_forbidden_source_records",
            "expected_source_ids",
            "expected_document_types",
        ):
            if any(not entry.strip() for entry in getattr(self, field)):
                raise ValueError(f"{field} must not contain blank identifiers")
        return self

    @model_validator(mode="after")
    def expectation_sets_disjoint(self) -> "ResearchRetrievalScenario":
        """Reject expected records that are simultaneously forbidden."""
        overlap = set(self.expected_relevant_source_records) & set(
            self.expected_forbidden_source_records
        )
        if overlap:
            raise ValueError(
                "a source record cannot be both expected relevant and forbidden: "
                + ", ".join(sorted(overlap))
            )
        return self

    @model_validator(mode="after")
    def gap_contract_coherent(self) -> "ResearchRetrievalScenario":
        """Reject a declared gap that also declares relevance truth."""
        if self.expected_retrieval_gap and (
            self.expected_relevant_source_records or self.expected_source_ids
        ):
            raise ValueError(
                "an expected retrieval gap cannot also declare expected material"
            )
        return self


class ResearchRetrievalFailureCode(str, Enum):
    """Stable machine-readable retrieval failure categories (PR 22D).

    Codes describe structural retrieval acceptability only; they carry no
    scenario identity and never inspect free-form text for relevance.
    Relevance is author-declared through stable source-record/source
    identities.
    """

    REQUIRED_RECORD_NOT_RETRIEVED = "required_record_not_retrieved"
    """An expected relevant source record is absent from the retrieved set."""

    FORBIDDEN_RECORD_RETRIEVED = "forbidden_record_retrieved"
    """A forbidden source record appears in the retrieved set."""

    EXPECTED_SOURCE_MISSING = "expected_source_missing"
    """An expected durable source identity is absent from retrieved chunks."""

    UNEXPECTED_NONEMPTY_RETRIEVAL = "unexpected_nonempty_retrieval"
    """A scenario declaring no relevance truth and no explicit gap observed material."""

    EXPECTED_RETRIEVAL_GAP_NOT_OBSERVED = "expected_retrieval_gap_not_observed"
    """The scenario declared an explicit retrieval gap but retrieval returned material."""

    FILTER_VIOLATION = "filter_violation"
    """A retrieved chunk violates the scenario's source/document-type filters."""

    EXPECTED_RANK_VIOLATION = "expected_rank_violation"
    """The first expected relevant record ranked beyond the declared maximum rank."""

    DUPLICATE_RETRIEVAL_IDENTITY = "duplicate_retrieval_identity"
    """The retrieval response repeats one stable chunk citation identity."""


class ResearchRetrievalMetrics(BaseModel):
    """Deterministic metrics derived from the same comparison as the failures.

    ``None`` marks an undefined denominator: no relevance truth was declared.
    An explicit retrieval-gap case scores perfect recall/precision; an
    expected-relevance case with an empty response scores zero.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    recall_at_k: float | None
    precision_at_k: float | None
    mrr: float | None
    expected_source_rank: int | None = Field(default=None, ge=1)


class ResearchRetrievalEvaluationResult(BaseModel):
    """The immutable result of one retrieval evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    passed: bool
    failures: tuple[ResearchRetrievalFailureCode, ...]
    metrics: ResearchRetrievalMetrics

    @model_validator(mode="after")
    def passed_consistent(self) -> "ResearchRetrievalEvaluationResult":
        """Require ``passed`` to equal the absence of failures."""
        if self.passed != (not self.failures):
            raise ValueError("passed must equal the absence of failures")
        return self


class ResearchFixtureReference(BaseModel):
    """Stable semantic fixture reference for a research scenario."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str

    @field_validator("name", mode="after")
    @classmethod
    def name_present(cls, value: str) -> str:
        """Reject blank fixture reference names."""
        return _not_blank(value)


class ExpectedResearchClaim(BaseModel):
    """One bounded structural claim expectation (PR 22D).

    A persisted claim satisfies the expectation when its citation set
    contains every required resolved citation label and its text, after
    canonical whitespace normalization, contains every required phrase and no
    forbidden phrase. No stemming, embeddings, fuzzy similarity, or strict
    whole-text equality is ever used.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    citation_labels: tuple[str, ...]
    required_phrases: tuple[str, ...] = ()
    forbidden_phrases: tuple[str, ...] = ()

    @field_validator("citation_labels", mode="after")
    @classmethod
    def citation_labels_stable(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable, bounded semantic citation labels."""
        for label in value:
            _require_semantic_label(label, "citation_labels")
        return value

    @field_validator("required_phrases", "forbidden_phrases", mode="after")
    @classmethod
    def phrases_normalized(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Canonicalize and reject blank phrase entries."""
        result: list[str] = []
        for phrase in value:
            normalized = _normalize_whitespace(phrase)
            if not normalized:
                raise ValueError("expectation phrases must not be blank")
            result.append(normalized)
        return tuple(result)

    @field_validator(
        "citation_labels", "required_phrases", "forbidden_phrases", mode="before"
    )
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before tuple conversion."""
        return _reject_duplicates(value, info.field_name or "field")


class ExpectedResearchResult(BaseModel):
    """The acceptable deterministic envelope for one persisted ResearchResult.

    The envelope is structural: exact citation identities, exact phrase
    membership after whitespace normalization, explicit claim-count bounds,
    explicit empty-result semantics, and epistemic non-promotion gates. It
    never encodes whole-report text similarity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    min_claims: int = Field(default=0, ge=0)
    max_claims: int | None = Field(default=None, ge=0)

    required_citation_labels: tuple[str, ...] = ()
    forbidden_citation_labels: tuple[str, ...] = ()

    required_claims: tuple[ExpectedResearchClaim, ...] = ()
    expected_empty_result: bool = False

    expect_no_evidence_promotion: bool = True
    expect_no_assessment_promotion: bool = True

    @field_validator(
        "required_citation_labels",
        "forbidden_citation_labels",
        mode="before",
    )
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before tuple conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator(
        "required_citation_labels", "forbidden_citation_labels", mode="after"
    )
    @classmethod
    def citation_labels_stable(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable, bounded semantic citation labels."""
        for label in value:
            _require_semantic_label(label, "citation_labels")
        return value

    @model_validator(mode="after")
    def claim_count_bounds_coherent(self) -> "ExpectedResearchResult":
        """Reject a max bound below the min bound."""
        if self.max_claims is not None and self.max_claims < self.min_claims:
            raise ValueError("max_claims must not be below min_claims")
        return self

    @model_validator(mode="after")
    def citation_expectations_disjoint(self) -> "ExpectedResearchResult":
        """Reject a label that is simultaneously required and forbidden."""
        overlap = set(self.required_citation_labels) & set(
            self.forbidden_citation_labels
        )
        if overlap:
            raise ValueError(
                "a citation label cannot be both required and forbidden: "
                + ", ".join(sorted(overlap))
            )
        return self

    @model_validator(mode="after")
    def claim_expectation_labels_declared(self) -> "ExpectedResearchResult":
        """Require every claim expectation label to be declared in the envelope.

        A required claim that references an undeclared label would never
        resolve against a deterministic resolution; failing at load time keeps
        authoring fail-closed.
        """
        declared = set(self.required_citation_labels) | set(
            self.forbidden_citation_labels
        )
        for claim in self.required_claims:
            unknown = sorted(set(claim.citation_labels) - declared)
            if unknown:
                raise ValueError(
                    "required claim cites undeclared citation labels: "
                    + ", ".join(unknown)
                )
        return self


class ResearchSynthesisScenario(BaseModel):
    """One repository-owned, versioned synthesis evaluation scenario.

    The scenario pairs one deterministic fixture with one expected-result
    envelope, carries the exact retrieval context (query, filters,
    ``max_results``) used to produce the persisted result under evaluation,
    and declares the semantic label universe: each citation label in
    ``source_records`` names the stable upstream ``source_record_id`` that
    materialization must resolve to an exact persisted ``citation_id``. It
    never contains model prompt text, runtime UUIDs, or secrets.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: int = Field(ge=1)
    description: str | None = None
    fixture: ResearchFixtureReference
    query: str
    source_ids: tuple[str, ...] = ()
    document_types: tuple[str, ...] = ()
    max_results: int = Field(default=8, ge=1, le=100)
    source_records: dict[str, str] = Field(default_factory=dict)
    expected: ExpectedResearchResult

    @field_validator("id", mode="after")
    @classmethod
    def id_valid(cls, value: str) -> str:
        """Require a stable lowercase scenario identifier."""
        return _scenario_id(value)

    @field_validator("description", mode="after")
    @classmethod
    def description_not_blank(cls, value: str | None) -> str | None:
        """Reject blank scenario descriptions."""
        if value is None:
            return None
        return _not_blank(value)

    @field_validator("query", mode="after")
    @classmethod
    def query_not_blank(cls, value: str) -> str:
        """Reject blank retrieval queries."""
        return _not_blank(value)

    @field_validator("source_ids", "document_types", mode="before")
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before tuple conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @model_validator(mode="after")
    def filters_not_blank(self) -> "ResearchSynthesisScenario":
        """Reject blank retrieval filter identifiers."""
        for field in ("source_ids", "document_types"):
            if any(not entry.strip() for entry in getattr(self, field)):
                raise ValueError(f"{field} must not contain blank identifiers")
        return self

    @model_validator(mode="after")
    def source_records_stable(self) -> "ResearchSynthesisScenario":
        """Require stable semantic label keys and nonblank upstream identities."""
        for label, record_id in self.source_records.items():
            _require_semantic_label(label, "source_records")
            if not record_id.strip():
                raise ValueError(
                    "source_records values must not be blank upstream identities"
                )
        return self

    @model_validator(mode="after")
    def expectation_labels_declared(self) -> "ResearchSynthesisScenario":
        """Require every expected citation label to be declared in the fixture map.

        An expectation label with no authored ``source_records`` entry can
        never resolve to a persisted citation ID; failing closed at load time
        keeps authoring deterministic.
        """
        expected = self.expected
        declared = set(self.source_records)
        referenced = set(expected.required_citation_labels)
        referenced.update(expected.forbidden_citation_labels)
        for claim in expected.required_claims:
            referenced.update(claim.citation_labels)
        unknown = sorted(referenced - declared)
        if unknown:
            raise ValueError(
                "scenario expectations reference undeclared citation labels: "
                + ", ".join(unknown)
            )
        return self


class ResearchScenarioResolution(BaseModel):
    """Immutable mapping of semantic labels to exact runtime identities.

    Produced after the production corpus is materialized and retrieved:
    ``citations`` maps each stable citation label to its exact persisted
    ``citation_id``; ``source_records`` maps semantic source labels to their
    stable upstream ``source_record_id`` when the label names a record
    identity. The evaluator resolves every expectation label exactly once and
    fails closed on unknown labels.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    citations: dict[str, UUID] = Field(default_factory=dict)
    source_records: dict[str, str] = Field(default_factory=dict)


class ResearchEpistemicSnapshot(BaseModel):
    """Evaluation-only immutable snapshot of promotion-sensitive identities.

    Captured immediately before and immediately after an isolated research
    interval through the application UnitOfWork seam. Only identities/versions
    are recorded: never payloads, claim text, or prompt content.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_ids: tuple[UUID, ...] = ()
    relationship_observation_ids: tuple[UUID, ...] = ()
    assessment_identities: tuple[tuple[UUID, int], ...] = ()


class ResearchSynthesisFailureCode(str, Enum):
    """Stable machine-readable synthesis failure categories (PR 22D)."""

    RESULT_INVESTIGATION_MISMATCH = "result_investigation_mismatch"
    """The persisted result anchors a different investigation."""

    RESULT_SUBJECT_MISMATCH = "result_subject_mismatch"
    """The persisted result anchors a different subject entity."""

    INVALID_CITATION_CLOSURE = "invalid_citation_closure"
    """A claim cites a citation missing from the result's citation snapshots."""

    CITATION_NOT_SUPPLIED = "citation_not_supplied"
    """A result citation was never supplied to the model invocation."""

    EXPECTED_EMPTY_RESULT_NOT_EMPTY = "expected_empty_result_not_empty"
    """The scenario expected an empty result but the result carries material."""

    UNEXPECTED_EMPTY_RESULT = "unexpected_empty_result"
    """The scenario demanded material but the persisted result is empty."""

    CLAIM_COUNT_OUT_OF_BOUNDS = "claim_count_out_of_bounds"
    """The persisted claim count is outside the scenario's bounds."""

    REQUIRED_CITATION_MISSING = "required_citation_missing"
    """A required citation label is absent from the persisted result."""

    FORBIDDEN_CITATION_USED = "forbidden_citation_used"
    """A forbidden citation label appears in the persisted result."""

    REQUIRED_CLAIM_MISSING = "required_claim_missing"
    """No persisted claim satisfies a required claim expectation."""

    FORBIDDEN_CLAIM_CONTENT = "forbidden_claim_content"
    """A matched claim contains a forbidden normalized phrase."""

    EVIDENCE_PROMOTION_DETECTED = "evidence_promotion_detected"
    """Research execution changed the investigation's Evidence identity set."""

    RELATIONSHIP_OBSERVATION_PROMOTION_DETECTED = (
        "relationship_observation_promotion_detected"
    )
    """Research execution changed the RelationshipObservation identity set."""

    ASSESSMENT_PROMOTION_DETECTED = "assessment_promotion_detected"
    """Research execution changed the Assessment identity/version set."""


class ResearchSynthesisMetrics(BaseModel):
    """Small structural metrics derived from the same comparisons as failures."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    citation_validity_rate: float = Field(ge=0.0, le=1.0)
    required_citation_coverage: float = Field(ge=0.0, le=1.0)
    required_claim_coverage: float = Field(ge=0.0, le=1.0)
    epistemic_promotion_count: int = Field(ge=0)


class ResearchSynthesisEvaluationResult(BaseModel):
    """The immutable result of one synthesis evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    scenario_version: int
    passed: bool
    failures: tuple[ResearchSynthesisFailureCode, ...]
    metrics: ResearchSynthesisMetrics

    @model_validator(mode="after")
    def passed_consistent(self) -> "ResearchSynthesisEvaluationResult":
        """Require ``passed`` to equal the absence of failures."""
        if self.passed != (not self.failures):
            raise ValueError("passed must equal the absence of failures")
        return self


class ResearchExecutionEvaluationInput(BaseModel):
    """Execution-envelope facts for scenarios that may fail before a result.

    Used only where a scenario intentionally exercises a safe-failure path
    (for example an unsupported citation) and no persisted
    :class:`ResearchResult` exists to evaluate. Keeps the synthesis evaluator
    free of fabricated empty results.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    result: ResearchResult | None = None
    execution_error_code: str | None = None
    llm_calls: int = Field(default=0, ge=0)
    research_requests: int = Field(default=0, ge=0)
    final_execution_status: ResearchExecutionStatus | None = None


def _normalize_whitespace(value: str) -> str:
    """Collapse all runs of whitespace to single spaces and trim."""
    return " ".join(value.split())
