# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned end-to-end Investigation evaluation contracts (PR 30F).

PR 30F answers one deterministic question about a complete investigation
world executed through the production investigation orchestration and the
production Report Writer:

> Did the end-to-end investigation produce the expected durable outcome,
> trajectory, provenance, and report for the authored scenario?

Each :class:`InvestigationScenario` combines one deterministic world
fixture (a named entry point into the repository-owned synthetic world),
one canonical root indicator, and one :class:`ExpectedInvestigationOutcome`
envelope. Expectations use **semantic labels** (``root_domain``,
``resolved_ip``, ``malware_family``) rather than runtime UUIDs; the
:class:`InvestigationScenarioResolution` produced at fixture
materialization/execution time maps each label to the exact persisted
identity. Every correctness rule is a binary predicate; numeric envelopes
are explicit efficiency bounds, never a score.

These are evaluation DTOs only. They extend no runtime model and reuse the
existing domain enums (``Verdict``, ``AssessmentConfidence``,
``InvestigationStatus``, ``StopReason``, ``RelationshipType``,
``EntityType``); no production semantics are modified for evaluation
convenience.
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

from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceObservation
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    StopReason,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)
from agentic_threat_investigator.domain.report import InvestigationReport
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.evaluation.common.models import (
    ScenarioSpecification,
)
from agentic_threat_investigator.evaluation.coordinator import CoordinatorActionRecord

_SCENARIO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable lowercase scenario identifiers: letters, digits, dot, dash, underscore."""

_SEMANTIC_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable lowercase semantic fixture labels: letters, digits, dot, dash, underscore."""

_FINDING_CODE_RE = re.compile(r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$")
"""Stable finding codes: ``<category>:<disposition>`` (for example ``reputation:supporting``)."""

_ACTION_URN_RE = re.compile(r"^urn:ati:action:[a-z0-9_]+$")
"""Stable coordinator action URNs (for example ``urn:ati:action:pivot_executed``)."""

_RELATIONSHIP_URN_RE = re.compile(r"^urn:ati:relationship:[a-z]+:[a-z_]+$")
"""Stable relationship type URNs (for example ``urn:ati:relationship:dns:resolves_to``)."""

_SOURCE_URN_RE = re.compile(r"^urn:ati:source:[a-z0-9_]+$")
"""Stable provider/source URNs (for example ``urn:ati:source:threatfox``)."""

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


def _reject_duplicates(value: object, field: str) -> object:
    """Reject duplicate entries in a JSON list/tuple before tuple conversion.

    Pydantic converts list inputs to tuples silently, which would otherwise
    hide duplicates such as ``["a", "a"]``. This helper runs before
    conversion and rejects them deterministically.
    """
    if isinstance(value, (list, tuple)):
        seen: list[object] = []
        for entry in value:
            if entry in seen:
                raise ValueError(f"{field} must not contain duplicate entries")
            seen.append(entry)
    return value


def _stable_labels(value: tuple[str, ...]) -> tuple[str, ...]:
    """Require stable, bounded, lowercase semantic labels."""
    for label in value:
        _semantic_label(label)
    return value


class InvestigationRoot(BaseModel):
    """The canonical root indicator of one investigation world.

    ``entity_label`` is the stable semantic label the scenario expectations
    reference (for example ``root_domain``); ``entity_type`` and ``value``
    are the canonical entity identity the materializer persists. Scenario
    JSON contains declarative data only: never runtime UUIDs.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_label: str
    entity_type: EntityType
    value: str

    @field_validator("entity_label", mode="after")
    @classmethod
    def label_valid(cls, value: str) -> str:
        """Require a stable, bounded semantic label."""
        return _semantic_label(value)

    @field_validator("value", mode="after")
    @classmethod
    def value_valid(cls, value: str) -> str:
        """Require a nonblank canonical entity value."""
        return _not_blank(value)


class TerminalExpectation(BaseModel):
    """Expected terminal durable Investigation state."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: InvestigationStatus
    stop_reason: StopReason | None = None


class AssessmentExpectation(BaseModel):
    """Expected final current Assessment envelope.

    Finding expectations use stable structural codes ``<category>:<disposition>``
    (for example ``reputation:supporting``); findings are matched structurally,
    never by parsing Finding statement prose.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Verdict
    confidence: AssessmentConfidence
    required_findings: tuple[str, ...] = ()
    forbidden_findings: tuple[str, ...] = ()

    @field_validator("required_findings", "forbidden_findings", mode="before")
    @classmethod
    def reject_duplicate_codes(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw finding codes."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator("required_findings", "forbidden_findings", mode="after")
    @classmethod
    def finding_codes_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable ``<category>:<disposition>`` finding codes."""
        for code in value:
            if not _FINDING_CODE_RE.fullmatch(code):
                raise ValueError("finding codes must match " + _FINDING_CODE_RE.pattern)
        return value

    @model_validator(mode="after")
    def findings_disjoint(self) -> "AssessmentExpectation":
        """Reject a finding code that is simultaneously required and forbidden."""
        overlap = set(self.required_findings) & set(self.forbidden_findings)
        if overlap:
            raise ValueError(
                "a finding code cannot be both required and forbidden: "
                + ", ".join(sorted(overlap))
            )
        return self


class EvidenceExpectation(BaseModel):
    """Expected durable Evidence/Observation universe of the investigation.

    ``required_sources`` are stable provider URNs; ``required_entity_labels``
    and ``forbidden_entity_labels`` are semantic fixture labels resolved to
    persisted entity identities at execution time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    required_sources: tuple[str, ...] = ()
    required_entity_labels: tuple[str, ...] = ()
    forbidden_entity_labels: tuple[str, ...] = ()

    @field_validator(
        "required_sources",
        "required_entity_labels",
        "forbidden_entity_labels",
        mode="before",
    )
    @classmethod
    def reject_duplicate_entries(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator("required_sources", mode="after")
    @classmethod
    def sources_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable source URNs."""
        for source in value:
            if not _SOURCE_URN_RE.fullmatch(source):
                raise ValueError(
                    "required_sources must match " + _SOURCE_URN_RE.pattern
                )
        return value

    @field_validator("required_entity_labels", "forbidden_entity_labels", mode="after")
    @classmethod
    def labels_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable semantic entity labels."""
        return _stable_labels(value)

    @model_validator(mode="after")
    def entities_disjoint(self) -> "EvidenceExpectation":
        """Reject an entity label that is simultaneously required and forbidden."""
        overlap = set(self.required_entity_labels) & set(self.forbidden_entity_labels)
        if overlap:
            raise ValueError(
                "an entity label cannot be both required and forbidden: "
                + ", ".join(sorted(overlap))
            )
        return self


class RelationshipExpectation(BaseModel):
    """Expected durable RelationshipType universe of the investigation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    required: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()

    @field_validator("required", "forbidden", mode="before")
    @classmethod
    def reject_duplicate_entries(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw relationship URNs."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator("required", "forbidden", mode="after")
    @classmethod
    def urns_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable relationship type URNs."""
        for urn in value:
            if not _RELATIONSHIP_URN_RE.fullmatch(urn):
                raise ValueError(
                    "relationship expectations must match "
                    + _RELATIONSHIP_URN_RE.pattern
                )
        return value

    @model_validator(mode="after")
    def relationships_disjoint(self) -> "RelationshipExpectation":
        """Reject a relationship URN that is simultaneously required and forbidden."""
        overlap = set(self.required) & set(self.forbidden)
        if overlap:
            raise ValueError(
                "a relationship URN cannot be both required and forbidden: "
                + ", ".join(sorted(overlap))
            )
        return self


class ResearchExpectation(BaseModel):
    """Expected research context of the investigation.

    ``required_subject_labels`` and ``forbidden_subject_labels`` are semantic
    entity labels of research subjects; research remains Research, never
    Evidence.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    required_subject_labels: tuple[str, ...] = ()
    forbidden_subject_labels: tuple[str, ...] = ()

    @field_validator(
        "required_subject_labels", "forbidden_subject_labels", mode="before"
    )
    @classmethod
    def reject_duplicate_entries(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw subject labels."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator(
        "required_subject_labels", "forbidden_subject_labels", mode="after"
    )
    @classmethod
    def labels_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable semantic subject labels."""
        return _stable_labels(value)

    @model_validator(mode="after")
    def subjects_disjoint(self) -> "ResearchExpectation":
        """Reject a subject label that is simultaneously required and forbidden."""
        overlap = set(self.required_subject_labels) & set(self.forbidden_subject_labels)
        if overlap:
            raise ValueError(
                "a research subject cannot be both required and forbidden: "
                + ", ".join(sorted(overlap))
            )
        return self


class ReportExpectation(BaseModel):
    """Expected persisted InvestigationReport envelope.

    The report is generated only after terminal investigation state and
    consumes the actual final Assessment/Research. ``verdict`` and
    ``confidence`` are the report's stamping contract (equal to the final
    Assessment); finding ordinals refer to the Assessment's stable 1-based
    finding order.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    required: bool = True
    verdict: Verdict | None = None
    confidence: AssessmentConfidence | None = None
    required_finding_ordinals: tuple[int, ...] = ()
    forbidden_finding_ordinals: tuple[int, ...] = ()
    required_limitations: tuple[str, ...] = ()
    min_research_context: int = Field(default=0, ge=0)
    min_narrative_statements: int = Field(default=0, ge=0)
    max_narrative_statements: int | None = Field(default=None, ge=0)

    @field_validator(
        "required_finding_ordinals", "forbidden_finding_ordinals", mode="before"
    )
    @classmethod
    def reject_duplicate_ordinals(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw finding ordinals."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator("required_limitations", mode="before")
    @classmethod
    def reject_duplicate_limitations(
        cls, value: object, info: ValidationInfo
    ) -> object:
        """Reject duplicate raw limitation entries."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator("required_limitations", mode="after")
    @classmethod
    def limitations_normalized(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Normalize whitespace and reject blank limitation entries."""
        result: list[str] = []
        for entry in value:
            normalized = " ".join(entry.split())
            if not normalized:
                raise ValueError("required_limitations must not be blank")
            result.append(normalized)
        return tuple(result)

    @field_validator("required_finding_ordinals", mode="after")
    @classmethod
    def ordinals_positive(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        """Require positive finding ordinals."""
        if any(ordinal < 1 for ordinal in value):
            raise ValueError("required finding ordinals must be positive")
        return value

    @model_validator(mode="after")
    def ordinals_disjoint(self) -> "ReportExpectation":
        """Reject an ordinal that is simultaneously required and forbidden."""
        overlap = set(self.required_finding_ordinals) & set(
            self.forbidden_finding_ordinals
        )
        if overlap:
            raise ValueError(
                "a report finding ordinal cannot be both required and forbidden: "
                + ", ".join(str(ordinal) for ordinal in sorted(overlap))
            )
        return self

    @model_validator(mode="after")
    def narrative_bounds_coherent(self) -> "ReportExpectation":
        """Reject a max statement bound below the min bound."""
        if (
            self.max_narrative_statements is not None
            and self.max_narrative_statements < self.min_narrative_statements
        ):
            raise ValueError(
                "max_narrative_statements must not be below min_narrative_statements"
            )
        return self


class TrajectoryExpectation(BaseModel):
    """Expected structured trajectory of the investigation.

    ``required_actions`` and ``forbidden_actions`` are stable coordinator
    action URNs; ``required_research`` and ``forbidden_research`` are
    semantic research-subject labels. ``max_depth`` bounds the observed
    maximum executed pivot depth and ``termination_required`` requires the
    trajectory to end with the stable stop action.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    required_actions: tuple[str, ...] = ()
    forbidden_actions: tuple[str, ...] = ()
    required_research: tuple[str, ...] = ()
    forbidden_research: tuple[str, ...] = ()
    max_depth: int | None = Field(default=None, ge=0)
    termination_required: bool = True

    @field_validator(
        "required_actions",
        "forbidden_actions",
        "required_research",
        "forbidden_research",
        mode="before",
    )
    @classmethod
    def reject_duplicate_entries(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries."""
        return _reject_duplicates(value, info.field_name or "field")

    @field_validator("required_actions", "forbidden_actions", mode="after")
    @classmethod
    def actions_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable coordinator action URNs."""
        for action in value:
            if not _ACTION_URN_RE.fullmatch(action):
                raise ValueError(
                    "trajectory actions must match " + _ACTION_URN_RE.pattern
                )
        return value

    @field_validator("required_research", "forbidden_research", mode="after")
    @classmethod
    def research_labels_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable semantic research-subject labels."""
        return _stable_labels(value)

    @model_validator(mode="after")
    def actions_disjoint(self) -> "TrajectoryExpectation":
        """Reject an action that is simultaneously required and forbidden."""
        overlap = set(self.required_actions) & set(self.forbidden_actions)
        if overlap:
            raise ValueError(
                "an action cannot be both required and forbidden: "
                + ", ".join(sorted(overlap))
            )
        return self

    @model_validator(mode="after")
    def research_disjoint(self) -> "TrajectoryExpectation":
        """Reject a research subject that is simultaneously required and forbidden."""
        overlap = set(self.required_research) & set(self.forbidden_research)
        if overlap:
            raise ValueError(
                "a research subject cannot be both required and forbidden: "
                + ", ".join(sorted(overlap))
            )
        return self


class EfficiencyExpectation(BaseModel):
    """Explicit efficiency envelopes of one investigation world.

    Every envelope is an independent boolean predicate
    (``observed <= authored max``) guarding a documented operational
    regression risk; none is a score, weight, or threshold-derived verdict.
    All maxima are optional; an absent envelope is not evaluated.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_provider_calls: int | None = Field(default=None, ge=0)
    max_llm_calls: int | None = Field(default=None, ge=0)
    max_replans: int | None = Field(default=None, ge=0)
    max_pivots: int | None = Field(default=None, ge=0)
    max_duplicate_provider_calls: int | None = Field(default=None, ge=0)
    max_duplicate_entity_investigations: int | None = Field(default=None, ge=0)
    max_total_actions: int | None = Field(default=None, ge=0)


class ExpectedInvestigationOutcome(BaseModel):
    """The complete expected envelope of one end-to-end investigation.

    Combines terminal state, Assessment, Evidence, Relationships, Research,
    Report, trajectory, and efficiency expectations. Every rule is a binary
    predicate; aggregation stays at the common PASS/FAIL/ERROR level.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    terminal: TerminalExpectation
    assessment: AssessmentExpectation
    evidence: EvidenceExpectation = EvidenceExpectation()
    relationships: RelationshipExpectation = RelationshipExpectation()
    research: ResearchExpectation = ResearchExpectation()
    report: ReportExpectation = ReportExpectation()
    trajectory: TrajectoryExpectation = TrajectoryExpectation()
    efficiency: EfficiencyExpectation = EfficiencyExpectation()

    @model_validator(mode="after")
    def report_envelope_coherent(self) -> "ExpectedInvestigationOutcome":
        """Require the report envelope to agree with the Assessment verdict.

        A report expectation that stamps verdict/confidence must not
        contradict the expected final Assessment; the report contract is
        Assessment fidelity, never an override.
        """
        if (
            self.report.verdict is not None
            and self.report.verdict is not self.assessment.verdict
        ):
            raise ValueError(
                "report verdict expectation must equal the assessment verdict"
            )
        if (
            self.report.confidence is not None
            and self.report.confidence is not self.assessment.confidence
        ):
            raise ValueError(
                "report confidence expectation must equal the assessment confidence"
            )
        return self


class InvestigationScenario(BaseModel):
    """One repository-owned, versioned end-to-end Investigation scenario.

    The scenario pairs one common PR 30A scenario specification, one
    deterministic world fixture reference, one canonical root indicator, and
    one expected outcome envelope. It never contains model prompt text,
    runtime UUIDs, raw model output, or secrets.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: int = Field(ge=1)
    specification: ScenarioSpecification
    fixture: str
    root: InvestigationRoot
    expected: ExpectedInvestigationOutcome

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

    @model_validator(mode="after")
    def root_label_resolves(self) -> "InvestigationScenario":
        """Require the root label to match the fixture's world universe.

        The root label must be present in the fixture's declared entity-label
        universe; the fixture registry performs the exact membership check at
        resolution time (the model itself cannot import fixtures), so here we
        only reject a blank label.
        """
        if not self.root.entity_label.strip():
            raise ValueError("root entity label must not be blank")
        return self


class InvestigationScenarioResolution(BaseModel):
    """Immutable mapping of semantic labels to exact runtime identities.

    Produced when a scenario is executed: ``entity_ids`` maps every
    fixture-declared entity label (root and world-discovered labels) to its
    exact persisted ``Entity`` identity; ``investigation_id`` is the
    execution-scoped Investigation identity. The evaluator resolves every
    expectation label exactly once and fails closed on unknown labels.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    entity_ids: dict[str, UUID] = Field(default_factory=dict)

    @model_validator(mode="after")
    def labels_stable(self) -> "InvestigationScenarioResolution":
        """Require stable semantic keys and nonempty values."""
        for label, entity_id in self.entity_ids.items():
            _semantic_label(label)
            if entity_id is None:
                raise ValueError(f"entity resolution for {label!r} must not be null")
        return self


class InvestigationExecutionMetrics(BaseModel):
    """Bounded deterministic execution observations of one investigation.

    Metrics are derived exclusively from durable state and transparent
    recorders (never logs): the persisted budget counters, the structured
    timeline actions, and the exact model-call count of the injected
    ``LlmClient`` boundary. They are diagnostics and envelope operands only;
    they never combine into an aggregate correctness score.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider_calls: int = Field(ge=0)
    llm_calls: int = Field(ge=0)
    analysis_calls: int = Field(ge=0)
    research_calls: int = Field(ge=0)
    report_calls: int = Field(ge=0)
    replans: int = Field(ge=0)
    pivot_count: int = Field(ge=0)
    duplicate_provider_calls: int = Field(ge=0)
    duplicate_entity_investigations: int = Field(ge=0)
    total_actions: int = Field(ge=0)
    maximum_depth_observed: int = Field(ge=0)


class InvestigationEvaluationOutput(BaseModel):
    """Typed bounded payload one evaluator consumes for one executed case.

    Carries the authoritative durable snapshot (terminal Investigation, final
    current Assessment, persisted report, Evidence observations, Entities,
    Relationship observations, Research results), the structured trajectory
    actions (never logs), the deterministic execution metrics, and the label
    resolution. No LangSmith identity, prompt text, raw provider payload,
    model output, or report prose ever appears here.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    final_investigation: InvestigationState
    """The durable terminal InvestigationState of the current run."""

    final_assessment: Assessment | None
    """The durable final current Assessment (``None`` only for malformed output)."""

    report: InvestigationReport | None
    """The persisted InvestigationReport (``None`` = report ERROR)."""

    evidence_observations: tuple[EvidenceObservation, ...] = ()
    stable_evidence: tuple[Evidence, ...] = ()
    entities: tuple[Entity, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    relationship_observations: tuple[RelationshipObservation, ...] = ()
    research_results: tuple[ResearchResult, ...] = ()
    actions: tuple[CoordinatorActionRecord, ...] = ()
    execution_metrics: InvestigationExecutionMetrics
    resolution: InvestigationScenarioResolution


class InvestigationFailureCode(str, Enum):
    """Stable machine-readable end-to-end failure categories (PR 30F).

    Codes describe structural/behavioral acceptability only; they carry no
    scenario identity and never inspect free-form prose for relevance.
    """

    TERMINAL_STATUS_MISMATCH = "terminal_status_mismatch"
    """The durable Investigation status differs from the scenario."""

    TERMINATION_MISSING = "termination_missing"
    """The terminal state carries no stop reason."""

    FINAL_ASSESSMENT_MISSING = "final_assessment_missing"
    """The terminal Investigation has no current Assessment."""

    ASSESSMENT_VERDICT_MISMATCH = "assessment_verdict_mismatch"
    """The final Assessment verdict differs from the scenario."""

    ASSESSMENT_CONFIDENCE_MISMATCH = "assessment_confidence_mismatch"
    """The final Assessment confidence differs from the scenario."""

    REQUIRED_FINDING_MISSING = "required_finding_missing"
    """A required structural finding code is absent from the Assessment."""

    FORBIDDEN_FINDING_INCLUDED = "forbidden_finding_included"
    """A forbidden structural finding code appears in the Assessment."""

    REQUIRED_EVIDENCE_SOURCE_MISSING = "required_evidence_source_missing"
    """A required Evidence source is absent from the admitted observations."""

    REQUIRED_ENTITY_MISSING = "required_entity_missing"
    """A required entity label is absent from the investigation's entities."""

    FORBIDDEN_ENTITY_INCLUDED = "forbidden_entity_included"
    """A forbidden entity label appears in the investigation's entities."""

    REQUIRED_RELATIONSHIP_MISSING = "missing_required_relationship"
    """A required relationship type is absent from the investigation."""

    FORBIDDEN_RELATIONSHIP_INCLUDED = "forbidden_relationship_included"
    """A forbidden relationship type appears in the investigation."""

    REQUIRED_RESEARCH_MISSING = "missing_required_research"
    """A required research subject has no persisted ResearchResult."""

    RESEARCH_AUTHORIZATION_MISSING = "missing_research_authorization"
    """A required research subject has no RESEARCH_REQUESTED trajectory action."""

    FORBIDDEN_RESEARCH_INCLUDED = "forbidden_research_included"
    """A forbidden research subject has a persisted ResearchResult."""

    REPORT_MISSING = "report_missing"
    """The scenario required a report but none was persisted."""

    REPORT_VERDICT_MISMATCH = "report_verdict_mismatch"
    """The persisted report verdict differs from the final Assessment."""

    REPORT_CONFIDENCE_MISMATCH = "report_confidence_mismatch"
    """The persisted report confidence differs from the final Assessment."""

    REPORT_REQUIRED_FINDING_MISSING = "report_required_finding_missing"
    """A required Assessment finding ordinal is absent from the report."""

    REPORT_FORBIDDEN_FINDING_INCLUDED = "report_forbidden_finding_included"
    """A forbidden Assessment finding ordinal appears in the report."""

    REQUIRED_LIMITATION_MISSING = "required_limitation_missing"
    """A required limitation phrase is absent from the report."""

    REPORT_RESEARCH_CONTEXT_MISSING = "report_research_context_missing"
    """The report research-context count is below the authored envelope."""

    INVALID_REPORT_REFERENCE = "invalid_report_reference"
    """The report references material that was not supplied/admitted."""

    UNSUPPORTED_MATERIAL_REFERENCE = "unsupported_material_reference"
    """An Assessment or report claim lacks valid Evidence/Research provenance."""

    RELATIONSHIP_OBSERVATION_PROVENANCE = "relationship_observation_provenance"
    """A RelationshipObservation references material outside the investigation."""

    RESEARCH_EVIDENCE_SEPARATION = "research_evidence_separation"
    """ResearchResult identities collide with Evidence identities."""

    UNKNOWN_ENTITY_EXECUTION = "unknown_entity_execution"
    """A trajectory action targets an entity outside the investigation's entities."""

    REQUIRED_ACTION_MISSING = "required_action_missing"
    """A required trajectory action is absent from the structured actions."""

    FORBIDDEN_ACTION_INCLUDED = "forbidden_action_included"
    """A forbidden trajectory action appears in the structured actions."""

    DEPTH_POLICY_VIOLATION = "pivot_depth_violation"
    """An executed pivot exceeds the scenario's maximum depth."""

    TERMINAL_ACTION_MISSING = "terminal_action_missing"
    """The trajectory lacks the stable investigation-stop action."""

    ACTION_AFTER_TERMINAL = "action_after_terminal"
    """An action appears after the stable investigation-stop action."""

    PROVIDER_CALL_LIMIT_EXCEEDED = "provider_call_limit_exceeded"
    """The observed provider-call count exceeds the authored envelope."""

    LLM_CALL_LIMIT_EXCEEDED = "llm_call_limit_exceeded"
    """The observed model-call count exceeds the authored envelope."""

    REPLAN_LIMIT_EXCEEDED = "replan_limit_exceeded"
    """The observed replan count exceeds the authored envelope."""

    PIVOT_LIMIT_EXCEEDED = "pivot_limit_exceeded"
    """The observed pivot count exceeds the authored envelope."""

    DUPLICATE_PROVIDER_CALL_LIMIT_EXCEEDED = "duplicate_provider_call"
    """The observed duplicate provider-work count exceeds the envelope."""

    DUPLICATE_ENTITY_LIMIT_EXCEEDED = "duplicate_entity_investigation"
    """The observed duplicate entity-investigation count exceeds the envelope."""

    TOTAL_ACTIONS_LIMIT_EXCEEDED = "total_actions_limit_exceeded"
    """The observed total action count exceeds the authored envelope."""


class InvestigationEvaluationResult(BaseModel):
    """The immutable result of one end-to-end Investigation evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    scenario_version: int
    passed: bool
    failures: tuple[InvestigationFailureCode, ...]
    metrics: InvestigationExecutionMetrics

    @model_validator(mode="after")
    def passed_consistent(self) -> "InvestigationEvaluationResult":
        """Require ``passed`` to equal the absence of failures."""
        if self.passed != (not self.failures):
            raise ValueError("passed must equal the absence of failures")
        return self
