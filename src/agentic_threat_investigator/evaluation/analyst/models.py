# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned Evidence Analyst evaluation contracts (PR 20C).

PR 20C answers one question about a persisted
:class:`~agentic_threat_investigator.domain.assessment.Assessment` produced
through the unchanged PR 20B execution path:

> Did the Evidence Analyst make an acceptable analytical decision for a known
> scenario?

Each :class:`AnalystScenario` combines one deterministic fixture (a compact,
label-based description of the persisted Investigation/Evidence/Relationship
graph the scenario is materialized into) with one
:class:`ExpectedAssessment` envelope. Expectations use **semantic labels**
(``"threatfox_async_rat_association"``) rather than runtime UUIDs; the
:class:`AnalystScenarioResolution` produced at fixture materialization time
maps each label to the exact persisted identity.

The evaluator (:class:`EvidenceAnalystEvaluator`) compares a persisted
Assessment to the scenario's declared envelope. It is synchronous and pure:
no database, network, LLM, environment, or clock access. Findings are matched
structurally (category, disposition, support identity, confidence) — never by
parsing Finding statement prose. The only string comparison performed is
exact, normalized matching of the repository-owned canonical limitation /
unresolved-question / next-step phrases declared in
:class:`ExpectedAssessment` to the persisted Assessment text collections.

These are evaluation DTOs only. They extend no runtime model and reuse the
existing domain enums (``Verdict``, ``AssessmentConfidence``,
``FindingCategory``, ``FindingDisposition``); no production Assessment
semantics are modified for evaluation convenience.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Any
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
    AssessmentConfidence,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType

_SCENARIO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable lowercase scenario identifiers: letters, digits, dot, dash, underscore."""

_SEMANTIC_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Stable lowercase semantic fixture labels: letters, digits, dot, dash, underscore."""

_MAX_SCENARIO_TAGS = 10
"""Bounded number of tags a scenario may carry."""

_MAX_SCENARIO_ID_LENGTH = 64
"""Bounded scenario identifier length."""

_MAX_SEMANTIC_LABEL_LENGTH = 64
"""Bounded semantic fixture-label length."""


def _reject_duplicates(value: object, field: str) -> object:
    """Reject duplicate entries in a JSON list/tuple before set conversion.

    Pydantic converts list inputs to ``frozenset`` fields silently, which
    would otherwise hide duplicates such as ``["a", "a"]``. This helper runs
    before conversion. List/tuple inputs are compared with deterministic
    equality-based membership so malformed, unhashable members (nested lists
    or objects) never raise raw ``TypeError`` from a ``set()`` call; Pydantic
    rejects non-duplicate malformed members according to the declared
    ``frozenset[...]`` element type. Already-constructed set/frozenset values
    are returned unchanged because their duplicates were already lost at
    construction.
    """
    if isinstance(value, (list, tuple)):
        seen: list[object] = []
        for entry in value:
            if entry in seen:
                raise ValueError(f"{field} must not contain duplicate entries")
            seen.append(entry)
    return value


def _require_semantic_label(value: str, field: str) -> str:
    """Require one stable, bounded, lowercase semantic fixture label.

    No trimming or silent normalization is performed: a value that does not
    match the documented contract fails exactly as authored.
    """
    if len(value) > _MAX_SEMANTIC_LABEL_LENGTH or not _SEMANTIC_LABEL_RE.fullmatch(
        value
    ):
        raise ValueError(
            f"{field} must be a stable semantic label matching "
            + _SEMANTIC_LABEL_RE.pattern
        )
    return value


class UnknownFixtureLabelError(ValueError):
    """A semantic fixture label cannot be resolved to a persisted identity.

    The evaluator fails closed: expectations must reference labels that the
    scenario declares and the resolution maps to an exact persisted UUID.
    """

    def __init__(self, kind: str, label: str) -> None:
        """Record the unresolved kind and label."""
        super().__init__(f"unknown fixture {kind} label: {label!r}")
        self.kind = kind
        self.label = label


class AnalystEvaluationFailureCode(str, Enum):
    """Stable machine-readable behavioral failure categories.

    These codes describe analytical acceptability only. Structural or
    provenance invalidity (unknown Evidence, cross-investigation references,
    invalid observation chains) is PR 20A validation territory and is never
    reported here.
    """

    VERDICT_NOT_ALLOWED = "verdict_not_allowed"
    """The Assessment verdict is outside the scenario's allowed envelope."""

    CONFIDENCE_NOT_ALLOWED = "confidence_not_allowed"
    """The Assessment confidence is outside the scenario's allowed envelope."""

    REQUIRED_FINDING_MISSING = "required_finding_missing"
    """No Finding satisfies a required Finding expectation."""

    FORBIDDEN_FINDING_PRESENT = "forbidden_finding_present"
    """A Finding matches a ForbiddenFinding regression pattern."""

    REQUIRED_SUPPORT_MISSING = "required_support_missing"
    """Candidates exist but none carries the expectation's required support."""

    FORBIDDEN_SUPPORT_USED = "forbidden_support_used"
    """A candidate Finding cites support the expectation forbids."""

    REQUIRED_CONTRADICTION_MISSING = "required_contradiction_missing"
    """A required contradiction pair is not fully represented."""

    REQUIRED_LIMITATION_MISSING = "required_limitation_missing"
    """A required canonical limitation phrase is absent from the Assessment."""

    REQUIRED_UNRESOLVED_QUESTION_MISSING = "required_unresolved_question_missing"
    """A required canonical unresolved question is absent."""

    REQUIRED_NEXT_STEP_MISSING = "required_next_step_missing"
    """A required canonical next step is absent."""

    UNSUPPORTED_MATERIAL_FINDING = "unsupported_material_finding"
    """A material Finding's support is entirely scenario-declared context."""

    CONTEXTUAL_EVIDENCE_MISUSED = "contextual_evidence_misused"
    """Scenario-declared contextual-only evidence supports a material Finding."""


class ExpectedFinding(BaseModel):
    """A structured expectation one Finding may satisfy.

    A persisted Finding satisfies this expectation when its category and
    disposition match (where constrained), its support contains every
    required label, it cites no forbidden label, and its confidence is
    allowed where constrained. Statement prose is never inspected.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: FindingCategory | None = None
    disposition: FindingDisposition | None = None
    allowed_confidence: frozenset[AssessmentConfidence] = frozenset()
    required_evidence_support: frozenset[str] = frozenset()
    required_relationship_support: frozenset[str] = frozenset()
    forbidden_evidence_support: frozenset[str] = frozenset()
    forbidden_relationship_support: frozenset[str] = frozenset()

    @field_validator(
        "allowed_confidence",
        "required_evidence_support",
        "required_relationship_support",
        "forbidden_evidence_support",
        "forbidden_relationship_support",
        mode="before",
    )
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before frozenset conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @model_validator(mode="after")
    def labels_stable(self) -> "ExpectedFinding":
        """Require every support label to be a stable semantic label."""
        for field in (
            "required_evidence_support",
            "required_relationship_support",
            "forbidden_evidence_support",
            "forbidden_relationship_support",
        ):
            for label in getattr(self, field):
                _require_semantic_label(label, field)
        return self

    @model_validator(mode="after")
    def requires_constraint(self) -> "ExpectedFinding":
        """Reject an expectation that constrains nothing at all."""
        if (
            self.category is None
            and self.disposition is None
            and not self.required_evidence_support
            and not self.required_relationship_support
            and not self.allowed_confidence
        ):
            raise ValueError(
                "an expected finding must constrain category, disposition, "
                "required support, or confidence"
            )
        return self

    @model_validator(mode="after")
    def supports_disjoint(self) -> "ExpectedFinding":
        """Reject a label declared both required and forbidden."""
        overlap_evidence = (
            self.required_evidence_support & self.forbidden_evidence_support
        )
        overlap_relationship = (
            self.required_relationship_support & self.forbidden_relationship_support
        )
        if overlap_evidence or overlap_relationship:
            raise ValueError(
                "a fixture label cannot be both required and forbidden support"
            )
        return self


class ForbiddenFinding(BaseModel):
    """An explicit negative expectation for a known analytical regression.

    A persisted Finding matches when its category and disposition match
    (where constrained) and, when support is declared, it cites at least one
    of the declared labels. This is how PR 20C encodes rules such as
    "DB-IP city evidence is not maliciousness support" without parsing
    Finding prose.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: FindingCategory | None = None
    disposition: FindingDisposition | None = None
    evidence_support: frozenset[str] = frozenset()
    relationship_support: frozenset[str] = frozenset()

    @field_validator("evidence_support", "relationship_support", mode="before")
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before frozenset conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @model_validator(mode="after")
    def labels_stable(self) -> "ForbiddenFinding":
        """Require every support label to be a stable semantic label."""
        for field in ("evidence_support", "relationship_support"):
            for label in getattr(self, field):
                _require_semantic_label(label, field)
        return self

    @model_validator(mode="after")
    def requires_constraint(self) -> "ForbiddenFinding":
        """Reject a pattern that would forbid every possible Finding."""
        if (
            self.category is None
            and self.disposition is None
            and not self.evidence_support
            and not self.relationship_support
        ):
            raise ValueError(
                "a forbidden finding must constrain category, disposition, or support"
            )
        return self


class RequiredContradiction(BaseModel):
    """One explicitly required contradiction pair.

    The Assessment must represent both sides: a SUPPORTING Finding backed by
    one provenance set and a CONTRADICTING Finding backed by another. The
    evaluator never decides on its own that a provider disagreement is a
    contradiction.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    supporting_finding: ExpectedFinding
    contradicting_finding: ExpectedFinding

    @model_validator(mode="after")
    def dispositions_opposed(self) -> "RequiredContradiction":
        """Require the supporting side to support and the opposing side to contradict."""
        if self.supporting_finding.disposition is not FindingDisposition.SUPPORTING:
            raise ValueError(
                "a required contradiction supporting side must be SUPPORTING"
            )
        if (
            self.contradicting_finding.disposition
            is not FindingDisposition.CONTRADICTING
        ):
            raise ValueError(
                "a required contradiction contradicting side must be CONTRADICTING"
            )
        return self


class ExpectedAssessment(BaseModel):
    """The acceptable analytical envelope for one persisted Assessment.

    The envelope is intentionally not an exact snapshot: the Assessment
    summary and Finding statements are never compared, extra structurally
    valid Findings are allowed unless matched by a forbidden expectation or
    forbidden support semantics, and limitations/questions/next steps are
    checked as exact canonical phrase membership (extra items are allowed).

    ``forbidden_evidence_support`` / ``forbidden_relationship_support``
    declare **contextual-only** labels: evidence/observation labels that must
    not materially support a verdict. The only legitimate citation of these
    labels is inside a GEOLOCATION-category SUPPORTING Finding (the domain's
    explicit contextual category); anywhere else the evaluator reports
    :data:`AnalystEvaluationFailureCode.CONTEXTUAL_EVIDENCE_MISUSED`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_verdicts: frozenset[Verdict]
    allowed_confidence: frozenset[AssessmentConfidence]

    required_findings: tuple[ExpectedFinding, ...] = ()
    forbidden_findings: tuple[ForbiddenFinding, ...] = ()
    required_contradictions: tuple[RequiredContradiction, ...] = ()

    forbidden_evidence_support: frozenset[str] = frozenset()
    forbidden_relationship_support: frozenset[str] = frozenset()

    required_limitations: frozenset[str] = frozenset()
    required_unresolved_questions: frozenset[str] = frozenset()
    required_next_steps: frozenset[str] = frozenset()

    @field_validator(
        "allowed_verdicts",
        "allowed_confidence",
        "forbidden_evidence_support",
        "forbidden_relationship_support",
        "required_limitations",
        "required_unresolved_questions",
        "required_next_steps",
        mode="before",
    )
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before frozenset conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @model_validator(mode="after")
    def labels_stable(self) -> "ExpectedAssessment":
        """Require every contextual-only support label to be a stable semantic label."""
        for field in ("forbidden_evidence_support", "forbidden_relationship_support"):
            for label in getattr(self, field):
                _require_semantic_label(label, field)
        return self

    @model_validator(mode="after")
    def envelopes_nonempty(self) -> "ExpectedAssessment":
        """Require non-empty verdict and confidence envelopes."""
        if not self.allowed_verdicts:
            raise ValueError("allowed_verdicts must not be empty")
        if not self.allowed_confidence:
            raise ValueError("allowed_confidence must not be empty")
        return self

    @model_validator(mode="after")
    def findings_unique(self) -> "ExpectedAssessment":
        """Reject duplicate expectation fixtures (identical value equality)."""
        if len(set(self.required_findings)) != len(self.required_findings):
            raise ValueError("required findings must be unique")
        if len(set(self.forbidden_findings)) != len(self.forbidden_findings):
            raise ValueError("forbidden findings must be unique")
        if len(set(self.required_contradictions)) != len(self.required_contradictions):
            raise ValueError("required contradictions must be unique")
        return self

    @model_validator(mode="after")
    def canonical_text_nonblank(self) -> "ExpectedAssessment":
        """Reject blank canonical limitation/question/next-step phrases."""
        for collection_name, collection in (
            ("required_limitations", self.required_limitations),
            ("required_unresolved_questions", self.required_unresolved_questions),
            ("required_next_steps", self.required_next_steps),
        ):
            if any(not entry.strip() for entry in collection):
                raise ValueError(
                    f"{collection_name} must not contain blank canonical phrases"
                )
        return self


class FixtureEntity(BaseModel):
    """One canonical entity the fixture materializes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    type: EntityType
    value: str

    @field_validator("label", mode="after")
    @classmethod
    def label_stable(cls, value: str) -> str:
        """Require a stable semantic label."""
        return _require_semantic_label(value, "label")


class FixtureEvidence(BaseModel):
    """One immutable Evidence observation the fixture materializes.

    ``stale`` is scenario-author metadata documenting that the observation is
    intentionally stale; the deterministic behavioral expectation is the
    scenario's required limitation, never a global freshness policy.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    type: EvidenceType
    subject: str
    source: str
    facts: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime | None = None
    retrieved_at: datetime | None = None
    stale: bool = False

    @field_validator("label", "subject", mode="after")
    @classmethod
    def labels_stable(cls, value: str, info: ValidationInfo) -> str:
        """Require stable semantic labels."""
        return _require_semantic_label(value, info.field_name or "label")

    @field_validator("observed_at", "retrieved_at")
    @classmethod
    def normalize_utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware fixture timestamps, normalized to UTC."""
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("fixture evidence timestamps must be timezone-aware")
        return value.astimezone(UTC)


class FixtureRelationship(BaseModel):
    """One stable Relationship edge the fixture materializes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    type: RelationshipType
    source: str
    target: str

    @field_validator("label", "source", "target", mode="after")
    @classmethod
    def labels_stable(cls, value: str, info: ValidationInfo) -> str:
        """Require stable semantic labels."""
        return _require_semantic_label(value, info.field_name or "label")


class FixtureObservation(BaseModel):
    """One historical RelationshipObservation the fixture materializes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    relationship: str
    evidence: str
    source: str
    confidence: float | None = None

    @field_validator("label", "relationship", "evidence", mode="after")
    @classmethod
    def labels_stable(cls, value: str, info: ValidationInfo) -> str:
        """Require stable semantic labels."""
        return _require_semantic_label(value, info.field_name or "label")


class AnalystFixture(BaseModel):
    """A deterministic, label-based description of one persisted graph.

    The fixture is data only: no executable callbacks, no provider-specific
    prompt text, no secrets. At materialization time each label becomes an
    exact persisted UUID inside an :class:`AnalystScenarioResolution`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    objective: str
    root_entity: str
    entities: tuple[FixtureEntity, ...]
    evidence: tuple[FixtureEvidence, ...] = ()
    relationships: tuple[FixtureRelationship, ...] = ()
    observations: tuple[FixtureObservation, ...] = ()

    @field_validator("root_entity", mode="after")
    @classmethod
    def root_entity_stable(cls, value: str) -> str:
        """Require the root-entity label to be a stable semantic label."""
        return _require_semantic_label(value, "root_entity")

    @field_validator("objective", mode="after")
    @classmethod
    def objective_not_blank(cls, value: str) -> str:
        """Reject blank investigation objectives."""
        if not value.strip():
            raise ValueError("fixture objective must not be blank")
        return value

    @model_validator(mode="after")
    def labels_unique_and_resolvable(self) -> "AnalystFixture":
        """Require globally unique labels and valid cross-references."""
        if not self.entities:
            raise ValueError("a fixture must declare at least one entity")
        entity_labels = {entity.label for entity in self.entities}
        evidence_labels = {evidence.label for evidence in self.evidence}
        relationship_labels = {
            relationship.label for relationship in self.relationships
        }
        observation_labels = {observation.label for observation in self.observations}
        if self.root_entity not in entity_labels:
            raise ValueError("fixture root_entity must reference a declared entity")
        all_labels = (
            entity_labels | evidence_labels | relationship_labels | observation_labels
        )
        total_count = (
            len(self.entities)
            + len(self.evidence)
            + len(self.relationships)
            + len(self.observations)
        )
        if len(self.entities) != len(entity_labels):  # pragma: no cover
            raise ValueError("fixture entity labels must be unique")
        if len(all_labels) != total_count:
            raise ValueError(
                "fixture labels must be unique across entities, evidence, "
                "relationships, and observations"
            )
        for evidence in self.evidence:
            if evidence.subject not in entity_labels:
                raise ValueError(
                    f"fixture evidence {evidence.label!r} references an "
                    "unknown subject entity"
                )
        for relationship in self.relationships:
            if relationship.source not in entity_labels:
                raise ValueError(
                    f"fixture relationship {relationship.label!r} references an "
                    "unknown source entity"
                )
            if relationship.target not in entity_labels:
                raise ValueError(
                    f"fixture relationship {relationship.label!r} references an "
                    "unknown target entity"
                )
        for observation in self.observations:
            if observation.relationship not in relationship_labels:
                raise ValueError(
                    f"fixture observation {observation.label!r} references an "
                    "unknown relationship"
                )
            if observation.evidence not in evidence_labels:
                raise ValueError(
                    f"fixture observation {observation.label!r} references an "
                    "unknown evidence row"
                )
        return self


def expected_support_labels(
    expected: ExpectedAssessment,
) -> tuple[frozenset[str], frozenset[str]]:
    """Return every evidence and observation label the expectations reference.

    The returned pair is (evidence labels, observation labels). Both the
    scenario validator (expectation labels must exist in the fixture) and the
    evaluator (labels must resolve in the resolution before any comparison)
    use this same collection, so the fail-closed label contract cannot drift
    between load time and evaluation time.
    """
    evidence: set[str] = set(expected.forbidden_evidence_support)
    observations: set[str] = set(expected.forbidden_relationship_support)
    for expectation in expected.required_findings:
        evidence.update(expectation.required_evidence_support)
        evidence.update(expectation.forbidden_evidence_support)
        observations.update(expectation.required_relationship_support)
        observations.update(expectation.forbidden_relationship_support)
    for pattern in expected.forbidden_findings:
        evidence.update(pattern.evidence_support)
        observations.update(pattern.relationship_support)
    for contradiction in expected.required_contradictions:
        for side in (
            contradiction.supporting_finding,
            contradiction.contradicting_finding,
        ):
            evidence.update(side.required_evidence_support)
            evidence.update(side.forbidden_evidence_support)
            observations.update(side.required_relationship_support)
            observations.update(side.forbidden_relationship_support)
    return frozenset(evidence), frozenset(observations)


class AnalystScenario(BaseModel):
    """One repository-owned Evidence Analyst evaluation scenario.

    The scenario carries a stable identifier, a positive version, a bounded
    tag set, one deterministic fixture, and one expected-Assessment
    contract. It never contains executable callbacks, model/prompt text, or
    secrets.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: int = Field(ge=1)
    description: str
    tags: frozenset[str] = frozenset()
    fixture: AnalystFixture
    expected: ExpectedAssessment

    @field_validator("tags", mode="before")
    @classmethod
    def tags_reject_duplicates_and_bound(
        cls, value: object, info: ValidationInfo
    ) -> object:
        """Reject duplicate tags and enforce the raw count bound."""
        if isinstance(value, (list, tuple)) and len(value) > _MAX_SCENARIO_TAGS:
            raise ValueError(
                f"{info.field_name or 'tags'} is bounded to {_MAX_SCENARIO_TAGS} entries"
            )
        return _reject_duplicates(value, info.field_name or "tags")

    @field_validator("id", mode="after")
    @classmethod
    def id_valid(cls, value: str) -> str:
        """Require a stable lowercase identifier of bounded length."""
        if len(value) > _MAX_SCENARIO_ID_LENGTH or not _SCENARIO_ID_RE.fullmatch(value):
            raise ValueError("scenario id must match " + _SCENARIO_ID_RE.pattern)
        return value

    @field_validator("description", mode="after")
    @classmethod
    def description_not_blank(cls, value: str) -> str:
        """Reject blank scenario descriptions."""
        if not value.strip():
            raise ValueError("scenario description must not be blank")
        return value

    @model_validator(mode="after")
    def tags_bounded(self) -> "AnalystScenario":
        """Require nonblank tags within a bounded count."""
        # The mode="before" validator already rejects raw list/tuple inputs
        # above the bound; this branch defends direct frozenset construction,
        # which is not a supported authoring path.
        if (
            len(self.tags) > _MAX_SCENARIO_TAGS
        ):  # pragma: no cover - before-validator guards raw input
            raise ValueError(f"scenario tags are bounded to {_MAX_SCENARIO_TAGS}")
        if any(not tag.strip() for tag in self.tags):
            raise ValueError("scenario tags must not be blank")
        return self

    @model_validator(mode="after")
    def expected_labels_resolve(self) -> "AnalystScenario":
        """Require every expected support label to exist in the fixture.

        Human-authored expectations use stable semantic labels; a label that
        does not name a fixture entity/evidence/observation can never
        resolve to a persisted UUID and is rejected at load time.
        """
        evidence_labels = {evidence.label for evidence in self.fixture.evidence}
        observation_labels = {
            observation.label for observation in self.fixture.observations
        }
        expected_evidence, expected_observations = expected_support_labels(
            self.expected
        )

        unknown_evidence = sorted(
            label for label in expected_evidence if label not in evidence_labels
        )
        if unknown_evidence:
            raise ValueError(
                "scenario expectations reference unknown evidence labels: "
                + ", ".join(unknown_evidence)
            )
        unknown_observations = sorted(
            label for label in expected_observations if label not in observation_labels
        )
        if unknown_observations:
            raise ValueError(
                "scenario expectations reference unknown observation labels: "
                + ", ".join(unknown_observations)
            )
        return self


class AnalystScenarioResolution(BaseModel):
    """Immutable mapping from fixture labels to exact persisted UUIDs.

    Produced after the fixture is materialized. Evaluator code resolves every
    expectation label through these maps exactly once and compares UUIDs
    afterward; it never queries by fuzzy value or source name.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_ids: Mapping[str, UUID]
    relationship_observation_ids: Mapping[str, UUID]
    entity_ids: Mapping[str, UUID]
    relationship_ids: Mapping[str, UUID]


class AnalystEvaluationFailure(BaseModel):
    """One deterministic behavioral failure with a stable code and message."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: AnalystEvaluationFailureCode
    message: str


class AnalystEvaluationMetrics(BaseModel):
    """Deterministic counts derived from the same comparisons as the failures.

    Every total/satisfied pair is denominator-safe; the derived ratio
    properties return ``1.0`` when the total is zero (no requirement, perfect
    satisfaction) and never emit NaN or divide by zero.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict_acceptable: bool
    confidence_acceptable: bool

    required_findings_total: int = Field(ge=0)
    required_findings_satisfied: int = Field(ge=0)
    required_support_total: int = Field(ge=0)
    required_support_satisfied: int = Field(ge=0)
    forbidden_support_violations: int = Field(ge=0)

    required_contradictions_total: int = Field(ge=0)
    required_contradictions_satisfied: int = Field(ge=0)

    required_limitations_total: int = Field(ge=0)
    required_limitations_satisfied: int = Field(ge=0)
    required_unresolved_questions_total: int = Field(ge=0)
    required_unresolved_questions_satisfied: int = Field(ge=0)
    required_next_steps_total: int = Field(ge=0)
    required_next_steps_satisfied: int = Field(ge=0)

    @model_validator(mode="after")
    def satisfied_bounded(self) -> "AnalystEvaluationMetrics":
        """Reject satisfied counts above their totals."""
        pairs: list[tuple[str, int, int]] = [
            (
                "required findinds",
                self.required_findings_satisfied,
                self.required_findings_total,
            ),
            (
                "required support",
                self.required_support_satisfied,
                self.required_support_total,
            ),
            (
                "required contradictions",
                self.required_contradictions_satisfied,
                self.required_contradictions_total,
            ),
            (
                "required limitations",
                self.required_limitations_satisfied,
                self.required_limitations_total,
            ),
            (
                "required unresolved questions",
                self.required_unresolved_questions_satisfied,
                self.required_unresolved_questions_total,
            ),
            (
                "required next steps",
                self.required_next_steps_satisfied,
                self.required_next_steps_total,
            ),
        ]
        for name, satisfied, total in pairs:
            if satisfied > total:
                raise ValueError(f"{name} satisfied count exceeds its total")
        return self

    @property
    def required_finding_recall(self) -> float:
        """Return required-finding recall; an empty requirement scores 1.0."""
        if self.required_findings_total == 0:
            return 1.0
        return self.required_findings_satisfied / self.required_findings_total

    @property
    def required_support_recall(self) -> float:
        """Return required-support recall; an empty requirement scores 1.0."""
        if self.required_support_total == 0:
            return 1.0
        return self.required_support_satisfied / self.required_support_total

    @property
    def contradiction_coverage(self) -> float:
        """Return contradiction coverage; an empty requirement scores 1.0."""
        if self.required_contradictions_total == 0:
            return 1.0
        return (
            self.required_contradictions_satisfied / self.required_contradictions_total
        )


class AnalystEvaluationResult(BaseModel):
    """The immutable result of one behavioral evaluation.

    ``passed`` is exactly the absence of failures; the model rejects a
    self-contradictory combination.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    scenario_version: int
    passed: bool
    failures: tuple[AnalystEvaluationFailure, ...]
    metrics: AnalystEvaluationMetrics

    @model_validator(mode="after")
    def passed_consistent(self) -> "AnalystEvaluationResult":
        """Require ``passed`` to equal the absence of failures."""
        if self.passed != (not self.failures):
            raise ValueError("passed must equal the absence of failures")
        return self
