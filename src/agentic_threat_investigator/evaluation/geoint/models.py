# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned GEOINT evaluation contracts (PR 26G).

Each :class:`GeointScenario` pairs one deterministic fixture (a compact,
label-based description of the reference geography, Investigation,
Entities, GEOLOCATION Evidence, and pending ``GeoResolution`` work the
scenario is materialized into) with one :class:`ExpectedGeointOutcome`
envelope covering geographic state, resolution outcomes, the delivered
PR 26F tool/context policy, structured agent output, provenance, and
epistemic hard gates.

Expectations use **semantic labels** rather than runtime UUIDs; the
:class:`GeointScenarioResolution` produced at fixture materialization time
maps every label to the exact persisted identity. Evaluation after that is
exact UUID identity.

The scenario contract mirrors the analyst convention (PR 20C): fail-closed
authoring validation, globally unique stable labels, no runtime UUIDs or
model prompt text in scenario files, and envelope semantics. These are
evaluation DTOs only; they extend no runtime model and never claim the
Assessment schema persists geographic observation identities.
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

from agentic_threat_investigator.domain.analyst import (
    EvidenceAnalystDecision,
    GeographicFindingKind,
)
from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)

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

_MAX_GEOGRAPHY_RECORDS = 32
"""Bounded reference-geography records per scenario fixture."""

_MAX_RESOLUTIONS = 16
"""Bounded pending-resolution entries per scenario fixture."""

_MAX_EXPECTED_FINDINGS = 16
"""Bounded expected/forbidden geographic finding entries per scenario."""


def _reject_duplicates(value: object, field: str) -> object:
    """Reject duplicate entries in a JSON list/tuple before set conversion.

    Mirrors the analyst scenario contract: list/tuple inputs are compared
    with deterministic equality-based membership so malformed, unhashable
    members never raise a raw ``TypeError``; already-constructed
    set/frozenset values are returned unchanged.
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


class GeointForbiddenInference(str, Enum):
    """Epistemic hard-gate codes a scenario may forbid (PR 26G).

    The PR 26F runtime already makes these structurally impossible through
    the closed descriptive vocabulary and the independent-support gate; the
    evaluation scenario declares which gates are under test so the evaluator
    independently proves the delivered behavior without an LLM judge.
    """

    COORDINATION = "coordination"
    OWNERSHIP = "ownership"
    CAMPAIGN = "campaign"
    TARGETING = "targeting"
    ATTRIBUTION = "attribution"
    TRAVEL = "travel"
    ROUTE = "route"
    MALICIOUSNESS = "maliciousness"


class GeointToolOperation(str, Enum):
    """The delivered PR 26F tool operations the evaluator can observe.

    ``PROXIMITY`` and ``ARBITRARY_SPATIAL_QUERY`` are deliberate sentinel
    values that never exist in the delivered facade; a trace containing them
    is definitionally a disallowed capability.
    """

    SUMMARY = "summary"
    CURRENT_FOR_ENTITY = "current_for_entity"
    HISTORY_FOR_ENTITY = "history_for_entity"
    ENTITIES_IN_LOCATION = "entities_in_location"
    OBSERVATIONS_IN_LOCATION = "observations_in_location"
    OBSERVATION_DETAIL = "observation_detail"
    PROXIMITY = "proximity"
    ARBITRARY_SPATIAL_QUERY = "arbitrary_spatial_query"


class GeointValidationExpectation(str, Enum):
    """Expected runtime validation outcome for the scripted agent output.

    ``ACCEPTED`` means the deterministic ``GeointFindingValidator`` and
    provenance validation accepted the decision and an Assessment persisted;
    ``REJECTED`` means the candidate was deterministically rejected before
    persistence (no Assessment row).
    """

    ACCEPTED = "accepted"
    REJECTED = "rejected"


class GeointValidationOutcome(str, Enum):
    """Observed runtime validation outcome recorded by the evaluation input."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Fixture contracts
# ---------------------------------------------------------------------------


class GeointFixtureLocation(BaseModel):
    """One canonical reference-geography record the fixture materializes.

    ``parent`` is the semantic label of the parent record (countries have
    none). Geometry/centroid are EWKT strings exactly like the production
    reference contract; NULL geometry is represented by omission.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    location_type: LocationType
    name: str
    country_code: str
    admin1_code: str | None = None
    admin2_code: str | None = None
    parent: str | None = None
    geometry: str | None = None
    centroid: str | None = None

    @field_validator("label", mode="after")
    @classmethod
    def label_stable(cls, value: str) -> str:
        """Require a stable semantic label."""
        return _require_semantic_label(value, "label")

    @field_validator("name", mode="after")
    @classmethod
    def name_not_blank(cls, value: str) -> str:
        """Reject blank geographic names."""
        if not value.strip():
            raise ValueError("geography name must not be blank")
        return value


class GeointFixtureEntity(BaseModel):
    """One canonical Entity the fixture materializes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    type: EntityType
    value: str

    @field_validator("label", mode="after")
    @classmethod
    def label_stable(cls, value: str) -> str:
        """Require a stable semantic label."""
        return _require_semantic_label(value, "label")


class GeointFixtureEvidence(BaseModel):
    """One immutable GEOLOCATION Evidence observation the fixture materializes.

    ``facts`` mirrors the persisted GEOLOCATION fact vocabulary consumed by
    the PR 26C claim extraction (``country_code``, ``region``,
    ``administrative_area``, ``administrative_area_code``, ``city``,
    ``latitude``, ``longitude``, ``precision``). ``other_investigation``
    attaches the row to the scenario's deterministic second Investigation
    (isolation scenarios): the row is real geographic truth the scenario
    Investigation must never see. The default Evidence type is
    ``GEOLOCATION``; independent-support scenarios add a non-geographic row
    that never participates in resolution.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    subject: str
    source: str
    type: EvidenceType = EvidenceType.GEOLOCATION
    facts: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime | None = None
    retrieved_at: datetime | None = None
    other_investigation: bool = False

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


class GeointFixtureResolution(BaseModel):
    """One pending GeoResolution work item the fixture materializes.

    The resolution label is also the observation label for resolved
    outcomes; unresolved outcomes simply produce no observation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    entity: str
    evidence: str

    @field_validator("label", "entity", "evidence", mode="after")
    @classmethod
    def labels_stable(cls, value: str, info: ValidationInfo) -> str:
        """Require stable semantic labels."""
        return _require_semantic_label(value, info.field_name or "label")


class GeointFixture(BaseModel):
    """A deterministic, label-based description of one persisted GEOINT world.

    The fixture is data only: no executable callbacks, no model prompt text,
    no secrets. At materialization time each label becomes an exact persisted
    UUID inside a :class:`GeointScenarioResolution`. Reference geography is
    materialized through the normal reference write API; geographic truth
    (``EntityLocationObservation``/``EntityLocation``) is only ever created
    by the production GeoResolution worker completion -- never by direct
    derived-row inserts.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    objective: str
    root_entity: str
    geography: tuple[GeointFixtureLocation, ...]
    entities: tuple[GeointFixtureEntity, ...]
    evidence: tuple[GeointFixtureEvidence, ...]
    resolutions: tuple[GeointFixtureResolution, ...]

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
    def labels_unique_and_resolvable(self) -> "GeointFixture":
        """Require globally unique labels and valid cross-references."""
        if not self.entities:
            raise ValueError("a fixture must declare at least one entity")
        if not self.geography:
            raise ValueError("a fixture must declare at least one reference location")
        geography_labels = {item.label for item in self.geography}
        entity_labels = {entity.label for entity in self.entities}
        evidence_labels = {evidence.label for evidence in self.evidence}
        resolution_labels = {resolution.label for resolution in self.resolutions}
        all_labels = (
            geography_labels | entity_labels | evidence_labels | resolution_labels
        )
        total_count = (
            len(self.geography)
            + len(self.entities)
            + len(self.evidence)
            + len(self.resolutions)
        )
        if len(all_labels) != total_count:
            raise ValueError(
                "fixture labels must be unique across geography, entities, "
                "evidence, and resolutions"
            )
        if self.root_entity not in entity_labels:
            raise ValueError("fixture root_entity must reference a declared entity")
        if len(self.geography) > _MAX_GEOGRAPHY_RECORDS:  # pragma: no cover
            raise ValueError(
                f"fixture geography is bounded to {_MAX_GEOGRAPHY_RECORDS} records"
            )
        if len(self.resolutions) > _MAX_RESOLUTIONS:  # pragma: no cover
            raise ValueError(f"fixture resolutions are bounded to {_MAX_RESOLUTIONS}")
        for location in self.geography:
            if location.parent is not None and location.parent not in geography_labels:
                raise ValueError(
                    f"fixture location {location.label!r} references an "
                    "unknown parent location"
                )
        for evidence in self.evidence:
            if evidence.subject not in entity_labels:
                raise ValueError(
                    f"fixture evidence {evidence.label!r} references an "
                    "unknown subject entity"
                )
        for resolution in self.resolutions:
            if resolution.entity not in entity_labels:
                raise ValueError(
                    f"fixture resolution {resolution.label!r} references an "
                    "unknown entity"
                )
            if resolution.evidence not in evidence_labels:
                raise ValueError(
                    f"fixture resolution {resolution.label!r} references an "
                    "unknown evidence row"
                )
        return self


# ---------------------------------------------------------------------------
# Expected envelopes
# ---------------------------------------------------------------------------


class ExpectedResolutionOutcome(BaseModel):
    """Expected terminal outcome of one fixture resolution.

    ``status`` is ``resolved`` (a canonical observation exists) or
    ``unresolvable`` (terminal with no observation, including the PR 26C
    v0.1 policy that canonical AMBIGUOUS is terminal UNRESOLVABLE and never
    guessed). ``location``/``precision`` are required exactly when resolved.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    status: str
    location: str | None = None
    precision: LocationPrecision | None = None

    @field_validator("label", "location", mode="after")
    @classmethod
    def labels_stable(cls, value: str | None, info: ValidationInfo) -> str | None:
        """Require stable semantic labels when present."""
        if value is None:
            return None
        return _require_semantic_label(value, info.field_name or "label")

    @model_validator(mode="after")
    def status_shape(self) -> "ExpectedResolutionOutcome":
        """Require the resolved/unresolvable shape to be self-consistent."""
        if self.status not in ("resolved", "unresolvable"):
            raise ValueError("expected resolution status must be resolved/unresolvable")
        if self.status == "resolved":
            if self.location is None or self.precision is None:
                raise ValueError(
                    "a resolved expectation requires a location and a precision"
                )
        else:
            if self.location is not None or self.precision is not None:
                raise ValueError(
                    "an unresolvable expectation must not carry a location or precision"
                )
        return self


class ExpectedCurrentState(BaseModel):
    """Expected Investigation-relative current EntityLocation of one Entity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity: str
    location: str
    precision: LocationPrecision

    @field_validator("entity", "location", mode="after")
    @classmethod
    def labels_stable(cls, value: str, info: ValidationInfo) -> str:
        """Require stable semantic labels."""
        return _require_semantic_label(value, info.field_name or "label")


class ExpectedHistory(BaseModel):
    """Expected Investigation-relative observation history of one Entity.

    ``locations`` is ordered **newest-first** (the documented PR 26D
    effective-time ordering); a single-observation history is a
    one-element tuple.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity: str
    locations: tuple[str, ...]

    @field_validator("entity", "locations", mode="after")
    @classmethod
    def labels_stable(cls, value: object, info: ValidationInfo) -> object:
        """Require stable semantic labels."""
        if isinstance(value, str):
            return _require_semantic_label(value, info.field_name or "label")
        if isinstance(value, (list, tuple)):
            for entry in value:
                _require_semantic_label(entry, info.field_name or "label")
        return value


class ExpectedGeographicFinding(BaseModel):
    """A structured expectation one geographic finding may satisfy.

    Support labels resolve to exact UUIDs; the finding must carry every
    required observation/evidence/entity/location label and cite no
    forbidden label. Kind and temporal interpretation match where
    constrained. Statement prose is never inspected.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: GeographicFindingKind | None = None
    observation_labels: frozenset[str] = frozenset()
    evidence_labels: frozenset[str] = frozenset()
    entity_labels: frozenset[str] = frozenset()
    location_labels: frozenset[str] = frozenset()
    forbidden_observation_labels: frozenset[str] = frozenset()

    @field_validator(
        "observation_labels",
        "evidence_labels",
        "entity_labels",
        "location_labels",
        "forbidden_observation_labels",
        mode="before",
    )
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before frozenset conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @model_validator(mode="after")
    def labels_stable(self) -> "ExpectedGeographicFinding":
        """Require every support label to be a stable semantic label."""
        for field in (
            "observation_labels",
            "evidence_labels",
            "entity_labels",
            "location_labels",
            "forbidden_observation_labels",
        ):
            for label in getattr(self, field):
                _require_semantic_label(label, field)
        return self

    @model_validator(mode="after")
    def requires_constraint(self) -> "ExpectedGeographicFinding":
        """Reject an expectation that constrains nothing at all."""
        if (
            self.kind is None
            and not self.observation_labels
            and not self.evidence_labels
            and not self.entity_labels
            and not self.location_labels
            and not self.forbidden_observation_labels
        ):
            raise ValueError(
                "an expected geographic finding must constrain kind or support"
            )
        return self


class ForbiddenGeographicFinding(BaseModel):
    """An explicit negative expectation for a known geographic regression.

    A persisted geographic finding matches when its kind matches (where
    constrained) and, when support is declared, it cites at least one of the
    declared observation labels.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: GeographicFindingKind | None = None
    observation_labels: frozenset[str] = frozenset()

    @field_validator("observation_labels", mode="before")
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before frozenset conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @model_validator(mode="after")
    def labels_stable(self) -> "ForbiddenGeographicFinding":
        """Require every observation label to be a stable semantic label."""
        for label in self.observation_labels:
            _require_semantic_label(label, "observation_labels")
        return self

    @model_validator(mode="after")
    def requires_constraint(self) -> "ForbiddenGeographicFinding":
        """Reject a pattern that would forbid every possible finding."""
        if self.kind is None and not self.observation_labels:
            raise ValueError(
                "a forbidden geographic finding must constrain kind or support"
            )
        return self


class ExpectedAgentContext(BaseModel):
    """Expected delivered PR 26F tool/context policy behavior.

    The envelope mirrors the configured aggregate bounds; the evaluator
    proves the observed tool trace and the model-visible context stay inside
    it and that the disallowed capabilities (proximity, arbitrary spatial
    queries, cursor draining, Location fan-out, automatic containment
    expansion) never appear.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_entities: int = Field(default=10, ge=1)
    max_observations_per_entity: int = Field(default=5, ge=1)
    max_total_observations: int = Field(default=50, ge=1)
    max_context_bytes: int = Field(default=262_144, ge=1)
    allowed_operations: frozenset[GeointToolOperation] = frozenset(
        {
            GeointToolOperation.SUMMARY,
            GeointToolOperation.CURRENT_FOR_ENTITY,
            GeointToolOperation.HISTORY_FOR_ENTITY,
        }
    )
    expect_no_proximity: bool = True
    expect_no_containment_expansion: bool = True
    expect_no_cursor_drain: bool = True
    expect_no_location_fanout: bool = True

    @field_validator("allowed_operations", mode="before")
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before frozenset conversion."""
        return _reject_duplicates(value, info.field_name or "field")


class ExpectedAgentOutput(BaseModel):
    """Expected structured agent output and validation outcome.

    ``expected_validation`` declares whether the scripted FakeLlmClient
    decision must be accepted by the deterministic runtime validator (an
    Assessment persists) or rejected (no Assessment row). Verdicts are an
    allowed envelope; geographic findings are matched structurally.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_validation: GeointValidationExpectation
    allowed_verdicts: frozenset[Verdict]
    allowed_confidence: frozenset[AssessmentConfidence] = frozenset()
    required_geographic_findings: tuple[ExpectedGeographicFinding, ...] = ()
    forbidden_geographic_findings: tuple[ForbiddenGeographicFinding, ...] = ()
    require_independent_support: bool = False

    @field_validator(
        "allowed_verdicts",
        "allowed_confidence",
        mode="before",
    )
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before frozenset conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @model_validator(mode="after")
    def envelopes_nonempty(self) -> "ExpectedAgentOutput":
        """Require a non-empty verdict envelope."""
        if not self.allowed_verdicts:
            raise ValueError("allowed_verdicts must not be empty")
        return self

    @model_validator(mode="after")
    def findings_unique(self) -> "ExpectedAgentOutput":
        """Reject duplicate expectation fixtures (identical value equality)."""
        if len(set(self.required_geographic_findings)) != len(
            self.required_geographic_findings
        ):
            raise ValueError("required geographic findings must be unique")
        if len(set(self.forbidden_geographic_findings)) != len(
            self.forbidden_geographic_findings
        ):
            raise ValueError("forbidden geographic findings must be unique")
        return self


class ExpectedGeointOutcome(BaseModel):
    """The acceptable evaluation envelope for one materialized scenario.

    Coverage is intentionally per-dimension: every declared resolution
    outcome, current state, and history must match exactly, the delivered
    tool/context policy must hold, the structured agent output must satisfy
    the declared envelope, and declared epistemic hard gates must never be
    crossed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    resolutions: tuple[ExpectedResolutionOutcome, ...]
    current: tuple[ExpectedCurrentState, ...] = ()
    histories: tuple[ExpectedHistory, ...] = ()
    agent_context: ExpectedAgentContext = ExpectedAgentContext()
    agent_output: ExpectedAgentOutput
    forbidden_inferences: frozenset[GeointForbiddenInference] = frozenset()

    @field_validator("forbidden_inferences", mode="before")
    @classmethod
    def reject_duplicates(cls, value: object, info: ValidationInfo) -> object:
        """Reject duplicate raw entries before frozenset conversion."""
        return _reject_duplicates(value, info.field_name or "field")

    @model_validator(mode="after")
    def resolution_labels_unique(self) -> "ExpectedGeointOutcome":
        """Require every expected resolution label to be unique and present."""
        labels = [item.label for item in self.resolutions]
        if len(set(labels)) != len(labels):
            raise ValueError("expected resolution labels must be unique")
        if not labels:
            raise ValueError("expected resolutions must not be empty")
        return self


class GeointScenario(BaseModel):
    """One repository-owned GEOINT evaluation scenario.

    The scenario carries a stable identifier, a positive version, a bounded
    tag set, one deterministic fixture, and one expected-outcome contract.
    It never contains executable callbacks, model/prompt text, or secrets.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: int = Field(ge=1)
    description: str
    tags: frozenset[str] = frozenset()
    fixture: GeointFixture
    expected: ExpectedGeointOutcome

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
    def tags_bounded(self) -> "GeointScenario":
        """Require nonblank tags within a bounded count."""
        if (
            len(self.tags) > _MAX_SCENARIO_TAGS
        ):  # pragma: no cover - before-validator guards raw input
            raise ValueError(f"scenario tags are bounded to {_MAX_SCENARIO_TAGS}")
        if any(not tag.strip() for tag in self.tags):
            raise ValueError("scenario tags must not be blank")
        return self

    @model_validator(mode="after")
    def expected_labels_resolve(self) -> "GeointScenario":
        """Require every expected support label to exist in the fixture.

        Human-authored expectations use stable semantic labels; a label that
        does not name a fixture geography/entity/evidence/resolution can
        never resolve to a persisted UUID and is rejected at load time.
        """
        geography_labels = {item.label for item in self.fixture.geography}
        entity_labels = {item.label for item in self.fixture.entities}
        evidence_labels = {item.label for item in self.fixture.evidence}
        resolution_labels = {item.label for item in self.fixture.resolutions}

        for outcome in self.expected.resolutions:
            if outcome.label not in resolution_labels:
                raise ValueError(
                    f"expected resolution {outcome.label!r} does not name a "
                    "fixture resolution"
                )
            if (
                outcome.location is not None
                and outcome.location not in geography_labels
            ):
                raise ValueError(
                    f"expected resolution {outcome.label!r} references an "
                    f"unknown geography label {outcome.location!r}"
                )
        for current in self.expected.current:
            if current.entity not in entity_labels:
                raise ValueError(
                    f"expected current state references an unknown entity "
                    f"{current.entity!r}"
                )
            if current.location not in geography_labels:
                raise ValueError(
                    f"expected current state references an unknown geography "
                    f"label {current.location!r}"
                )
        for history in self.expected.histories:
            if history.entity not in entity_labels:
                raise ValueError(
                    f"expected history references an unknown entity {history.entity!r}"
                )
            for label in history.locations:
                if label not in geography_labels:
                    raise ValueError(
                        f"expected history references an unknown geography "
                        f"label {label!r}"
                    )

        output = self.expected.agent_output
        unknown_observations = sorted(
            label
            for expected_finding in output.required_geographic_findings
            for label in expected_finding.observation_labels
            if label not in resolution_labels
        )
        if unknown_observations:
            raise ValueError(
                "expected geographic findings reference unknown resolution "
                "labels: " + ", ".join(unknown_observations)
            )
        for expected_finding in output.required_geographic_findings:
            for label in expected_finding.evidence_labels:
                if label not in evidence_labels:
                    raise ValueError(
                        f"expected geographic finding references unknown "
                        f"evidence label {label!r}"
                    )
            for label in expected_finding.entity_labels:
                if label not in entity_labels:
                    raise ValueError(
                        f"expected geographic finding references unknown "
                        f"entity label {label!r}"
                    )
            for label in expected_finding.location_labels:
                if label not in geography_labels:
                    raise ValueError(
                        f"expected geographic finding references unknown "
                        f"geography label {label!r}"
                    )
        for forbidden_finding in output.forbidden_geographic_findings:
            for label in forbidden_finding.observation_labels:
                if label not in resolution_labels:
                    raise ValueError(
                        f"forbidden geographic finding references unknown "
                        f"resolution label {label!r}"
                    )
        return self


class GeointScenarioResolution(BaseModel):
    """Immutable mapping from fixture labels to exact persisted UUIDs.

    Produced after the fixture is materialized and, for resolved outcomes,
    after the production GeoResolution worker completed the pending work.
    Evaluator code resolves every expectation label through these maps
    exactly once and compares UUIDs afterward.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    geography_ids: Mapping[str, UUID]
    entity_ids: Mapping[str, UUID]
    evidence_ids: Mapping[str, UUID]
    resolution_ids: Mapping[str, UUID]
    observation_ids: Mapping[str, UUID] = {}
    other_investigation_id: UUID | None = None


# ---------------------------------------------------------------------------
# Evaluator inputs (persisted/evaluation state, never raw model output)
# ---------------------------------------------------------------------------


class PersistedGeointObservation(BaseModel):
    """One immutable persisted geographic observation snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: UUID
    entity_id: UUID
    location_id: UUID
    evidence_observation_id: UUID
    precision: LocationPrecision
    observed_at: datetime | None = None
    retrieved_at: datetime


class GeointCurrentState(BaseModel):
    """One persisted current EntityLocation snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    location_id: UUID
    precision: LocationPrecision
    latest_observation_id: UUID


class GeointResolutionState(BaseModel):
    """Observed terminal state of one fixture resolution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    status: str
    observation_id: UUID | None = None
    location_id: UUID | None = None
    precision: LocationPrecision | None = None


class GeointGeographicState(BaseModel):
    """The authoritative persisted geographic state of one evaluation.

    Built only from repository read-backs after the production worker
    completed; the evaluator never reads a database itself.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    observations: tuple[PersistedGeointObservation, ...]
    current: tuple[GeointCurrentState, ...] = ()
    resolutions: tuple[GeointResolutionState, ...] = ()


class GeointToolOperationRecord(BaseModel):
    """One evaluation-recorded tool operation (PR 26G evaluation seam)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: GeointToolOperation
    investigation_id: UUID
    entity_id: UUID | None = None
    location_id: UUID | None = None
    observation_id: UUID | None = None
    limit: int | None = None
    include_contained: bool | None = None
    cursor_requested: bool = False
    has_more: bool | None = None


class GeointAgentEvaluationInput(BaseModel):
    """The structured agent output and its runtime fate for one evaluation.

    ``decision`` is the scripted FakeLlmClient decision; ``validation`` is
    the deterministic runtime validator outcome; ``assessment`` is the
    persisted Assessment when validation accepted (None otherwise). This
    input never carries raw model prose beyond the typed decision fields.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: EvidenceAnalystDecision | None = None
    validation: GeointValidationOutcome
    assessment: Assessment | None = None


# ---------------------------------------------------------------------------
# Failure codes, metrics, result
# ---------------------------------------------------------------------------


class GeointEvaluationFailureCode(str, Enum):
    """Stable machine-readable GEOINT evaluation failure categories.

    Emission order is fixed (see :class:`GeointDeterministicEvaluator`);
    failures never depend on set/hash iteration.
    """

    WRONG_RESOLUTION_STATUS = "wrong_resolution_status"
    MISSING_EXPECTED_OBSERVATION = "missing_expected_observation"
    WRONG_CANONICAL_LOCATION = "wrong_canonical_location"
    PRECISION_INFLATION = "precision_inflation"
    WRONG_CURRENT_STATE = "wrong_current_state"
    WRONG_HISTORY_ORDER = "wrong_history_order"
    DUPLICATE_GEOGRAPHIC_TRUTH = "duplicate_geographic_truth"
    OBSERVATION_EVIDENCE_MISMATCH = "observation_evidence_mismatch"
    WRONG_INVESTIGATION_PROVENANCE = "wrong_investigation_provenance"
    UNKNOWN_OBSERVATION_CITED = "unknown_observation_cited"
    SUBSTITUTED_EVIDENCE = "substituted_evidence"
    CROSS_INVESTIGATION_LEAK = "cross_investigation_leak"
    REFERENCE_LOCATION_ONLY_SUPPORT = "reference_location_only_support"
    DISALLOWED_TOOL_OPERATION = "disallowed_tool_operation"
    TOOL_BOUND_EXCEEDED = "tool_bound_exceeded"
    CURSOR_DRAINING = "cursor_draining"
    UNRELATED_ENTITY_FANOUT = "unrelated_entity_fanout"
    OMITTED_CONTEXT_OBSERVATION_CITED = "omitted_context_observation_cited"
    TRUNCATION_NOT_SURFACED = "truncation_not_surfaced"
    CONTEXT_EXPOSES_COORDINATES = "context_exposes_coordinates"
    UNSUPPORTED_FINDING_KIND = "unsupported_finding_kind"
    WRONG_FINDING_ENTITY_SUPPORT = "wrong_finding_entity_support"
    WRONG_FINDING_LOCATION_SUPPORT = "wrong_finding_location_support"
    UNSUPPORTED_CONTAINMENT = "unsupported_containment"
    INVALID_LOCATION_CHANGE = "invalid_location_change"
    MISSING_REQUIRED_GEOGRAPHIC_FINDING = "missing_required_geographic_finding"
    FORBIDDEN_GEOGRAPHIC_FINDING = "forbidden_geographic_finding"
    UNEXPECTED_VALIDATION_OUTCOME = "unexpected_validation_outcome"
    GEOGRAPHY_ONLY_VERDICT = "geography_only_verdict"
    GEOGRAPHIC_EVIDENCE_MISUSED = "geographic_evidence_misused"
    UNSUPPORTED_MATERIAL_FINDING = "unsupported_material_finding"
    FORBIDDEN_INFERENCE_EXPRESSED = "forbidden_inference_expressed"


class GeointEvaluationFailure(BaseModel):
    """One deterministic evaluation failure with a stable code and message."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: GeointEvaluationFailureCode
    message: str


class GeointEvaluationMetrics(BaseModel):
    """Deterministic metrics derived from the same comparisons as failures.

    ``provenance_closure_rate`` is denominator-safe: with zero geographic
    claims it is 1.0 (nothing to close) and never emits NaN.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    geographic_claim_count: int = Field(ge=0)
    supported_geographic_claim_count: int = Field(ge=0)
    unsupported_geographic_claim_count: int = Field(ge=0)
    tool_call_count: int = Field(ge=0)
    geoint_context_entity_count: int = Field(ge=0)
    geoint_context_observation_count: int = Field(ge=0)
    observation_count: int = Field(ge=0)
    resolution_count: int = Field(ge=0)

    @property
    def provenance_closure_rate(self) -> float:
        """Return the fraction of geographic claims with exact provenance."""
        if self.geographic_claim_count == 0:
            return 1.0
        return self.supported_geographic_claim_count / self.geographic_claim_count


class GeointEvaluationResult(BaseModel):
    """The immutable result of one GEOINT evaluation.

    ``passed`` is exactly the absence of failures; the model rejects a
    self-contradictory combination.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    scenario_version: int
    passed: bool
    failures: tuple[GeointEvaluationFailure, ...]
    metrics: GeointEvaluationMetrics

    @model_validator(mode="after")
    def passed_consistent(self) -> "GeointEvaluationResult":
        """Require ``passed`` to equal the absence of failures."""
        if self.passed != (not self.failures):
            raise ValueError("passed must equal the absence of failures")
        return self


def expected_support_labels(expected: ExpectedGeointOutcome) -> frozenset[str]:
    """Return every resolution label the agent-output expectations reference."""
    labels: set[str] = set()
    for expected_finding in expected.agent_output.required_geographic_findings:
        labels.update(expected_finding.observation_labels)
        labels.update(expected_finding.forbidden_observation_labels)
    for forbidden_finding in expected.agent_output.forbidden_geographic_findings:
        labels.update(forbidden_finding.observation_labels)
    return frozenset(labels)
