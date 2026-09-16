# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence Analyst typed contracts: deterministic analyst input and LLM output.

These are ATI-owned Pydantic contracts only. They carry no repository,
provider, LangChain, LangGraph, or persistence dependency.

``EvidenceAnalystInput`` is the immutable, deterministic, minimized snapshot
the Evidence Analyst receives: persisted Investigation context plus the exact
Evidence and RelationshipObservation identities shown to the model. It is
assembled exclusively from persisted authoritative resources; ``raw_payload``
and other non-analytical content never appears here.

``EvidenceAnalystDecision`` is the semantic output of the LLM call. It carries
verdict, confidence, summary, Findings, and ordered text collections only.
Persistence-owned identifiers (``investigation_id``, ``id``, ``version``,
``created_at``, deletion metadata) are deliberately absent: the application
stamps them when it constructs the authoritative ``Assessment``. The model
cannot manufacture ``analyzed_evidence_ids``; ATI declares the analyzed set
to be exactly the Evidence deliberately supplied in the input.
"""

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
    AnalyticalFinding,
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)
from agentic_threat_investigator.domain.immutable_json import FrozenDict, freeze_mapping
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.domain.relationships import RelationshipType

_MAX_GEOGRAPHIC_FINDING_COLLECTION = 25
"""Hard ceiling of every support collection of one geographic finding.

The structured geographic output is bounded so the model can never return an
unbounded support list; the deterministic validator further requires every
referenced identity to be an exact supplied observation/Evidence pair.
"""

_COUNTRY_CODE_RE = "^[A-Z]{2}$"


def _require_aware_utc(value: datetime, label: str) -> datetime:
    """Require a timezone-aware timestamp and normalize it to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


class AnalystEntity(BaseModel):
    """Minimal entity identity provided for interpretation, never for citation.

    ``entity_id`` is the persisted canonical entity identity; ``entity_type``
    and ``value`` are the canonical identity values. Endpoint entities are
    included only so the analyst can interpret relationships.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    entity_type: EntityType
    value: str


def _empty_facts() -> FrozenDict:
    """Return an empty deeply immutable facts mapping."""
    return freeze_mapping({})


class AnalystEvidenceItem(BaseModel):
    """The minimized, normalized Evidence view shown to the model.

    ``facts`` are the normalized evidence facts: provider-specific scores stay
    normalized facts and analytical confidence belongs to the Assessment.
    ``raw_payload`` and HTTP headers are never included. ``source_url`` is
    omitted for PR 20B: normalized facts and stable source metadata are
    sufficient to reason and cite.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: UUID
    type: EvidenceType
    subject: AnalystEntity
    source: str
    source_record_id: str | None = None
    observed_at: datetime | None = None
    retrieved_at: datetime
    facts: dict[str, Any] = Field(default_factory=_empty_facts)

    @field_validator("facts", mode="after")
    @classmethod
    def freeze_facts(cls, value: dict[str, Any]) -> FrozenDict:
        """Store normalized facts as a deeply immutable JSON object."""
        return freeze_mapping(value)


class AnalystRelationshipObservation(BaseModel):
    """The minimized view of one historical relationship observation.

    The observation identity is the exact identity the model must cite for a
    graph-backed Finding. A bare Relationship is never citable, so the DTO
    always resolves the stable Relationship and its endpoint entities.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    relationship_observation_id: UUID
    evidence_id: UUID
    relationship_id: UUID
    relationship_type: RelationshipType
    source_entity: AnalystEntity
    target_entity: AnalystEntity
    observed_at: datetime | None = None
    retrieved_at: datetime
    source: str
    confidence: float | None = None


# ---------------------------------------------------------------------------
# Model-visible bounded GEOINT context (PR 26F)
# ---------------------------------------------------------------------------
# These frozen ``extra="forbid"`` DTOs are the ONLY geographic view the model
# receives. They are built by the deterministic context policy over PR 26D
# query results; representative coordinates, raw EWKT/WKB geometry, provider
# payloads, global ``EntityLocation`` state, and containment cursor internals
# are deliberately absent. Canonical Location identity and precision are
# sufficient for same-place and temporal reasoning without exposing raw
# coordinates that would create false-proximity temptation.


class AnalystGeointLocation(BaseModel):
    """Bounded canonical Location reference shown to the model (PR 26F).

    Location is canonical reference geography, never a threat Entity.
    Representative coordinates are omitted from model context: canonical
    identity and precision are sufficient for same-place and temporal
    reasoning, while raw coordinates would invite false-proximity
    interpretation. Location display text is data, never instructions.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    location_id: UUID
    location_type: LocationType
    canonical_location_name: str
    country_code: str
    admin1_code: str | None = None
    admin2_code: str | None = None
    parent_location_id: UUID | None = None

    @field_validator("canonical_location_name")
    @classmethod
    def _name_not_blank(cls, value: str) -> str:
        """Reject blank canonical Location names."""
        if not value.strip():
            raise ValueError("geoint canonical_location_name must not be blank")
        return value

    @field_validator("country_code")
    @classmethod
    def _country_code_shape(cls, value: str) -> str:
        """Require the two-letter uppercase ISO-style country-code shape."""
        if len(value) != 2 or not value.isalpha() or value != value.upper():
            raise ValueError("geoint country_code must be two uppercase letters")
        return value

    @field_validator("admin1_code", "admin2_code")
    @classmethod
    def _admin_code_not_blank(cls, value: str | None) -> str | None:
        """Reject blank administrative codes when present."""
        if value is not None and not value.strip():
            raise ValueError("geoint administrative code must not be blank")
        return value


class AnalystGeointObservation(BaseModel):
    """One immutable geographic observation with exact provenance (PR 26F).

    ``observation_id`` is the exact ``EntityLocationObservation`` identity
    and ``evidence_id`` the exact immutable Evidence that produced it; the
    model must cite them as an exact pair. ``observed_at`` is the
    source-semantic observation time when present, ``retrieved_at`` the
    collection time, and ``resolved_at`` the ATI resolution time; a missing
    ``observed_at`` is never replaced with an invented time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: UUID
    entity_id: UUID
    evidence_id: UUID
    location: AnalystGeointLocation
    precision: LocationPrecision
    resolution_method: str
    observed_at: datetime | None = None
    retrieved_at: datetime
    resolved_at: datetime

    @field_validator("observed_at", "retrieved_at", "resolved_at")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized timestamps."""
        if value is None:
            return None
        return _require_aware_utc(value, "geoint observation timestamp")

    @field_validator("resolution_method")
    @classmethod
    def _method_not_blank(cls, value: str) -> str:
        """Reject blank resolution-method identifiers."""
        if not value.strip():
            raise ValueError("geoint resolution_method must not be blank")
        return value


class AnalystEntityGeointContext(BaseModel):
    """One Entity's bounded geographic context within this Investigation (PR 26F).

    ``current_observation`` is the Investigation-relative current observation
    under the exact PR 26A currentness ordering; ``history`` carries the
    bounded observation page newest-first (already deduplicated against the
    current observation). ``has_more_history`` tells the model that the
    history was bounded and older observations exist.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    entity_type: EntityType
    entity_value: str
    current_observation: AnalystGeointObservation | None = None
    history: tuple[AnalystGeointObservation, ...] = ()
    has_more_history: bool = False

    @field_validator("entity_value")
    @classmethod
    def _value_not_blank(cls, value: str) -> str:
        """Reject blank canonical entity values."""
        if not value.strip():
            raise ValueError("geoint entity_value must not be blank")
        return value

    @model_validator(mode="after")
    def _validate_observation_membership(self) -> "AnalystEntityGeointContext":
        """Require every observation to belong to this Entity exactly once."""
        candidates: list[AnalystGeointObservation] = list(self.history)
        if self.current_observation is not None:
            candidates.append(self.current_observation)
        for observation in candidates:
            if observation.entity_id != self.entity_id:
                raise ValueError(
                    "geoint observation entity must match its entity context"
                )
        observation_ids = [item.observation_id for item in candidates]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("geoint entity context must not repeat an observation_id")
        return self


class AnalystGeointTopLocation(BaseModel):
    """One exact observed Location group in the bounded summary (PR 26F)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    location: AnalystGeointLocation
    scoped_entity_count: int

    @field_validator("scoped_entity_count")
    @classmethod
    def _count_not_negative(cls, value: int) -> int:
        """Reject negative scoped entity counts."""
        if value < 0:
            raise ValueError("geoint top-location entity count must not be negative")
        return value


class AnalystGeointPrecisionCounts(BaseModel):
    """Observation counts by the approved precision vocabulary (PR 26F)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    country: int = 0
    administrative_area: int = 0
    city: int = 0

    @field_validator("country", "administrative_area", "city")
    @classmethod
    def _count_not_negative(cls, value: int) -> int:
        """Reject negative precision counts."""
        if value < 0:
            raise ValueError("geoint precision count must not be negative")
        return value


class AnalystGeointSummary(BaseModel):
    """Bounded Investigation geographic summary shown to the model (PR 26F).

    Counts are exact scoped facts, never risk/concentration/attribution
    labels. ``truncated`` is true exactly when more Location groups existed
    beyond the server-owned top-location bound, so the model can distinguish
    "not supplied because bounded" from "does not exist".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_count_with_location: int
    observation_count: int
    location_count: int
    country_count: int
    administrative_area_count: int
    city_count: int
    precision_counts: AnalystGeointPrecisionCounts
    top_locations: tuple[AnalystGeointTopLocation, ...]
    truncated: bool

    @model_validator(mode="after")
    def _validate_counts(self) -> "AnalystGeointSummary":
        """Require the exact per-type and precision counts to be consistent."""
        if (
            self.country_count + self.administrative_area_count + self.city_count
            > self.location_count
        ):
            raise ValueError(
                "geoint summary per-type location counts exceed location_count"
            )
        total_precision = sum(
            (
                self.precision_counts.country,
                self.precision_counts.administrative_area,
                self.precision_counts.city,
            )
        )
        if total_precision != self.observation_count:
            raise ValueError(
                "geoint summary precision counts must equal observation_count"
            )
        if self.entity_count_with_location > self.observation_count:
            raise ValueError(
                "geoint summary entity count must not exceed observation_count"
            )
        return self


class AnalystGeointContext(BaseModel):
    """The complete bounded model-visible GEOINT context (PR 26F).

    The context is an immutable snapshot of exactly the Investigation-scoped
    observations supplied to one Evidence Analyst invocation; every
    observation preserves its exact ``observation_id`` and ``evidence_id``.
    ``contained_observation_ids`` records which supplied observations were
    returned by a boundary-containment selection (``containment_applied``);
    the v0.1 context policy never performs contained expansion, so it is
    normally empty and any claimed containment fails closed during
    validation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: AnalystGeointSummary
    entities: tuple[AnalystEntityGeointContext, ...] = ()
    contained_observation_ids: tuple[UUID, ...] = ()

    @model_validator(mode="after")
    def _validate_context_shape(self) -> "AnalystGeointContext":
        """Require unique Entities and supplied-contained-observation membership."""
        entity_ids = [entity.entity_id for entity in self.entities]
        if len(entity_ids) != len(set(entity_ids)):
            raise ValueError("geoint context entities must not repeat an entity_id")
        supplied: set[UUID] = set()
        for entity in self.entities:
            if entity.current_observation is not None:
                supplied.add(entity.current_observation.observation_id)
            supplied.update(item.observation_id for item in entity.history)
        if not set(self.contained_observation_ids) <= supplied:
            raise ValueError(
                "contained_observation_ids must reference supplied observations"
            )
        return self


# ---------------------------------------------------------------------------
# Structured geographic output (PR 26F)
# ---------------------------------------------------------------------------


class GeographicFindingKind(str, Enum):
    """Approved descriptive geographic finding vocabulary (PR 26F).

    The vocabulary is deliberately descriptive rather than inferential:
    there is no coordinated-activity, common-owner, campaign, targeting,
    attribution, malicious-location, travel, or movement-route kind.
    """

    SHARED_LOCATION = "shared_location"
    LOCATION_HISTORY = "location_history"
    LOCATION_CHANGE_OBSERVED = "location_change_observed"
    GEOGRAPHIC_DISTRIBUTION = "geographic_distribution"
    CONTAINED_LOCATION_CONTEXT = "contained_location_context"


class GeographicTemporalInterpretation(str, Enum):
    """Bounded temporal interpretation of one geographic finding (PR 26F).

    ``location_change_observed`` means only that two supported observations
    for the same Entity identify different canonical Locations at different
    effective observation times; it never means the Entity traveled.
    """

    NONE = "none"
    SAME_OBSERVATION_WINDOW = "same_observation_window"
    DIFFERENT_OBSERVATION_TIMES = "different_observation_times"
    LOCATION_CHANGE_OBSERVED = "location_change_observed"


class GeographicFinding(BaseModel):
    """One structured, validated geographic analytical claim (PR 26F).

    ``observation_ids`` and ``evidence_ids`` are parallel lists: the
    Evidence at each index is the exact Evidence of the observation at the
    same index. Every referenced identity must be one of the exact
    observation/Evidence pairs supplied to this invocation; the
    :class:`~agentic_threat_investigator.app.evidence_analyst.geoint_validation.GeointFindingValidator`
    rejects unknown, substituted, or cross-scope references before
    persistence. ``limitations`` carries bounded honesty statements rather
    than extrapolation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: GeographicFindingKind
    statement: str
    observation_ids: tuple[UUID, ...]
    evidence_ids: tuple[UUID, ...]
    entity_ids: tuple[UUID, ...]
    location_ids: tuple[UUID, ...]
    temporal_interpretation: GeographicTemporalInterpretation = (
        GeographicTemporalInterpretation.NONE
    )
    limitations: tuple[str, ...] = ()

    @field_validator("statement", mode="after")
    @classmethod
    def statement_not_blank(cls, value: str) -> str:
        """Reject blank statements."""
        if not value.strip():
            raise ValueError("geographic finding statement must not be blank")
        return value

    @field_validator(
        "observation_ids", "evidence_ids", "entity_ids", "location_ids", mode="after"
    )
    @classmethod
    def collections_bounded_and_unique(
        cls, value: tuple[UUID, ...], info: ValidationInfo
    ) -> tuple[UUID, ...]:
        """Require non-empty, bounded, duplicate-free support collections."""
        if not value:
            raise ValueError(f"geographic finding {info.field_name} must not be empty")
        if len(value) > _MAX_GEOGRAPHIC_FINDING_COLLECTION:
            raise ValueError(
                f"geographic finding {info.field_name} exceeds the maximum of "
                f"{_MAX_GEOGRAPHIC_FINDING_COLLECTION}"
            )
        if len(value) != len(set(value)):
            raise ValueError(
                f"geographic finding {info.field_name} must not contain duplicates"
            )
        return value

    @field_validator("limitations", mode="after")
    @classmethod
    def no_blank_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject blank limitation entries."""
        if any(not entry.strip() for entry in value):
            raise ValueError("geographic finding limitations must not be blank")
        return value

    @model_validator(mode="after")
    def _validate_parallel_evidence(self) -> "GeographicFinding":
        """Require the observation and Evidence lists to be parallel."""
        if len(self.observation_ids) != len(self.evidence_ids):
            raise ValueError(
                "observation_ids and evidence_ids must be parallel lists with "
                "equal length"
            )
        return self


class EvidenceAnalystInput(BaseModel):
    """The deterministic, bounded context for one analyst execution.

    Ordering is deterministic: ``evidence`` and ``relationship_observations``
    follow the documented repository orders and ``root_entities`` follows the
    Investigation root list. The same persisted investigation state always
    produces the same serialized input.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    objective: str
    root_entities: tuple[AnalystEntity, ...] = ()
    evidence: tuple[AnalystEvidenceItem, ...] = ()
    relationship_observations: tuple[AnalystRelationshipObservation, ...] = ()
    geoint_context: AnalystGeointContext | None = None

    @field_validator("objective", mode="after")
    @classmethod
    def objective_not_blank(cls, value: str) -> str:
        """Reject blank objectives."""
        if not value.strip():
            raise ValueError("investigation objective must not be blank")
        return value


class EvidenceAnalystDecision(BaseModel):
    """The semantic-only analytical output the model returns.

    The model sets verdict, confidence, summary, Findings, limitations,
    unresolved questions, and recommended next steps. The application stamps
    ``investigation_id``, ``analyzed_evidence_ids``, and every
    persistence-owned field when it constructs the authoritative
    :class:`~agentic_threat_investigator.domain.assessment.Assessment`.

    ``disposition`` is the required bounded orchestration decision:
    ``SUFFICIENT`` (the collected evidence supports a confident stop),
    ``NEEDS_MORE_EVIDENCE`` (another bounded collection round is justified),
    or ``EXHAUSTED`` (no further collection is justified). It is a typed
    semantic output, never derived by the application from verdict,
    confidence, findings, or recommendation prose.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Verdict
    confidence: AssessmentConfidence
    summary: str
    disposition: AnalysisDisposition
    findings: tuple[AnalyticalFinding, ...] = ()
    geographic_findings: tuple[GeographicFinding, ...] = ()
    limitations: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    recommended_next_steps: tuple[str, ...] = ()

    @field_validator("summary", mode="after")
    @classmethod
    def summary_not_blank(cls, value: str) -> str:
        """Reject blank summaries."""
        if not value.strip():
            raise ValueError("decision summary must not be blank")
        return value

    @field_validator("limitations", "unresolved_questions", "recommended_next_steps")
    @classmethod
    def no_blank_entries(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject blank or empty-string entries in ordered text collections."""
        if any(not entry.strip() for entry in value):
            raise ValueError("decision text collections must not contain blank entries")
        return value
