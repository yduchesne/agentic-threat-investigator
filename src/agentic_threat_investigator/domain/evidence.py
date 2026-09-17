# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Stable global Evidence, immutable observations, and pure transition semantics (PR 28A).

``Evidence`` is a stable global source-intelligence identity: it is not owned
by an Investigation, has no single subject, and carries no mutable facts,
timestamps, raw payloads, or retrieval metadata. Stable identity is derived
deterministically from the semantic-format/source namespace plus an approved
stable upstream source-record identity — never from retrieval time,
Investigation, Entity, message, or broker position.

``EvidenceObservation`` is the immutable provenance-bearing state of one
Evidence item: versions are monotonically increasing per Evidence,
``(evidence_id, version)`` is unique, and version 1 is the first material
state. A later retrieval whose material state is unchanged creates no new
observation; a material change appends the next version with a deterministic
diff from the immediately prior material state. Operational acquisition
metadata (``retrieved_at``, datasource execution identity, acquisition
attempt) is never material.

Converters produce ``EvidenceObservationCandidate`` values — pre-persistence
material states with no persisted observation ID/version/diff — wrapped in
``ConvertedEvidence``. Authoritative version allocation belongs to
persistence (PR 28B); pure code never computes ``latest.version + 1``.

The pure helpers in this module implement the approved observation
transition contract:

- ``EvidenceMaterialState``: the explicit material subset of an observation.
- ``EvidenceTransition`` + ``decide_evidence_transition``: the create /
  unchanged / append decision truth table (fail closed on impossible
  combinations).
- ``material_state_diff``: the canonical shallow top-level ``{old, new}``
  diff contract that PR 28B SQL must match (mirrors ``ati.ati_jsonb_diff``)
  — absent and JSON null remain distinct, first observation diff is ``None``.

``EvidenceObservationEntity`` records which canonical Entities are
materially represented in the exact observation (no role, confidence, or
duplicate timestamps). ``InvestigationEvidence`` admits **exact immutable
observations** into an Investigation with bounded mechanism/actor
vocabularies; a newer global observation never silently alters an
Investigation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.immutable_json import (
    FrozenDict,
    freeze_mapping,
)

_ATI_ROOT_NAMESPACE = UUID("00000000-0000-0000-0000-0000000000ca")
"""Stable ATI-owned UUIDv5 root namespace (shared with evaluation fixtures)."""

_EVIDENCE_IDENTITY_NAMESPACE = uuid5(
    _ATI_ROOT_NAMESPACE, "ATI stable global Evidence identity"
)
"""ATI-owned namespace for deterministic Evidence identity (PR 28A).

Derived once from the stable ATI root namespace; the value is a durable
contract and must never change after first release.
"""


class EvidenceType(str, Enum):
    """Stable ATI evidence type URNs."""

    DNS = "urn:ati:evidence:dns"
    REGISTRATION = "urn:ati:evidence:registration"
    NETWORK = "urn:ati:evidence:network"
    GEOLOCATION = "urn:ati:evidence:geolocation"
    REPUTATION = "urn:ati:evidence:reputation"
    THREAT_INTELLIGENCE = "urn:ati:evidence:threat_intelligence"
    VULNERABILITY = "urn:ati:evidence:vulnerability"
    THREAT_RESEARCH = "urn:ati:evidence:threat_research"


def evidence_id_for_source_record(
    semantic_format: SemanticFormatId,
    source: SourceId,
    source_record_id: str,
) -> UUID:
    """Derive the deterministic stable Evidence identity of one source record.

    The identity is a UUIDv5 over the ATI-owned Evidence namespace and the
    exact triple ``(semantic format URN, source URN, upstream source-record
    identity)``. The upstream record identity is used verbatim; it is never
    normalized unless a semantic format's approved contract explicitly
    requires it. Retrieval time, Investigation/Entity identity, datasource
    execution identity, and broker position never participate. The same
    record converted under the same semantic format and source always yields
    the same Evidence ID; a different record, semantic format, or source
    yields a different ID.
    """
    name = f"{semantic_format.value}|{source.value}|{source_record_id}"
    return uuid5(_EVIDENCE_IDENTITY_NAMESPACE, name)


class Evidence(BaseModel):
    """A stable global source-intelligence identity (PR 28A).

    Immutable and Investigation-independent: no subject, no retrieval state,
    no mutable facts, no raw payload, no source URL. Identity is the
    required deterministic ID plus the exact approved stable source-record
    identity; a semantic format without such identity must fail closed
    before conversion rather than making the identity optional.
    """

    model_config = ConfigDict(frozen=True)

    id: UUID
    type: EvidenceType
    source: str
    source_record_id: str


def _validate_utc(value: datetime | None) -> datetime | None:
    """Require timezone-aware timestamps, normalized to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("evidence timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _freeze_json_object(value: dict[str, Any] | None) -> FrozenDict | None:
    """Return a deeply immutable JSON object snapshot, or ``None``."""
    return None if value is None else freeze_mapping(value)


class EvidenceObservation(BaseModel):
    """One immutable provenance-bearing state of a global Evidence (PR 28A).

    ``version`` is the ordered revision within one Evidence and is always
    ``>= 1``; version 1 is the first material state. ``retrieved_at`` is
    acquisition provenance only — it is never material state. ``diff`` is the
    canonical material diff from the immediately prior observation (``None``
    for the first observation); it is never fabricated by converters.
    """

    model_config = ConfigDict(frozen=True)

    id: UUID
    evidence_id: UUID
    version: int
    source_url: str | None = None
    observed_at: datetime | None = None
    retrieved_at: datetime
    facts: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] | None = None
    diff: dict[str, Any] | None = None

    @field_validator("version")
    @classmethod
    def _version_at_least_one(cls, value: int) -> int:
        """Reject versions below 1."""
        if value < 1:
            raise ValueError("evidence observation version must be >= 1")
        return value

    @field_validator("observed_at", "retrieved_at")
    @classmethod
    def _utc_timestamps(cls, value: datetime | None) -> datetime | None:
        """Normalize aware timestamps to UTC; reject naive timestamps."""
        return _validate_utc(value)

    @field_validator("facts", mode="after")
    @classmethod
    def _freeze_facts(cls, value: dict[str, Any]) -> FrozenDict:
        """Store normalized facts as a deeply immutable JSON object."""
        return freeze_mapping(value)

    @field_validator("raw_payload", "diff", mode="after")
    @classmethod
    def _freeze_payload(cls, value: dict[str, Any] | None) -> FrozenDict | None:
        """Store raw payload and diff as deeply immutable JSON objects."""
        return _freeze_json_object(value)


class EvidenceObservationCandidate(BaseModel):
    """Pre-persistence material state of one EvidenceObservation (PR 28A).

    Produced by pure converters, which can never know the authoritative
    database version: the candidate carries no persisted observation ID, no
    version, and no diff. The same field validators (UTC normalization and
    deep JSON immutability) apply so the candidate is directly comparable to
    persisted observations.
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: UUID
    source_url: str | None = None
    observed_at: datetime | None = None
    retrieved_at: datetime
    facts: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] | None = None

    @field_validator("observed_at", "retrieved_at")
    @classmethod
    def _utc_timestamps(cls, value: datetime | None) -> datetime | None:
        """Normalize aware timestamps to UTC; reject naive timestamps."""
        return _validate_utc(value)

    @field_validator("facts", mode="after")
    @classmethod
    def _freeze_facts(cls, value: dict[str, Any]) -> FrozenDict:
        """Store normalized facts as a deeply immutable JSON object."""
        return freeze_mapping(value)

    @field_validator("raw_payload", mode="after")
    @classmethod
    def _freeze_payload(cls, value: dict[str, Any] | None) -> FrozenDict | None:
        """Store raw payload as a deeply immutable JSON object."""
        return _freeze_json_object(value)


class ConvertedEvidence(BaseModel):
    """One cohesive converter output: global Evidence plus its observation candidate.

    A pure converter never fabricates a persisted observation identity,
    version, or diff; it emits exactly the stable ``Evidence`` and the
    ``EvidenceObservationCandidate`` carrying the material state.
    """

    model_config = ConfigDict(frozen=True)

    evidence: Evidence
    observation: EvidenceObservationCandidate


class EvidenceMaterialState(BaseModel):
    """The explicit material subset of one EvidenceObservation.

    Material fields are exactly ``observed_at``, ``source_url``, normalized
    ``facts``, and normalized ``raw_payload``. Excluded as operational-only:
    IDs, version, ``retrieved_at``, datasource-execution/acquisition
    metadata, future message/broker metadata, and diff. Equality of two
    states is structural (deep immutable JSON values), so a later retrieval
    with only a new ``retrieved_at`` compares equal.
    """

    model_config = ConfigDict(frozen=True)

    observed_at: datetime | None = None
    source_url: str | None = None
    facts: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] | None = None

    @field_validator("observed_at")
    @classmethod
    def _utc_observed_at(cls, value: datetime | None) -> datetime | None:
        """Normalize aware timestamps to UTC; reject naive timestamps."""
        return _validate_utc(value)

    @field_validator("facts", mode="after")
    @classmethod
    def _freeze_facts(cls, value: dict[str, Any]) -> FrozenDict:
        """Store normalized facts as a deeply immutable JSON object."""
        return freeze_mapping(value)

    @field_validator("raw_payload", mode="after")
    @classmethod
    def _freeze_payload(cls, value: dict[str, Any] | None) -> FrozenDict | None:
        """Store raw payload as a deeply immutable JSON object."""
        return _freeze_json_object(value)

    @classmethod
    def from_candidate(
        cls, candidate: EvidenceObservationCandidate
    ) -> "EvidenceMaterialState":
        """Return the material state of one observation candidate."""
        return cls(
            observed_at=candidate.observed_at,
            source_url=candidate.source_url,
            facts=candidate.facts,
            raw_payload=candidate.raw_payload,
        )

    @classmethod
    def from_observation(
        cls, observation: EvidenceObservation
    ) -> "EvidenceMaterialState":
        """Return the material state of one persisted observation."""
        return cls(
            observed_at=observation.observed_at,
            source_url=observation.source_url,
            facts=observation.facts,
            raw_payload=observation.raw_payload,
        )

    def shallow_json(self) -> dict[str, Any]:
        """Return the canonical top-level JSON object of this material state.

        The four material fields map to plain (thawed) JSON values; this is
        the exact shape the shallow diff contract operates on.
        """
        return {
            "observed_at": self.observed_at,
            "source_url": self.source_url,
            "facts": self.facts,
            "raw_payload": self.raw_payload,
        }


def material_state_diff(
    previous: EvidenceMaterialState,
    candidate: EvidenceMaterialState,
) -> dict[str, Any]:
    """Return the canonical material diff from ``previous`` to ``candidate``.

    Mirrors the fresh-main ``ati.ati_jsonb_diff`` convention as a small pure
    contract that PR 28B SQL must match: a shallow top-level diff over the
    material JSON object in which every changed key maps to
    ``{"old": <previous value>, "new": <candidate value>}``. A key that is
    absent in one state is recorded with ``old``/``new`` of ``None``; absent
    and JSON null remain distinct. Keys are emitted in sorted order for
    determinism. Equal states produce ``{}``.
    """
    old = previous.shallow_json()
    new = candidate.shallow_json()
    diff: dict[str, Any] = {}
    for key in sorted(set(old) | set(new)):
        old_present = key in old
        new_present = key in new
        old_value = old.get(key)
        new_value = new.get(key)
        if old_present != new_present or old_value != new_value:
            diff[key] = {"old": old_value, "new": new_value}
    return diff


class EvidenceTransition(str, Enum):
    """The pure decision of one conversion against the current observed state.

    ``CREATE_EVIDENCE_AND_OBSERVATION`` creates a new global Evidence whose
    first material state is necessarily observation version 1.
    ``NO_CHANGE`` means the latest material state already equals the
    candidate: no new observation and no diff. ``APPEND_OBSERVATION`` means
    the candidate is a material change and appends the next immutable
    observation.
    """

    CREATE_EVIDENCE_AND_OBSERVATION = "create_evidence_and_observation"
    NO_CHANGE = "no_change"
    APPEND_OBSERVATION = "append_observation"


def decide_evidence_transition(
    *,
    evidence_exists: bool,
    latest_observation: EvidenceObservation | None,
    candidate: EvidenceObservationCandidate,
) -> EvidenceTransition:
    """Decide the observation transition for one candidate, fail closed.

    Truth table:

    - no Evidence + no latest observation  -> CREATE_EVIDENCE_AND_OBSERVATION
    - Evidence + latest observation + equal material state -> NO_CHANGE
    - Evidence + latest observation + different state -> APPEND_OBSERVATION
    - Evidence present with no latest observation -> fail closed (a normal
      committed Evidence must always have at least observation version 1)
    - no Evidence with a latest observation present -> fail closed
      (impossible combination)

    The decision is pure; authoritative next-version allocation stays in
    persistence (PR 28B) and is never computed here.
    """
    if not evidence_exists:
        if latest_observation is not None:
            raise ValueError(
                "evidence does not exist yet a latest observation is present"
            )
        return EvidenceTransition.CREATE_EVIDENCE_AND_OBSERVATION
    if latest_observation is None:
        raise ValueError("committed evidence must have at least one observation")
    latest_state = EvidenceMaterialState.from_observation(latest_observation)
    candidate_state = EvidenceMaterialState.from_candidate(candidate)
    if latest_state == candidate_state:
        return EvidenceTransition.NO_CHANGE
    return EvidenceTransition.APPEND_OBSERVATION


class EvidenceObservationEntity(BaseModel):
    """Observation-level association of one canonical Entity to one observation.

    Logical identity is the exact ``(evidence_observation_id, entity_id)``
    pair; there is no role, Investigation, confidence, relationship type, or
    duplicate timestamp on the association in PR 28A.
    """

    model_config = ConfigDict(frozen=True)

    evidence_observation_id: UUID
    entity_id: UUID


class InvestigationEvidenceReason(str, Enum):
    """Bounded mechanism vocabulary admitting an observation to an Investigation.

    Repository-naming convention only; free-form strings are rejected by the
    enum contract. Values are durable and must never be reinterpreted.
    """

    INITIAL = "initial"
    PROVIDER_RESULT = "provider_result"
    CORRELATION = "correlation"
    AGENT_SELECTED = "agent_selected"
    ANALYST_ADDED = "analyst_added"


class InvestigationEvidenceActor(str, Enum):
    """Bounded actor vocabulary of who admitted an observation."""

    SYSTEM = "system"
    AGENT = "agent"
    ANALYST = "analyst"


class InvestigationEvidence(BaseModel):
    """Exact admission of one immutable observation into one Investigation.

    Logical identity is ``(investigation_id, evidence_observation_id)``;
    admission is append-only/idempotent and never carries duplicated
    Evidence/source/subject/source-record fields. ``added_at`` is normalized
    to UTC; ``discovered_from_evidence_observation_id`` is workflow
    provenance only, never a threat relationship.
    """

    model_config = ConfigDict(frozen=True)

    investigation_id: UUID
    evidence_observation_id: UUID
    inclusion_reason: InvestigationEvidenceReason
    discovered_from_evidence_observation_id: UUID | None = None
    added_at: datetime
    added_by: InvestigationEvidenceActor

    @field_validator("added_at")
    @classmethod
    def _utc_added_at(cls, value: datetime) -> datetime:
        """Normalize aware admission timestamps to UTC; reject naive ones."""
        returned = _validate_utc(value)
        if returned is None:  # pragma: no cover - added_at is required
            raise ValueError("added_at is required")
        return returned
