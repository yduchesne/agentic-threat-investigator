# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit versioned Evidence wire contract between conversion and the log (PR 28C).

An :class:`EvidenceMessage` is the durable, broker-independent wire
representation of **one producer-side :class:`ConvertedEvidence` candidate
plus bounded acquisition provenance**. It is never a direct serialization of
``ConvertedEvidence``, ``Evidence``, ``EvidenceObservation``,
``EvidenceObservationCandidate``, or ``SemanticSourceContext``: the schema,
the canonical JSON codec, and the typed validation are owned by this module
and pinned to ``schema_version == 1``.

Identity rules:

- ``evidence_id`` reuses the existing deterministic
  ``evidence_id_for_source_record(semantic_format, source, source_record_id)``
  global Evidence identity and is recomputed and validated on every
  construction and decode.
- ``message_id`` is a producer-side, replay-stable UUIDv5 over the exact
  ``(datasource_execution_id, sequence, evidence_id)`` producer execution
  slot. A new datasource execution is a new acquisition event and may have
  a new ``message_id`` even when the semantic state is unchanged; retrieval
  time, broker metadata, Investigation identity, Python hash, and ``uuid4``
  never participate.
- ``observation_candidate_id`` is a deterministic UUIDv5 derived from
  ``message_id``: it is the producer/replay identity of the **proposed**
  material state, explicitly **not** the PostgreSQL-authoritative committed
  ``EvidenceObservation.id``. The producer never allocates an Observation
  ``version`` or ``diff``; the message never claims to know whether
  PostgreSQL will create, reuse, or append an ``EvidenceObservation``.

The wire carries only the bounded provenance of invariant 11 of the PR 28C
contract (datasource execution ID, datasource ID, source ID, semantic
format, and the candidate's source/retrieval provenance) plus the exact
material state (``observed_at``, ``source_url``, ``facts``,
``raw_payload``; ``retrieved_at`` remains operational). Broker topology,
Investigation ownership, subject Entity, pivot/work-item state, reports,
agent state, derived Entity/Relationship/GEOINT/Assessment state, generic
metadata/headers/config/credentials dictionaries, and exception text are
absent by construction.

Construction and codec operations are pure: no database, no network, no
UnitOfWork, no clock, and no random reads. Serialization is canonical
deterministic UTF-8 JSON (sorted keys, compact separators, ``Z``-pinned
UTC timestamps, ``allow_nan=False``, enum stable values) and deserialization
fails closed on unknown versions, malformed fields, identity mismatches,
and extra fields. PR 28D+ will define the publisher/consumer/log
abstraction; this module neither publishes nor consumes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid5

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.domain.datasource import DatasourceId
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.immutable_json import (
    FrozenDict,
    freeze_mapping,
    thaw_json,
)

EVIDENCE_MESSAGE_SCHEMA_VERSION = 1
"""The one and only EvidenceMessage schema version supported by PR 28C.

The value is the durable wire ``schema_version`` field; it is deliberately
independent of package/release/migration/semantic-format versions. V1
accepts exactly ``1``; unsupported versions fail closed with
:class:`UnsupportedEvidenceMessageVersionError`. Future versions must
explicitly define reader compatibility, writer selection, migration/default
rules, and identity stability before the constant changes.
"""

_ATI_ROOT_NAMESPACE = UUID("00000000-0000-0000-0000-0000000000ca")
"""Stable ATI-owned UUIDv5 root namespace.

The exact value is shared with ``domain/evidence.py`` (``_ATI_ROOT_NAMESPACE``)
and the evaluation fixtures; it is a durable contract and must never
change after first release.
"""

_EVIDENCE_MESSAGE_IDENTITY_NAMESPACE = uuid5(
    _ATI_ROOT_NAMESPACE, "ATI stable Evidence message identity"
)
"""ATI-owned namespace for deterministic producer-side message identity (PR 28C).

Derived once from the stable ATI root namespace; the value is a durable
contract and must never change after first release. It is distinct from the
global Evidence identity namespace and from the observation-candidate
namespace.
"""

_EVIDENCE_OBSERVATION_CANDIDATE_IDENTITY_NAMESPACE = uuid5(
    _ATI_ROOT_NAMESPACE, "ATI stable Evidence observation candidate identity"
)
"""ATI-owned namespace for the proposed observation-candidate identity (PR 28C).

Derived once from the stable ATI root namespace; the value is a durable
contract and must never change after first release. Distinct from both the
global Evidence identity namespace and the message identity namespace.
"""

_WIRE_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "message_id",
        "observation_candidate_id",
        "datasource_execution_id",
        "datasource_id",
        "source_id",
        "semantic_format",
        "sequence",
        "evidence_id",
        "evidence_type",
        "source_record_id",
        "retrieved_at",
        "observed_at",
        "source_url",
        "facts",
        "raw_payload",
    }
)
"""The exact V1 top-level wire field vocabulary; anything else is rejected."""


class EvidenceMessageError(ValueError):
    """Base failure of the EvidenceMessage wire contract.

    All EvidenceMessage failures are typed ``ValueError`` subclasses so
    callers can rely on one base class; the leaf types below distinguish
    malformed transport, unsupported schema versions, and field/identity
    violations without exposing raw JSON, Pydantic, ``KeyError``, or
    ``TypeError`` details.
    """


class EvidenceMessageValidationError(EvidenceMessageError):
    """A field, identity, or structure violation of the V1 contract.

    Raised for missing/extra/invalid fields, identity mismatches, naive
    timestamps, non-finite or non-object JSON values, negative sequence
    values, and empty record identities. Error text is bounded and never
    echoes the raw payload.
    """


class UnsupportedEvidenceMessageVersionError(EvidenceMessageError):
    """A schema version other than ``1`` was requested or decoded.

    The message carries only the version numbers — never payload content —
    so the failure is safe to surface and log.
    """

    def __init__(self, version: int, supported_version: int) -> None:
        """Pin the presented and supported schema versions."""
        super().__init__(
            f"unsupported evidence message schema version {version}; "
            f"supported version is {supported_version}"
        )
        self.version = version
        self.supported_version = supported_version


class EvidenceMessageDecodeError(EvidenceMessageError):
    """The payload bytes are not valid UTF-8 or canonical JSON.

    Raised for malformed JSON, invalid UTF-8, and non-standard constants
    (``NaN``/``Infinity``). The error text never echoes the payload.
    """


def evidence_message_id(
    datasource_execution_id: UUID,
    sequence: int,
    evidence_id: UUID,
) -> UUID:
    """Derive the deterministic replay-stable message identity of one producer slot.

    A UUIDv5 over the canonical name tuple
    ``<datasource-execution-uuid>|<sequence>|<evidence-uuid>`` under the
    PR 28C message namespace: the same tuple always yields the same ID, any
    component change yields a different ID, and retrieval time, broker
    metadata, Investigation identity, Python hash, and ``uuid4`` never
    participate. ``sequence`` is the zero-based flattened ``ConvertedEvidence``
    order of the producer execution; schema version is representation, not
    logical identity, and does not participate.
    """
    name = f"{datasource_execution_id}|{sequence}|{evidence_id}"
    return uuid5(_EVIDENCE_MESSAGE_IDENTITY_NAMESPACE, name)


def evidence_observation_candidate_id(message_id: UUID) -> UUID:
    """Derive the deterministic proposed observation-candidate identity.

    A UUIDv5 over the canonical message identity under the PR 28C
    observation-candidate namespace: the same message always yields the
    same candidate ID. This is the producer/replay identity of the proposed
    material state — never a proof that a committed ``EvidenceObservation``
    exists and never the PostgreSQL-authoritative observation ID.
    """
    return uuid5(_EVIDENCE_OBSERVATION_CANDIDATE_IDENTITY_NAMESPACE, str(message_id))


def _validate_utc(value: datetime | None) -> datetime | None:
    """Require timezone-aware timestamps, normalized to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("evidence message timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _encode_timestamp(value: datetime) -> str:
    """Encode one aware UTC timestamp as canonical ``Z``-pinned ISO-8601.

    Microseconds are always rendered with the fixed six digits so identical
    instants produce byte-identical strings; the local/UTC offset never
    leaks into the wire.
    """
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _validation_field_names(exc: ValidationError) -> str:
    """Return a bounded field-name summary of one pydantic validation error.

    Only schema field paths are included — never payload values — so the
    resulting message can never echo raw message content.
    """
    names: list[str] = []
    for error in exc.errors():
        loc = error.get("loc")
        if loc:
            name = str(loc[0])
            if name not in names:
                names.append(name)
    return ", ".join(names) if names else "field"


class EvidenceMessage(BaseModel):
    """Immutable version-1 EvidenceMessage wire object (PR 28C).

    One versioned wire representation of one producer-side
    :class:`ConvertedEvidence` candidate plus bounded acquisition
    provenance. Construction is pure and fail-closed: every field is
    validated (including identity recomputation of the Evidence, message,
    and observation-candidate identities) and any violation raises
    :class:`EvidenceMessageValidationError`. The class carries exactly the
    V1 wire fields — no Investigation/subject/graph/broker state, no
    Observation version/diff, and no generic metadata dictionary.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int
    message_id: UUID
    observation_candidate_id: UUID
    datasource_execution_id: UUID
    datasource_id: DatasourceId
    source_id: SourceId
    semantic_format: SemanticFormatId
    sequence: int = Field(ge=0, strict=True)
    evidence_id: UUID
    evidence_type: EvidenceType
    source_record_id: str = Field(strict=True)
    retrieved_at: datetime
    observed_at: datetime | None = None
    source_url: str | None = Field(default=None, strict=True)
    facts: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] | None = None

    def __init__(self, **data: Any) -> None:
        """Validate every construction through the typed contract error.

        Pydantic performs the field/identity validation; any violation is
        re-raised as :class:`EvidenceMessageValidationError` so the public
        construction surface never leaks raw pydantic details.
        """
        try:
            self.__pydantic_validator__.validate_python(data, self_instance=self)
        except ValidationError as exc:
            raise EvidenceMessageValidationError(
                f"invalid evidence message {_validation_field_names(exc)}"
            ) from exc

    @field_validator("datasource_id", mode="before")
    @classmethod
    def _coerce_datasource_id(cls, value: object) -> DatasourceId:
        """Accept a DatasourceId or its canonical wire string form."""
        if isinstance(value, DatasourceId):
            return value
        if not isinstance(value, str):
            raise ValueError("datasource_id must be a string or DatasourceId")
        return DatasourceId(value)

    @field_validator("schema_version", mode="before")
    @classmethod
    def _schema_version_exactly_one(cls, value: object) -> int:
        """Reject any schema version other than the single supported one.

        Runs before pydantic's own coercion so a JSON ``true`` can never
        masquerade as version ``1`` (``True == 1`` under Python equality).
        """
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value != EVIDENCE_MESSAGE_SCHEMA_VERSION
        ):
            raise ValueError("unsupported evidence message schema version")
        return value

    @field_validator("source_record_id")
    @classmethod
    def _source_record_id_non_empty(cls, value: str) -> str:
        """Reject empty/blank upstream record identities without normalizing.

        The upstream record identity is preserved verbatim; only an empty
        or whitespace-only value fails closed.
        """
        if not value or not value.strip():
            raise ValueError("source_record_id must not be empty")
        return value

    @field_validator("source_url")
    @classmethod
    def _source_url_non_empty(cls, value: str | None) -> str | None:
        """Reject an empty source URL while preserving ``None`` and content."""
        if value is not None and not value:
            raise ValueError("source_url must not be empty")
        return value

    @field_validator("observed_at", "retrieved_at")
    @classmethod
    def _utc_timestamps(cls, value: datetime | None) -> datetime | None:
        """Normalize aware timestamps to UTC; reject naive timestamps."""
        return _validate_utc(value)

    @field_validator("facts", mode="after")
    @classmethod
    def _freeze_facts(cls, value: dict[str, Any]) -> FrozenDict:
        """Store facts as a deeply immutable JSON object."""
        return freeze_mapping(value)

    @field_validator("raw_payload", mode="after")
    @classmethod
    def _freeze_raw_payload(cls, value: dict[str, Any] | None) -> FrozenDict | None:
        """Store the raw payload as a deeply immutable JSON object or ``None``."""
        return freeze_mapping(value) if value is not None else None

    @model_validator(mode="after")
    def _validate_identities(self) -> "EvidenceMessage":
        """Recompute and cross-check the three deterministic identities.

        The Evidence identity must equal
        ``evidence_id_for_source_record(semantic_format, source_id,
        source_record_id)``; the message identity must equal
        ``evidence_message_id(datasource_execution_id, sequence,
        evidence_id)``; and the observation-candidate identity must equal
        ``evidence_observation_candidate_id(message_id)``. Any mismatch
        fails closed: the wire never accepts a claimed identity that the
        deterministic contract does not reproduce.
        """
        expected_evidence_id = evidence_id_for_source_record(
            self.semantic_format, self.source_id, self.source_record_id
        )
        if self.evidence_id != expected_evidence_id:
            raise ValueError(
                "evidence identity does not match semantic format, source, "
                "and source_record_id"
            )
        expected_message_id = evidence_message_id(
            self.datasource_execution_id, self.sequence, self.evidence_id
        )
        if self.message_id != expected_message_id:
            raise ValueError(
                "message identity does not match datasource execution, "
                "sequence, and evidence identity"
            )
        expected_candidate_id = evidence_observation_candidate_id(self.message_id)
        if self.observation_candidate_id != expected_candidate_id:
            raise ValueError(
                "observation candidate identity does not match the message identity"
            )
        return self


def evidence_message_from_converted(
    converted: ConvertedEvidence,
    *,
    datasource_execution_id: UUID,
    semantic_source: SemanticSourceContext,
    sequence: int,
) -> EvidenceMessage:
    """Build the V1 message of one ConvertedEvidence plus bounded provenance.

    Maps every Evidence and candidate field exactly, validates the source
    and retrieval provenance, and derives the deterministic message and
    observation-candidate identities. ``semantic_source`` carries the
    datasource/source/semantic-format identities and the retrieval
    provenance; the candidate ``source_url`` must equal the credential-free
    source reference (established identical by the production ThreatFox
    converter) and the candidate ``retrieved_at`` must equal the semantic
    retrieval time — conflicts fail closed rather than being silently
    resolved. ``sequence`` is the zero-based flattened order of this
    candidate within the producer execution. No database, network, broker,
    or UnitOfWork is involved.
    """
    if sequence < 0:
        raise EvidenceMessageValidationError("sequence must be >= 0")
    evidence = converted.evidence
    candidate = converted.observation
    if candidate.evidence_id != evidence.id:
        raise EvidenceMessageValidationError(
            "observation candidate evidence identity does not match the "
            "ConvertedEvidence Evidence identity"
        )
    if evidence.source != semantic_source.source_id.value:
        raise EvidenceMessageValidationError(
            "ConvertedEvidence source does not match the semantic source context"
        )
    if candidate.source_url != semantic_source.source_reference:
        raise EvidenceMessageValidationError(
            "observation candidate source_url does not match the semantic "
            "source reference"
        )
    if candidate.retrieved_at != semantic_source.retrieved_at:
        raise EvidenceMessageValidationError(
            "observation candidate retrieved_at does not match the semantic "
            "retrieval time"
        )
    message_id = evidence_message_id(datasource_execution_id, sequence, evidence.id)
    return EvidenceMessage(
        schema_version=EVIDENCE_MESSAGE_SCHEMA_VERSION,
        message_id=message_id,
        observation_candidate_id=evidence_observation_candidate_id(message_id),
        datasource_execution_id=datasource_execution_id,
        datasource_id=semantic_source.datasource_id,
        source_id=semantic_source.source_id,
        semantic_format=semantic_source.semantic_format,
        sequence=sequence,
        evidence_id=evidence.id,
        evidence_type=evidence.type,
        source_record_id=evidence.source_record_id,
        retrieved_at=candidate.retrieved_at,
        observed_at=candidate.observed_at,
        source_url=candidate.source_url,
        facts=candidate.facts,
        raw_payload=candidate.raw_payload,
    )


def converted_evidence_from_message(message: EvidenceMessage) -> ConvertedEvidence:
    """Reconstruct the exact ConvertedEvidence of one V1 message.

    Rebuilds the ``Evidence`` (reconstructing ``source`` from
    ``source_id.value`` — never a duplicated unconstrained string) and the
    pre-persistence ``EvidenceObservationCandidate`` only. It never creates
    an ``EvidenceObservation``, never allocates a version or diff, and
    never admits the Evidence to any Investigation or builds graph state.
    """
    return ConvertedEvidence(
        evidence=Evidence(
            id=message.evidence_id,
            type=message.evidence_type,
            source=message.source_id.value,
            source_record_id=message.source_record_id,
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=message.evidence_id,
            source_url=message.source_url,
            observed_at=message.observed_at,
            retrieved_at=message.retrieved_at,
            facts=message.facts,
            raw_payload=message.raw_payload,
        ),
    )


def _to_wire_dict(message: EvidenceMessage) -> dict[str, Any]:
    """Map one message to the explicit owned V1 wire dictionary.

    This is the single durable wire mapping: canonical lowercase UUID
    strings, enum stable URN values, ``Z``-pinned UTC timestamps, and
    thawed JSON objects. It is never a ``model_dump_json()`` of an internal
    model.
    """
    return {
        "schema_version": message.schema_version,
        "message_id": str(message.message_id),
        "observation_candidate_id": str(message.observation_candidate_id),
        "datasource_execution_id": str(message.datasource_execution_id),
        "datasource_id": message.datasource_id.value,
        "source_id": message.source_id.value,
        "semantic_format": message.semantic_format.value,
        "sequence": message.sequence,
        "evidence_id": str(message.evidence_id),
        "evidence_type": message.evidence_type.value,
        "source_record_id": message.source_record_id,
        "retrieved_at": _encode_timestamp(message.retrieved_at),
        "observed_at": (
            None
            if message.observed_at is None
            else _encode_timestamp(message.observed_at)
        ),
        "source_url": message.source_url,
        "facts": thaw_json(message.facts),
        "raw_payload": (
            None if message.raw_payload is None else thaw_json(message.raw_payload)
        ),
    }


def _reject_json_constant(value: str) -> None:
    """Reject the non-standard JSON constants ``NaN``/``Infinity``.

    JSON input is a strict format; accepting non-standard constants would
    let non-finite values into the contract.
    """
    raise ValueError(f"non-standard JSON constant: {value}")


def encode_evidence_message(message: EvidenceMessage) -> bytes:
    """Serialize one message to canonical deterministic UTF-8 JSON.

    Byte-identical for structurally equal messages: sorted keys (top level
    and nested), compact fixed separators, ``allow_nan=False``, no ASCII
    escaping, canonical UUID/URN values, and ``Z``-pinned UTC timestamps.
    The output is decodable back to an equal message by
    :func:`decode_evidence_message`.
    """
    wire = _to_wire_dict(message)
    return json.dumps(
        wire,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def decode_evidence_message(payload: bytes) -> EvidenceMessage:
    """Strictly decode canonical JSON bytes into an equal V1 message.

    Fails closed with typed errors: invalid UTF-8 and malformed/non-standard
    JSON raise :class:`EvidenceMessageDecodeError`; a missing or
    non-integer ``schema_version`` raises
    :class:`EvidenceMessageValidationError`; any version other than ``1``
    raises :class:`UnsupportedEvidenceMessageVersionError`; and unknown
    fields, malformed values, or identity mismatches raise
    :class:`EvidenceMessageValidationError`. No raw payload content is
    ever echoed by the raised errors.
    """
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceMessageDecodeError(
            "evidence message payload is not valid UTF-8"
        ) from exc
    try:
        data = json.loads(text, parse_constant=_reject_json_constant)
    except ValueError as exc:
        raise EvidenceMessageDecodeError(
            "evidence message payload is not valid canonical JSON"
        ) from exc
    if not isinstance(data, dict):
        raise EvidenceMessageValidationError("evidence message must be a JSON object")
    version = data.get("schema_version")
    if "schema_version" not in data:
        raise EvidenceMessageValidationError(
            "evidence message schema_version is required"
        )
    if isinstance(version, bool) or not isinstance(version, int):
        raise EvidenceMessageValidationError(
            "evidence message schema_version must be an integer"
        )
    if version != EVIDENCE_MESSAGE_SCHEMA_VERSION:
        raise UnsupportedEvidenceMessageVersionError(
            version, EVIDENCE_MESSAGE_SCHEMA_VERSION
        )
    unknown_fields = sorted(set(data) - _WIRE_TOP_LEVEL_FIELDS)
    if unknown_fields:
        raise EvidenceMessageValidationError(
            f"unknown evidence message field(s): {', '.join(unknown_fields)}"
        )
    return EvidenceMessage(**data)
