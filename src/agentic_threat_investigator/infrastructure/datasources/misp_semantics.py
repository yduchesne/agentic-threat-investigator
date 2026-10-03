# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""MISP native semantic-format parsing (PR 32A).

Parses one decoded native MISP Event value (the ``{"Event": {...}}``
semantic envelope after transport and serialization decoding) into
validated, immutable source-native :class:`MispAttributeRecord` /
:class:`MispObjectRecord` objects. This module owns only the small MISP
semantic contract ATI consumes for stable source identity, source
timestamps, hierarchy, future IOC conversion, and handling/distribution
provenance — it deliberately does not validate the complete MISP standard,
constructs no ATI Evidence, performs no network/DB/persistence I/O, assigns
no verdict, and logs no payloads.

Contract facts verified against the current MISP core format (v2.5):

- an Event is a JSON object ``{"Event": {...}}`` with ``uuid``/``info``/
  ``timestamp`` (UTC Unix seconds serialized as JSON strings), ``published``
  and ``deleted`` booleans, ``distribution`` ``0..4`` and ``sharing_group_id``;
- Attributes carry the ``category`` / ``type`` / ``value`` semantic triplet,
  a transferable upstream ``uuid``, a string Unix ``timestamp``, strict
  booleans ``to_ids``/``deleted``, ``distribution`` ``0..5`` (``5`` =
  inherit Event), ``sharing_group_id``, optional ``comment``/
  ``object_relation``, and tags;
- Objects carry identity/context plus nested Attributes and
  ``ObjectReference`` members (``uuid``/``referenced_uuid``/
  ``relationship_type``), ``meta-category`` (hyphenated key), integer
  ``template_version``, optional ``first_seen``/``last_seen`` (timezone-aware
  ISO-8601), and Object distribution ``0..5`` with ``5`` = inherit Event;
- when distribution is ``4`` MISP requires a real (nonzero) sharing group,
  and for every other distribution MISP normalizes ``sharing_group_id`` to
  ``0``.

Distribution values are preserved exactly; ``5`` is never resolved to an
effective value and never translated into ATI authorization. ``deleted``
state is preserved. ``data``/binary members are never decoded or copied.
Object-owned Attributes stay inside their ``MispObjectRecord`` and are never
also emitted as top-level ``MispAttributeRecord`` objects.

A malformed modeled member fails the whole Event with a bounded
non-retryable ``DatasourceStage.SEMANTIC_VALIDATION`` error and zero records;
partial results are never returned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TypeAlias
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    DatasourceStageError,
)

# --------------------------------------------------------------------------
# Bound and vocabulary constants
# --------------------------------------------------------------------------

# MISP distribution levels (`0`..`5`; `5` exists only on Attribute and Object
# where it means "inherit the Event's distribution", never resolved here).
DISTRIBUTION_ORGANISATION_ONLY = 0
DISTRIBUTION_COMMUNITY_ONLY = 1
DISTRIBUTION_CONNECTED_COMMUNITIES = 2
DISTRIBUTION_ALL_COMMUNITIES = 3
DISTRIBUTION_SHARING_GROUP = 4
DISTRIBUTION_INHERIT_EVENT = 5

# Modeled string bounds. These are ATI-bound; over-bound modeled content is a
# semantic failure (never truncated).
_EVENT_INFO_MAX_LENGTH = 4096
_ATTRIBUTE_TYPE_MAX_LENGTH = 64
_ATTRIBUTE_CATEGORY_MAX_LENGTH = 255
_ATTRIBUTE_VALUE_MAX_LENGTH = 8192
_ATTRIBUTE_COMMENT_MAX_LENGTH = 2048
_OBJECT_RELATION_MAX_LENGTH = 64
_OBJECT_NAME_MAX_LENGTH = 512
_OBJECT_COMMENT_MAX_LENGTH = 2048
_RELATIONSHIP_TYPE_MAX_LENGTH = 64
_TAG_NAME_MAX_LENGTH = 255
_META_CATEGORY_MAX_LENGTH = 255

# Strict source numeric forms: decimal digit strings (MISP REST serializes
# numeric fields as strings) or genuine integers; booleans and floats are
# rejected.
_DECIMAL_RE = re.compile(r"^[0-9]+$")
# MISP Unix timestamps are UTC Unix seconds serialized as JSON strings.
_UNIX_TIMESTAMP_RE = re.compile(r"^[0-9]+$")


def _parse_unix_timestamp(value: object, member: str) -> datetime:
    """Parse a strict MISP Unix-seconds timestamp string into UTC.

    The official MISP REST form is a nonempty decimal string with no
    whitespace, sign, or fraction. Integers/floats/booleans are rejected
    because the source contract serializes the value as a JSON string.
    Overflowing or otherwise out-of-range calendar values fail closed.
    """
    if not isinstance(value, str) or _UNIX_TIMESTAMP_RE.fullmatch(value) is None:
        raise ValueError(f"{member} must be a nonempty decimal Unix timestamp string")
    try:
        seconds = int(value)
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise ValueError(f"{member} is outside the supported timestamp range") from (
            error
        )


def _parse_iso_timestamp(value: object, member: str) -> datetime:
    """Parse a strict timezone-aware ISO-8601 source timestamp into UTC.

    A documented string is required; a ``Z`` suffix is normalized to UTC.
    Naive values are rejected; an Object's ``first_seen``/``last_seen`` are
    never substituted from the Object modification timestamp.
    """
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{member} must be a timezone-aware ISO-8601 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"{member} must be a timezone-aware ISO-8601 string") from (
            error
        )
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{member} must be a timezone-aware ISO-8601 string")
    return parsed.astimezone(UTC)


def _parse_source_int(value: object, member: str) -> int:
    """Parse a strict MISP integer (genuine int or decimal string).

    Booleans and floats are rejected; the numeric value itself is range- and
    consistency-checked by the caller.
    """
    if isinstance(value, bool):
        raise ValueError(f"{member} must be a source integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _DECIMAL_RE.fullmatch(value) is not None:
        return int(value)
    raise ValueError(f"{member} must be a source integer")


def _validate_bounded_string(value: object, member: str, max_length: int) -> str:
    """Require a nonblank bounded source string unchanged by stripping."""
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > max_length
    ):
        raise ValueError(f"{member} must be a nonblank bounded source string")
    return value


def _validate_optional_string(
    value: object, member: str, max_length: int
) -> str | None:
    """Validate an optional bounded source string; documented null is kept."""
    if value is None:
        return None
    return _validate_bounded_string(value, member, max_length)


def _validate_uuid(value: object, member: str) -> UUID:
    """Parse one strict dedicated RFC 4122 UUID from the source identity."""
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{member} must be a UUID")
    try:
        return UUID(value)
    except ValueError as error:
        raise ValueError(f"{member} must be a UUID") from error


def _unwrap_member(member: object, model_key: str) -> dict[str, object]:
    """Return the model fields of one array member.

    MISP's canonical REST export wraps array members in the singular model
    name (``{"Attribute": {...}}``, ``{"Object": {...}}``,
    ``{"ObjectReference": {...}}``, ``{"Tag": {...}}``); the direct form is
    also accepted. Anything else fails closed.
    """
    if not isinstance(member, dict):
        raise ValueError(f"{model_key} member must be a JSON object")
    nested = member.get(model_key)
    if isinstance(nested, dict):
        return nested
    return member


def _validate_sharing_group(
    distribution: int, sharing_group_id: int, member: str
) -> None:
    """Enforce the MISP distribution/sharing-group consistency rule.

    Verified upstream: distribution ``4`` (sharing group) requires a real
    nonzero group; MISP normalizes ``sharing_group_id`` to ``0`` for every
    other distribution (including Attribute/Object ``5`` inherit).
    """
    if distribution == DISTRIBUTION_SHARING_GROUP and sharing_group_id < 1:
        raise ValueError(
            f"{member} sharing_group_id must be nonzero with distribution 4"
        )
    if distribution != DISTRIBUTION_SHARING_GROUP and sharing_group_id != 0:
        raise ValueError(f"{member} sharing_group_id must be 0 outside distribution 4")


class _MispModel(BaseModel):
    """Frozen strict source model base: extra members are ignored, types strict."""

    model_config = ConfigDict(
        extra="ignore", frozen=True, strict=True, populate_by_name=True
    )


class MispTag(_MispModel):
    """One immutable MISP tag name; taxonomy/TLP are not interpreted."""

    name: str

    @field_validator("name", mode="before")
    @classmethod
    def _validate_name(cls, value: object) -> str:
        """Require a nonblank bounded tag name."""
        return _validate_bounded_string(value, "tag name", _TAG_NAME_MAX_LENGTH)


class MispEventContext(_MispModel):
    """Immutable MISP Event context carried by every semantic record.

    ``uuid`` is the transferable upstream semantic identity; local numeric
    Event ids are not modeled. Source Unix ``timestamp`` becomes a
    UTC-aware ``datetime``. ``published``/``publish_timestamp``/
    ``extends_uuid`` are preserved when present and stable in the MISP core
    contract; ``Org``/``Orgc`` and unmodeled members are ignored.
    """

    uuid: UUID
    info: str
    timestamp: datetime
    distribution: int
    sharing_group_id: int
    published: bool | None = None
    publish_timestamp: datetime | None = None
    extends_uuid: UUID | None = None
    tags: tuple[MispTag, ...] = Field(default=(), alias="Tag")

    @field_validator("uuid", mode="before")
    @classmethod
    def _validate_uuid(cls, value: object) -> UUID:
        """Parse the dedicated Event UUID."""
        return _validate_uuid(value, "Event.uuid")

    @field_validator("info", mode="before")
    @classmethod
    def _validate_info(cls, value: object) -> str:
        """Require the nonblank bounded MISP Event info string."""
        return _validate_bounded_string(value, "Event.info", _EVENT_INFO_MAX_LENGTH)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, value: object) -> datetime:
        """Parse the strict MISP Event Unix timestamp string."""
        return _parse_unix_timestamp(value, "Event.timestamp")

    @field_validator("publish_timestamp", mode="before")
    @classmethod
    def _validate_publish_timestamp(cls, value: object) -> datetime | None:
        """Parse the optional strict MISP publish-timestamp string."""
        if value is None:
            return None
        return _parse_unix_timestamp(value, "Event.publish_timestamp")

    @field_validator("extends_uuid", mode="before")
    @classmethod
    def _validate_extends_uuid(cls, value: object) -> UUID | None:
        """Parse the optional UUID of the extended parent Event."""
        if value is None:
            return None
        return _validate_uuid(value, "Event.extends_uuid")

    @field_validator("distribution", mode="before")
    @classmethod
    def _validate_distribution(cls, value: object) -> int:
        """Require the strict Event distribution ``0..4``."""
        distribution = _parse_source_int(value, "Event.distribution")
        if not 0 <= distribution <= 4:
            raise ValueError("Event.distribution must be in 0..4")
        return distribution

    @field_validator("sharing_group_id", mode="before")
    @classmethod
    def _validate_sharing_group(cls, value: object) -> int:
        """Parse the nonnegative source sharing-group identifier."""
        group = _parse_source_int(value, "Event.sharing_group_id")
        if group < 0:
            raise ValueError("Event.sharing_group_id must be nonnegative")
        return group

    @model_validator(mode="after")
    def _check_distribution_consistency(self) -> "MispEventContext":
        """Enforce the MISP Event distribution/sharing-group rule."""
        _validate_sharing_group(self.distribution, self.sharing_group_id, "Event")
        return self

    @field_validator("tags", mode="before")
    @classmethod
    def _validate_tags(cls, value: object) -> tuple[MispTag, ...]:
        """Parse and deduplicate the Event tags in first-occurrence order."""
        return _parse_tags(value, "Event")


def _parse_tags(value: object, member: str) -> tuple[MispTag, ...]:
    """Parse one tag array, suppressing later exact duplicate names."""
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{member} tags must be an array")
    tags: list[MispTag] = []
    seen: set[str] = set()
    for entry in value:
        fields = _unwrap_member(entry, "Tag")
        tag = MispTag(
            name=_validate_bounded_string(
                fields.get("name"), "tag name", _TAG_NAME_MAX_LENGTH
            )
        )
        if tag.name in seen:
            continue
        seen.add(tag.name)
        tags.append(tag)
    return tuple(tags)


class MispAttribute(_MispModel):
    """One immutable MISP Attribute semantic record.

    ``type``/``category``/``value`` are preserved exactly without IOC
    canonicalization or interpretation; ``to_ids`` is source semantics, not
    an ATI verdict; ``deleted``/``distribution``/``sharing_group_id`` are
    preserved. ``uuid`` is the transferable upstream Attribute identity.
    ``object_relation`` supports Object-owned Attributes. Binary ``data``
    is never decoded or retained.
    """

    uuid: UUID
    type: str
    category: str
    value: str
    timestamp: datetime
    to_ids: bool
    distribution: int
    sharing_group_id: int
    deleted: bool
    comment: str | None = None
    object_relation: str | None = None
    tags: tuple[MispTag, ...] = Field(default=(), alias="Tag")

    @field_validator("uuid", mode="before")
    @classmethod
    def _validate_uuid(cls, value: object) -> UUID:
        """Parse the dedicated Attribute UUID."""
        return _validate_uuid(value, "Attribute.uuid")

    @field_validator("type", mode="before")
    @classmethod
    def _validate_type(cls, value: object) -> str:
        """Require the nonblank bounded MISP Attribute type."""
        return _validate_bounded_string(
            value, "Attribute.type", _ATTRIBUTE_TYPE_MAX_LENGTH
        )

    @field_validator("category", mode="before")
    @classmethod
    def _validate_category(cls, value: object) -> str:
        """Require the nonblank bounded MISP Attribute category."""
        return _validate_bounded_string(
            value, "Attribute.category", _ATTRIBUTE_CATEGORY_MAX_LENGTH
        )

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, value: object) -> str:
        """Require the nonblank bounded source value without interpretation."""
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Attribute.value must be a nonblank source string")
        if len(value) > _ATTRIBUTE_VALUE_MAX_LENGTH:
            raise ValueError("Attribute.value exceeds the maximum length")
        return value

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, value: object) -> datetime:
        """Parse the strict MISP Attribute Unix timestamp string."""
        return _parse_unix_timestamp(value, "Attribute.timestamp")

    @field_validator("comment", mode="before")
    @classmethod
    def _validate_comment(cls, value: object) -> str | None:
        """Validate the optional bounded Attribute comment."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Attribute.comment must be a string or null")
        if value != value.strip() or len(value) > _ATTRIBUTE_COMMENT_MAX_LENGTH:
            raise ValueError("Attribute.comment is outside the supported bound")
        return value

    @field_validator("object_relation", mode="before")
    @classmethod
    def _validate_object_relation(cls, value: object) -> str | None:
        """Validate the optional bounded Object relation label."""
        return _validate_optional_string(
            value, "Attribute.object_relation", _OBJECT_RELATION_MAX_LENGTH
        )

    @field_validator("distribution", mode="before")
    @classmethod
    def _validate_distribution(cls, value: object) -> int:
        """Require the strict Attribute distribution ``0..5``."""
        distribution = _parse_source_int(value, "Attribute.distribution")
        if not 0 <= distribution <= 5:
            raise ValueError("Attribute.distribution must be in 0..5")
        return distribution

    @field_validator("sharing_group_id", mode="before")
    @classmethod
    def _validate_sharing_group(cls, value: object) -> int:
        """Parse the nonnegative source sharing-group identifier."""
        group = _parse_source_int(value, "Attribute.sharing_group_id")
        if group < 0:
            raise ValueError("Attribute.sharing_group_id must be nonnegative")
        return group

    @model_validator(mode="after")
    def _check_distribution_consistency(self) -> "MispAttribute":
        """Enforce the MISP Attribute distribution/sharing-group rule."""
        _validate_sharing_group(self.distribution, self.sharing_group_id, "Attribute")
        return self

    @field_validator("tags", mode="before")
    @classmethod
    def _validate_tags(cls, value: object) -> tuple[MispTag, ...]:
        """Parse and deduplicate the Attribute tags in first-occurrence order."""
        return _parse_tags(value, "Attribute")


class MispObjectReference(_MispModel):
    """One immutable MISP Object Reference.

    ``uuid`` is the stable upstream reference identity, ``referenced_uuid``
    the stable identity of the referenced Attribute/Object, and
    ``relationship_type`` the bounded source relationship label. No ATI
    Relationship is created and no reference resolution is performed.
    """

    uuid: UUID
    relationship_type: str
    referenced_uuid: UUID

    @field_validator("uuid", mode="before")
    @classmethod
    def _validate_uuid(cls, value: object) -> UUID:
        """Parse the dedicated Object Reference UUID."""
        return _validate_uuid(value, "ObjectReference.uuid")

    @field_validator("referenced_uuid", mode="before")
    @classmethod
    def _validate_referenced_uuid(cls, value: object) -> UUID:
        """Parse the referenced member's stable upstream UUID."""
        return _validate_uuid(value, "ObjectReference.referenced_uuid")

    @field_validator("relationship_type", mode="before")
    @classmethod
    def _validate_relationship_type(cls, value: object) -> str:
        """Require the nonblank bounded Object Reference relationship label."""
        return _validate_bounded_string(
            value, "ObjectReference.relationship_type", _RELATIONSHIP_TYPE_MAX_LENGTH
        )


class MispObject(_MispModel):
    """One immutable MISP Object with nested Attributes and References.

    Object-owned Attributes live only inside this record (never duplicated as
    Event-level ``MispAttributeRecord``). ``meta-category`` (the hyphenated
    MISP key), ``template_uuid``, ``template_version``, and the optional
    ``first_seen``/``last_seen`` timezone-aware ISO-8601 window are preserved
    when present and bounded; Object names/templates are never interpreted.
    ``deleted``/``distribution``/``sharing_group_id`` preserve source state.
    """

    uuid: UUID
    name: str
    timestamp: datetime
    distribution: int
    sharing_group_id: int
    deleted: bool
    comment: str | None = None
    meta_category: str | None = Field(default=None, alias="meta-category")
    template_uuid: UUID | None = None
    template_version: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    attributes: tuple[MispAttribute, ...] = Field(default=(), alias="Attribute")
    references: tuple[MispObjectReference, ...] = Field(
        default=(), alias="ObjectReference"
    )

    @field_validator("uuid", mode="before")
    @classmethod
    def _validate_uuid(cls, value: object) -> UUID:
        """Parse the dedicated Object UUID."""
        return _validate_uuid(value, "Object.uuid")

    @field_validator("name", mode="before")
    @classmethod
    def _validate_name(cls, value: object) -> str:
        """Require the nonblank bounded MISP Object name."""
        return _validate_bounded_string(value, "Object.name", _OBJECT_NAME_MAX_LENGTH)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, value: object) -> datetime:
        """Parse the strict MISP Object Unix timestamp string."""
        return _parse_unix_timestamp(value, "Object.timestamp")

    @field_validator("comment", mode="before")
    @classmethod
    def _validate_comment(cls, value: object) -> str | None:
        """Validate the optional bounded Object comment."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Object.comment must be a string or null")
        if value != value.strip() or len(value) > _OBJECT_COMMENT_MAX_LENGTH:
            raise ValueError("Object.comment is outside the supported bound")
        return value

    @field_validator("meta_category", mode="before")
    @classmethod
    def _validate_meta_category(cls, value: object) -> str | None:
        """Validate the optional bounded ``meta-category`` source member."""
        return _validate_optional_string(
            value, "Object.meta-category", _META_CATEGORY_MAX_LENGTH
        )

    @field_validator("template_uuid", mode="before")
    @classmethod
    def _validate_template_uuid(cls, value: object) -> UUID | None:
        """Parse the optional Object template UUID."""
        if value is None:
            return None
        return _validate_uuid(value, "Object.template_uuid")

    @field_validator("template_version", mode="before")
    @classmethod
    def _validate_template_version(cls, value: object) -> int | None:
        """Parse the optional natural-number Object template version."""
        if value is None:
            return None
        version = _parse_source_int(value, "Object.template_version")
        if version < 1:
            raise ValueError("Object.template_version must be a natural number")
        return version

    @field_validator("first_seen", mode="before")
    @classmethod
    def _validate_first_seen(cls, value: object) -> datetime | None:
        """Parse the optional timezone-aware ISO-8601 first-seen timestamp."""
        if value is None:
            return None
        return _parse_iso_timestamp(value, "Object.first_seen")

    @field_validator("last_seen", mode="before")
    @classmethod
    def _validate_last_seen(cls, value: object) -> datetime | None:
        """Parse the optional timezone-aware ISO-8601 last-seen timestamp."""
        if value is None:
            return None
        return _parse_iso_timestamp(value, "Object.last_seen")

    @field_validator("distribution", mode="before")
    @classmethod
    def _validate_distribution(cls, value: object) -> int:
        """Require the strict Object distribution ``0..5``.

        ``5`` (inherit the Event's distribution) is a real MISP source value
        for Objects: MISP's Object schema default is ``5`` and its own
        Object-distribution filters include it. It is preserved exactly,
        never resolved to the Event's effective value.
        """
        distribution = _parse_source_int(value, "Object.distribution")
        if not 0 <= distribution <= 5:
            raise ValueError("Object.distribution must be in 0..5")
        return distribution

    @field_validator("sharing_group_id", mode="before")
    @classmethod
    def _validate_sharing_group(cls, value: object) -> int:
        """Parse the nonnegative source sharing-group identifier."""
        group = _parse_source_int(value, "Object.sharing_group_id")
        if group < 0:
            raise ValueError("Object.sharing_group_id must be nonnegative")
        return group

    @model_validator(mode="after")
    def _check_distribution_consistency(self) -> "MispObject":
        """Enforce the MISP Object distribution/sharing-group rule."""
        _validate_sharing_group(self.distribution, self.sharing_group_id, "Object")
        if (
            self.first_seen is not None
            and self.last_seen is not None
            and self.first_seen > self.last_seen
        ):
            raise ValueError("Object.first_seen must not be after Object.last_seen")
        return self

    @field_validator("attributes", mode="before")
    @classmethod
    def _validate_attributes(cls, value: object) -> tuple[MispAttribute, ...]:
        """Parse the nested Object Attributes and deduplicate by UUID."""
        if value is None:
            return ()
        if not isinstance(value, list):
            raise ValueError("Object attributes must be an array")
        attributes: list[MispAttribute] = []
        seen: dict[UUID, MispAttribute] = {}
        for entry in value:
            fields = _unwrap_member(entry, "Attribute")
            attribute = MispAttribute.model_validate(fields)
            first = seen.get(attribute.uuid)
            if first is not None:
                if first != attribute:
                    raise ValueError("conflicting duplicate Object Attribute UUID")
                continue
            seen[attribute.uuid] = attribute
            attributes.append(attribute)
        return tuple(attributes)

    @field_validator("references", mode="before")
    @classmethod
    def _validate_references(cls, value: object) -> tuple[MispObjectReference, ...]:
        """Parse the Object References and deduplicate by UUID."""
        if value is None:
            return ()
        if not isinstance(value, list):
            raise ValueError("Object references must be an array")
        references: list[MispObjectReference] = []
        seen: dict[UUID, MispObjectReference] = {}
        for entry in value:
            fields = _unwrap_member(entry, "ObjectReference")
            reference = MispObjectReference.model_validate(fields)
            first = seen.get(reference.uuid)
            if first is not None:
                if first != reference:
                    raise ValueError("conflicting duplicate ObjectReference UUID")
                continue
            seen[reference.uuid] = reference
            references.append(reference)
        return tuple(references)


class MispAttributeRecord(_MispModel):
    """One flattened Event-level Attribute record with its Event context."""

    event: MispEventContext
    attribute: MispAttribute


class MispObjectRecord(_MispModel):
    """One flattened Event-level Object record with its Event context."""

    event: MispEventContext
    object: MispObject


MispSemanticRecord: TypeAlias = MispAttributeRecord | MispObjectRecord


@dataclass(frozen=True)
class MispSemanticResult:
    """One parsed MISP Event semantic outcome.

    Invariant: success means ``error is None`` with ``records`` possibly
    empty; failure means ``error`` is set and ``records`` is empty.
    """

    records: tuple[MispSemanticRecord, ...] = ()
    error: DatasourceStageError | None = None

    def __post_init__(self) -> None:
        """Enforce the success/failure invariant of the parsed outcome."""
        if self.error is not None and self.records:
            raise ValueError("a failed MISP parse cannot carry records")


def _semantic_validation_error() -> DatasourceStageError:
    """Build the standard non-retryable semantic-validation stage error."""
    return DatasourceStageError(
        stage=DatasourceStage.SEMANTIC_VALIDATION,
        code="semantic_validation_failed",
        retryable=False,
    )


def parse_misp_event(decoded: object) -> MispSemanticResult:
    """Parse one decoded native MISP Event envelope into typed records.

    Requires exactly the ``{"Event": {...}}`` semantic envelope; list/search/
    pagination envelopes and bare Events are not accepted (PR 32C adapts its
    selected REST endpoint into this contract). Event Attributes are
    returned first, then Event Objects, each in source order with nested
    Object Attributes/References preserved. An identical duplicate UUID is
    kept once (first occurrence); a conflicting duplicate UUID or any other
    malformed modeled member fails the whole Event with a bounded
    non-retryable ``SEMANTIC_VALIDATION`` error and zero records. The parser
    accepts a decoded value — never raw bytes — and performs no network/DB/
    persistence I/O and no Evidence construction.
    """
    if not isinstance(decoded, dict):
        return MispSemanticResult(error=_semantic_validation_error())
    event_value = decoded.get("Event")
    if not isinstance(event_value, dict):
        return MispSemanticResult(error=_semantic_validation_error())
    try:
        context = MispEventContext.model_validate(event_value)
        attribute_records = _parse_event_attributes(event_value, context)
        object_records = _parse_event_objects(event_value, context)
    except ValueError:
        return MispSemanticResult(error=_semantic_validation_error())
    return MispSemanticResult(records=attribute_records + object_records)


def _parse_event_attributes(
    event_value: dict[str, object], context: MispEventContext
) -> tuple[MispAttributeRecord, ...]:
    """Parse Event.Attribute into flattened records with duplicate control."""
    members = event_value.get("Attribute")
    if members is None:
        return ()
    if not isinstance(members, list):
        raise ValueError("Event.Attribute must be an array")
    records: list[MispAttributeRecord] = []
    seen: dict[UUID, MispAttribute] = {}
    for entry in members:
        fields = _unwrap_member(entry, "Attribute")
        attribute = MispAttribute.model_validate(fields)
        first = seen.get(attribute.uuid)
        if first is not None:
            if first != attribute:
                raise ValueError("conflicting duplicate Attribute UUID")
            continue
        seen[attribute.uuid] = attribute
        records.append(MispAttributeRecord(event=context, attribute=attribute))
    return tuple(records)


def _parse_event_objects(
    event_value: dict[str, object], context: MispEventContext
) -> tuple[MispObjectRecord, ...]:
    """Parse Event.Object into flattened records with duplicate control."""
    members = event_value.get("Object")
    if members is None:
        return ()
    if not isinstance(members, list):
        raise ValueError("Event.Object must be an array")
    records: list[MispObjectRecord] = []
    seen: dict[UUID, MispObject] = {}
    for entry in members:
        fields = _unwrap_member(entry, "Object")
        object_ = MispObject.model_validate(fields)
        first = seen.get(object_.uuid)
        if first is not None:
            if first != object_:
                raise ValueError("conflicting duplicate Object UUID")
            continue
        seen[object_.uuid] = object_
        records.append(MispObjectRecord(event=context, object=object_))
    return tuple(records)


__all__ = [
    "DISTRIBUTION_ORGANISATION_ONLY",
    "DISTRIBUTION_COMMUNITY_ONLY",
    "DISTRIBUTION_CONNECTED_COMMUNITIES",
    "DISTRIBUTION_ALL_COMMUNITIES",
    "DISTRIBUTION_SHARING_GROUP",
    "DISTRIBUTION_INHERIT_EVENT",
    "MispAttribute",
    "MispAttributeRecord",
    "MispEventContext",
    "MispObject",
    "MispObjectRecord",
    "MispObjectReference",
    "MispSemanticRecord",
    "MispSemanticResult",
    "MispTag",
    "parse_misp_event",
]
