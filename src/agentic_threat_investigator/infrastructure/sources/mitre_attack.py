# SPDX-License-Identifier: AGPL-3.0-only
"""MITRE ATT&CK STIX 2.1 batch-source normalization."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from agentic_threat_investigator.app.sources import (
    CHECKPOINTING,
    ArtifactReference,
    BatchSource,
    ObjectStore,
    SourceBatch,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.source import SourceRecord

RECORD_TYPE_TECHNIQUE = "attack_technique"
RECORD_TYPE_SOFTWARE = "attack_software"
RECORD_TYPE_GROUP = "attack_group"
RECORD_TYPE_RELATIONSHIP = "attack_relationship"
NORMALIZATION_VERSION = 1

_ATTACK_PATTERN_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_SOFTWARE_ID = re.compile(r"^S\d{4}$")
_GROUP_ID = re.compile(r"^G\d{4}$")
_CHECKPOINT = re.compile(r"^index:(\d+)$")

_HANDLED_TYPES = frozenset(
    {"attack-pattern", "malware", "tool", "intrusion-set", "relationship"}
)
# Common bundle metadata and out-of-scope domain objects are intentionally
# skipped. Unknown STIX types are skipped as well for forward compatibility.
_SKIPPED_TYPES = frozenset(
    {
        "identity",
        "marking-definition",
        "x-mitre-tactic",
        "x-mitre-matrix",
        "course-of-action",
    }
)


class MitreAttackFormatError(ValueError):
    """Raised when a MITRE ATT&CK STIX bundle is malformed."""


def _as_object(value: Any, context: str) -> dict[str, Any]:
    """Return a mutable dictionary for a JSON object or raise a format error."""
    if not isinstance(value, Mapping):
        raise MitreAttackFormatError(f"{context} must be an object")
    return dict(value)


def _required_string(obj: Mapping[str, Any], key: str, context: str) -> str:
    """Read a required non-blank string from a STIX object."""
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise MitreAttackFormatError(f"{context} requires a non-blank {key}")
    return value.strip()


def _optional_string(obj: Mapping[str, Any], key: str) -> str | None:
    """Read an optional string, rejecting non-string values."""
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise MitreAttackFormatError(f"{key} must be a string")
    return value


def _timestamp(obj: Mapping[str, Any], key: str, context: str) -> datetime | None:
    """Parse an optional STIX ISO timestamp into UTC."""
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise MitreAttackFormatError(f"{context} {key} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MitreAttackFormatError(
            f"{context} {key} must be an ISO timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MitreAttackFormatError(f"{context} {key} must be timezone-aware")
    return parsed.astimezone(UTC)


def _attack_id(obj: Mapping[str, Any], object_type: str) -> str:
    """Read and validate the ATT&CK identifier for a supported object."""
    value = _required_string(obj, "x_mitre_attack_id", object_type).upper()
    pattern = {
        "attack-pattern": _ATTACK_PATTERN_ID,
        "malware": _SOFTWARE_ID,
        "tool": _SOFTWARE_ID,
        "intrusion-set": _GROUP_ID,
    }[object_type]
    if pattern.fullmatch(value) is None:
        raise MitreAttackFormatError(f"{object_type} has invalid ATT&CK ID {value!r}")
    return value


def _string_list(obj: Mapping[str, Any], key: str) -> list[str]:
    """Read, validate, sort, and deduplicate a string-list property."""
    value = obj.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise MitreAttackFormatError(f"{key} must be a list of strings")
    return sorted(set(value))


def _flags(obj: Mapping[str, Any]) -> tuple[bool, bool]:
    """Return STIX revoked and ATT&CK deprecated flags."""
    revoked = obj.get("revoked", False)
    deprecated = obj.get("x_mitre_deprecated", False)
    if not isinstance(revoked, bool) or not isinstance(deprecated, bool):
        raise MitreAttackFormatError("revoked and x_mitre_deprecated must be booleans")
    return revoked, deprecated


def _url(object_type: str, attack_id: str) -> str:
    """Build the canonical public ATT&CK URL for an object."""
    collection = {
        "attack-pattern": "techniques",
        "malware": "software",
        "tool": "software",
        "intrusion-set": "groups",
    }[object_type]
    path_id = (
        attack_id.replace(".", "/") if object_type == "attack-pattern" else attack_id
    )
    return f"https://attack.mitre.org/{collection}/{path_id}"


def _tactics(obj: Mapping[str, Any]) -> list[str]:
    """Extract MITRE ATT&CK kill-chain phases deterministically."""
    phases = obj.get("kill_chain_phases", [])
    if not isinstance(phases, list):
        raise MitreAttackFormatError("kill_chain_phases must be a list")
    values: list[str] = []
    for phase in phases:
        phase_obj = _as_object(phase, "kill_chain_phases entry")
        if phase_obj.get("kill_chain_name") != "mitre-attack":
            continue
        values.append(_required_string(phase_obj, "phase_name", "kill_chain phase"))
    return sorted(set(values))


def _base_record_values(
    obj: Mapping[str, Any],
    record_type: str,
    attack_id: str | None,
    retrieved_at: datetime,
    source_id: str,
) -> dict[str, Any]:
    """Build common SourceRecord fields for one STIX object."""
    object_id = _required_string(obj, "id", "STIX object")
    object_type = _required_string(obj, "type", "STIX object")
    return {
        "source_id": source_id,
        "source_record_id": object_id,
        "record_type": record_type,
        "normalization_version": NORMALIZATION_VERSION,
        "published_at": _timestamp(obj, "modified", object_type),
        "retrieved_at": retrieved_at,
        "canonical_payload": {},
        "raw_payload": dict(obj),
        "metadata": {"stix_type": object_type, "attack_id": attack_id},
    }


def _entity_payload(
    obj: Mapping[str, Any], object_type: str, attack_id: str
) -> tuple[str, dict[str, Any]]:
    """Normalize a supported ATT&CK entity and return its record type/payload."""
    name = _required_string(obj, "name", object_type)
    description = _optional_string(obj, "description") or ""
    revoked, deprecated = _flags(obj)

    if object_type == "attack-pattern":
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
        if not isinstance(is_subtechnique, bool):
            raise MitreAttackFormatError("x_mitre_is_subtechnique must be a boolean")
        return RECORD_TYPE_TECHNIQUE, {
            "attack_id": attack_id,
            "name": name,
            "description": description,
            "url": _url(object_type, attack_id),
            "is_subtechnique": is_subtechnique,
            "tactics": _tactics(obj),
            "platforms": _string_list(obj, "x_mitre_platforms"),
            "revoked": revoked,
            "deprecated": deprecated,
        }

    if object_type in {"malware", "tool"}:
        return RECORD_TYPE_SOFTWARE, {
            "attack_id": attack_id,
            "name": name,
            "description": description,
            "url": _url(object_type, attack_id),
            "software_kind": object_type,
            "platforms": _string_list(obj, "x_mitre_platforms"),
            "revoked": revoked,
            "deprecated": deprecated,
        }

    return RECORD_TYPE_GROUP, {
        "attack_id": attack_id,
        "name": name,
        "description": description,
        "url": _url(object_type, attack_id),
        "aliases": _string_list(obj, "aliases"),
        "revoked": revoked,
        "deprecated": deprecated,
    }


def _endpoint_values(
    obj_value: Mapping[str, Any] | None,
) -> tuple[str | None, str | None, str | None]:
    """Return an endpoint's type, ATT&CK ID, and name when available."""
    if obj_value is None:
        return None, None, None
    endpoint_type_value = obj_value.get("type")
    if not isinstance(endpoint_type_value, str) or not endpoint_type_value.strip():
        return None, None, None
    endpoint_type = endpoint_type_value.strip()
    endpoint_id = obj_value.get("x_mitre_attack_id")
    attack_id = (
        endpoint_id.strip().upper()
        if isinstance(endpoint_id, str) and endpoint_id.strip()
        else None
    )
    name = obj_value.get("name")
    resolved_name = name.strip() if isinstance(name, str) and name.strip() else None
    return endpoint_type, attack_id, resolved_name


def _relationship_payload(
    obj: Mapping[str, Any], objects_by_id: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Normalize one STIX relationship and resolve known endpoints."""
    relationship_type = _required_string(obj, "relationship_type", "relationship")
    source_stix_id = _required_string(obj, "source_ref", "relationship")
    target_stix_id = _required_string(obj, "target_ref", "relationship")
    source_obj = objects_by_id.get(source_stix_id)
    target_obj = objects_by_id.get(target_stix_id)
    source_type, source_attack_id, source_name = _endpoint_values(source_obj)
    target_type, target_attack_id, target_name = _endpoint_values(target_obj)
    relationship_urn = (
        "urn:ati:relationship:attack:uses_technique"
        if relationship_type == "uses" and target_type == "attack-pattern"
        else "urn:ati:relationship:threat:associated_with"
    )
    return {
        "relationship_urn": relationship_urn,
        "stix_relationship_type": relationship_type,
        "source_stix_id": source_stix_id,
        "source_stix_type": source_type,
        "source_attack_id": source_attack_id,
        "source_name": source_name,
        "target_stix_id": target_stix_id,
        "target_stix_type": target_type,
        "target_attack_id": target_attack_id,
        "target_name": target_name,
    }


def _validate_objects(
    objects: Sequence[Mapping[str, Any]],
) -> list[tuple[dict[str, Any], str, str]]:
    """Snapshot objects and validate the identity required on every STIX object."""
    validated: list[tuple[dict[str, Any], str, str]] = []
    for index, value in enumerate(objects):
        obj = _as_object(value, f"STIX object {index}")
        context = f"STIX object {index}"
        validated.append(
            (
                obj,
                _required_string(obj, "id", context),
                _required_string(obj, "type", context),
            )
        )
    return validated


def normalize_stix_objects(
    objects: Sequence[Mapping[str, Any]],
    retrieved_at: datetime,
    source_id: str = SourceId.MITRE_ATTACK.value,
) -> list[SourceRecord]:
    """Normalize STIX 2.1 objects into deterministic immutable source records."""
    if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
        raise MitreAttackFormatError("retrieved_at must be timezone-aware")
    retrieved_at = retrieved_at.astimezone(UTC)
    validated = _validate_objects(objects)
    objects_by_id = {
        object_id: obj
        for obj, object_id, object_type in validated
        if object_type in _HANDLED_TYPES and object_type != "relationship"
    }
    records: list[SourceRecord] = []
    for obj, _object_id, object_type in validated:
        if object_type in _SKIPPED_TYPES or object_type not in _HANDLED_TYPES:
            continue
        if object_type == "relationship":
            payload = _relationship_payload(obj, objects_by_id)
            values = _base_record_values(
                obj, RECORD_TYPE_RELATIONSHIP, None, retrieved_at, source_id
            )
        else:
            attack_id = _attack_id(obj, object_type)
            record_type, payload = _entity_payload(obj, object_type, attack_id)
            values = _base_record_values(
                obj, record_type, attack_id, retrieved_at, source_id
            )
        values["canonical_payload"] = payload
        records.append(SourceRecord(**values))
    return records


def _parse_bundle(content: bytes) -> list[Mapping[str, Any]]:
    """Decode and validate the top-level STIX bundle envelope."""
    try:
        parsed = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MitreAttackFormatError("artifact is not valid UTF-8 JSON") from exc
    bundle = _as_object(parsed, "STIX bundle")
    if bundle.get("type") != "bundle":
        raise MitreAttackFormatError("STIX artifact type must be bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise MitreAttackFormatError("STIX bundle objects must be a list")
    return objects


def _checkpoint_index(checkpoint: str | None, total: int) -> int:
    """Validate an opaque source checkpoint and return its record index."""
    if checkpoint is None:
        return 0
    match = _CHECKPOINT.fullmatch(checkpoint)
    if match is None:
        raise ValueError("invalid MITRE ATT&CK checkpoint")
    index = int(match.group(1))
    if index > total:
        raise ValueError("MITRE ATT&CK checkpoint exceeds record count")
    return index


class MitreAttackBatchSource(BatchSource):  # pylint: disable=too-few-public-methods
    """Read and checkpoint a MITRE ATT&CK STIX 2.1 artifact."""

    source_id = SourceId.MITRE_ATTACK.value
    normalization_version = NORMALIZATION_VERSION
    capabilities = frozenset({CHECKPOINTING})

    def __init__(self, object_store: ObjectStore, batch_size: int = 100) -> None:
        """Create a source using an injected artifact store and bounded batches."""
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        self._object_store = object_store
        self._batch_size = batch_size

    def batches(
        self, artifact: ArtifactReference, checkpoint: str | None = None
    ) -> AsyncIterator[SourceBatch]:
        """Read, normalize, and yield bounded ATT&CK record batches."""

        async def generate() -> AsyncIterator[SourceBatch]:
            """Generate source batches without holding a database transaction."""
            if artifact.source_id != self.source_id:
                raise ValueError(
                    "artifact source_id does not match MITRE ATT&CK source"
                )
            content = await self._object_store.read(artifact.uri)
            objects = await asyncio.to_thread(_parse_bundle, content)
            records = normalize_stix_objects(
                objects, artifact.retrieved_at, self.source_id
            )
            if not records:
                raise MitreAttackFormatError("bundle contains no ingestible objects")
            start = _checkpoint_index(checkpoint, len(records))
            for offset in range(start, len(records), self._batch_size):
                batch_records = tuple(records[offset : offset + self._batch_size])
                end = offset + len(batch_records)
                yield SourceBatch(
                    batch_records,
                    checkpoint=f"index:{end}",
                    complete=end == len(records),
                )

        return generate()
