# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""STIX 2.1 semantic-format parsing (PR 27C).

Parses a decoded STIX 2.1 bundle value into validated immutable
:class:`Stix21Object` typed objects after transport and serialization
decoding. This module owns only the small STIX envelope/object identity
contract (mapping object, nonblank ``type``/``id``, optional string
``spec_version``) plus deep immutable snapshots that preserve every
extension field (including ``x_mitre_*``) as data. It is independent of
MITRE ATT&CK ``SourceRecord`` normalization and of ATI Evidence; full STIX
2.1 domain semantics are deliberately not reimplemented. The MITRE batch
source may consume this parser as its decoded-value boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationError,
    field_validator,
    model_validator,
)

from agentic_threat_investigator.domain.immutable_json import (
    freeze_mapping,
    thaw_json,
)


class Stix21SemanticError(ValueError):
    """Raised when a decoded STIX 2.1 value violates the semantic contract."""


class Stix21Object(BaseModel):
    """One validated immutable STIX 2.1 object preserved in source form.

    Only the identity contract is validated: the object must be a mapping
    with a nonblank ``type`` and ``id``; ``spec_version`` is an optional
    string validated only to the extent justified by the STIX 2.1 contract.
    Every other member, including nested source values and extension fields
    such as ``x_mitre_attack_id`` or ``x_mitre_deprecated``, is preserved
    verbatim as deeply immutable data and never executed. Parsing snapshots
    the input, so later caller mutation of the original dict cannot reach
    the validated object.
    """

    model_config = ConfigDict(extra="allow", frozen=True, strict=True)

    type: str
    id: str
    spec_version: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _snapshot_source(cls, data: Any) -> Any:
        """Snapshot mapping input into a deeply immutable copy before validation.

        Non-mapping input is passed through so Pydantic records the precise
        shape error; mappings are frozen so nested source values can never
        be shared mutable state with the caller.
        """
        if isinstance(data, Mapping):
            return freeze_mapping(data)
        return data

    @field_validator("type", "id", mode="before")
    @classmethod
    def _validate_identity(cls, value: object) -> str:
        """Require a nonblank source string identity member."""
        if not isinstance(value, str) or not value.strip():
            raise ValueError("STIX object type and id must be nonblank strings")
        return value

    def source_value(self) -> dict[str, Any]:
        """Return a mutable deep copy of the full validated source object.

        The returned value is a plain JSON-compatible dict (thawed), safe
        for consumers that normalize from a mutable mapping; the model
        itself stays immutable.
        """
        dumped = thaw_json(self.model_dump(mode="python"))
        assert isinstance(dumped, dict)
        return dumped


def parse_stix21_bundle(decoded: object) -> tuple[Stix21Object, ...]:
    """Parse a decoded STIX 2.1 bundle value into validated typed objects.

    Requires a mapping bundle whose ``type`` is ``bundle`` with an array
    ``objects``; every entry must be a mapping with a nonblank ``type`` and
    ``id``. Objects are returned in source order with extension fields
    preserved. The parser accepts a decoded value — never raw bytes — and
    performs no network/DB/persistence I/O.
    """
    if not isinstance(decoded, Mapping):
        raise Stix21SemanticError("STIX bundle must be a decoded JSON object")
    if decoded.get("type") != "bundle":
        raise Stix21SemanticError("STIX bundle type must be 'bundle'")
    objects = decoded.get("objects")
    if not isinstance(objects, list):
        raise Stix21SemanticError("STIX bundle objects must be a list")
    parsed: list[Stix21Object] = []
    for index, entry in enumerate(objects):
        if not isinstance(entry, Mapping):
            raise Stix21SemanticError(f"STIX bundle object {index} must be an object")
        try:
            parsed.append(Stix21Object.model_validate(entry))
        except ValidationError as exc:
            raise Stix21SemanticError(f"invalid STIX bundle object {index}") from exc
    return tuple(parsed)


__all__ = [
    "Stix21Object",
    "Stix21SemanticError",
    "parse_stix21_bundle",
]
