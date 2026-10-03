# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-authored synthetic MISP semantic fixtures (PR 32A).

Every payload in this module is synthetic documentation-safe test data
authored for ATI (RFC 5737 addresses, RFC 3849 ``2001:db8::`` address, RFC
2606 ``.test`` domains, and fixed synthetic UUIDs). No payload is a copied
community MISP Event and no helper contacts a live MISP service. Builders
compose the canonical MISP REST nested array-member form (``{"Attribute":
{...}}``, ``{"Object": {...}}``, ``{"ObjectReference": {...}}``,
``{"Tag": {...}}``) and accept ``**overrides`` so malformed shapes can be
authored per test.

The builders never import the production parser; they only construct plain
JSON-compatible dictionaries the production parser is then tested against.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

# Fixed synthetic UUIDs (RFC 4122 v4-shaped, documentation-safe).
EVENT_UUID = "10f8c2a0-5e54-4a0a-8b5c-2f9cc2ff3b01"
ATTRIBUTE_UUID = "21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02"
OBJECT_UUID = "32fac2a0-7e54-4a0a-ac7d-4f9cc2ff3b03"
OBJECT_ATTRIBUTE_UUID = "43fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b04"
REFERENCE_UUID = "54fcc2a0-9e54-4a0a-cd9f-6f9cc2ff3b05"

# Synthetic documentation-safe values (RFC 5737 / RFC 2606 / RFC 3849).
DOMAIN_VALUE = "malicious-domain.test"
SECONDARY_DOMAIN_VALUE = "secondary.test"
IPV4_VALUE = "203.0.113.42"
IPV6_VALUE = "2001:db8::42"

# 32B canonicalization targets: mixed-case/trailing-dot domain and IPv6
# forms that must normalize through the existing ATI canonicalizers.
MIXED_CASE_DOMAIN_VALUE = "Example.TEST."
UNICODE_DOMAIN_VALUE = "b\u00fccher.example"
EXPANDED_IPV6_VALUE = "2001:0db8:0000:0000:0000:0000:0000:0042"

# 32B compound ``domain|ip`` source values (exactly one literal ``|``).
COMPOUND_DOMAIN_IP_VALUE = "Example.TEST.|203.0.113.42"
COMPOUND_DOMAIN_IPV6_VALUE = "Example.TEST.|2001:0db8:0000:0000:0000:0000:0000:0042"

# One valid-but-unsupported 32B MISP Attribute type.
UNSUPPORTED_ATTRIBUTE_TYPE = "sha256"

# Synthetic documentation-safe MISP REST fixture constants (PR 32C).
MISP_BASE_URL = "https://misp.example.test"
MISP_REST_SEARCH_ENDPOINT = "https://misp.example.test/events/restSearch"
FIXED_KEY = "test-misp-api-key"
# Additional synthetic Event UUIDs for multi-Event REST pages (PR 32C).
SECOND_EVENT_UUID = "65fac2a0-7e54-4a0a-ac7d-4f9cc2ff3b11"
THIRD_EVENT_UUID = "76fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b12"

# Synthetic documentation-safe MISP REST timestamps (UTC Unix seconds as
# JSON strings) and ISO-8601 seen windows.
EVENT_TIMESTAMP = "1700000000"
ATTRIBUTE_TIMESTAMP = "1700000100"
OBJECT_TIMESTAMP = "1700000200"
FIRST_SEEN_ISO = "2023-11-01T00:00:00Z"
LAST_SEEN_ISO = "2023-11-02T00:00:00+00:00"


def _bind(member: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Return one canonical nested MISP array member.

    ``member`` is the field mapping and ``overrides`` replace any of its
    keys (including the wrapping model name when a test needs the direct
    member form).
    """
    merged = dict(member)
    merged.update(overrides)
    return merged


def misp_tag(name: str = "tlp:white", **overrides: Any) -> dict[str, Any]:
    """Build one synthetic MISP ``Tag`` list member."""
    fields: dict[str, Any] = {"id": "11", "name": name}
    fields.update(overrides)
    return {"Tag": fields}


def misp_event(
    *,
    attributes: tuple[dict[str, Any], ...] = (),
    objects: tuple[dict[str, Any], ...] = (),
    tags: tuple[dict[str, Any], ...] = (),
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic native MISP Event envelope ``{"Event": {...}}``."""
    fields: dict[str, Any] = {
        "id": "1",
        "uuid": EVENT_UUID,
        "info": "Synthetic MISP event for ATI documentation testing",
        "date": "2023-11-01",
        "timestamp": EVENT_TIMESTAMP,
        "published": True,
        "distribution": "0",
        "sharing_group_id": "0",
        "threat_level_id": "1",
        "analysis": "2",
    }
    if attributes:
        fields["Attribute"] = list(attributes)
    if objects:
        fields["Object"] = list(objects)
    if tags:
        fields["Tag"] = list(tags)
    fields.update(overrides)
    return {"Event": fields}


def misp_attribute(
    *,
    type_: str = "domain",
    category: str = "Network activity",
    value: str = DOMAIN_VALUE,
    uuid: str = ATTRIBUTE_UUID,
    object_relation: str | None = None,
    tags: tuple[dict[str, Any], ...] = (),
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic MISP ``Attribute`` list member (Event level)."""
    fields: dict[str, Any] = {
        "id": "21",
        "uuid": uuid,
        "type": type_,
        "category": category,
        "value": value,
        "timestamp": ATTRIBUTE_TIMESTAMP,
        "to_ids": True,
        "distribution": "1",
        "sharing_group_id": "0",
        "deleted": False,
        "comment": "",
    }
    if object_relation is not None:
        fields["object_relation"] = object_relation
    if tags:
        fields["Tag"] = list(tags)
    fields.update(overrides)
    return {"Attribute": fields}


def misp_object_attribute(
    *,
    type_: str = "filename",
    category: str = "Artifacts dropped",
    value: str = "payload.exe",
    uuid: str = OBJECT_ATTRIBUTE_UUID,
    object_relation: str | None = "filename",
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic Object-owned ``Attribute`` list member."""
    fields: dict[str, Any] = {
        "id": "31",
        "uuid": uuid,
        "type": type_,
        "category": category,
        "value": value,
        "timestamp": ATTRIBUTE_TIMESTAMP,
        "to_ids": True,
        "distribution": "5",
        "sharing_group_id": "0",
        "deleted": False,
        "comment": "",
    }
    if object_relation is not None:
        fields["object_relation"] = object_relation
    fields.update(overrides)
    return {"Attribute": fields}


def misp_object_reference(
    *,
    relationship_type: str = "includes",
    referenced_uuid: str = OBJECT_ATTRIBUTE_UUID,
    uuid: str = REFERENCE_UUID,
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic ``ObjectReference`` list member."""
    fields: dict[str, Any] = {
        "id": "41",
        "uuid": uuid,
        "relationship_type": relationship_type,
        "referenced_uuid": referenced_uuid,
        "timestamp": OBJECT_TIMESTAMP,
    }
    fields.update(overrides)
    return {"ObjectReference": fields}


def misp_object(
    *,
    name: str = "file",
    uuid: str = OBJECT_UUID,
    attributes: tuple[dict[str, Any], ...] = (),
    references: tuple[dict[str, Any], ...] = (),
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic MISP ``Object`` list member with nested children."""
    fields: dict[str, Any] = {
        "id": "51",
        "uuid": uuid,
        "name": name,
        "meta-category": "file",
        "description": "Synthetic file object",
        "template_uuid": "65fd2d2c-8f47-4a90-a48f-b8cdd0e3f234",
        "template_version": "1",
        "timestamp": OBJECT_TIMESTAMP,
        "distribution": "5",
        "sharing_group_id": "0",
        "comment": "",
        "deleted": False,
    }
    if attributes:
        fields["Attribute"] = list(attributes)
    if references:
        fields["ObjectReference"] = list(references)
    fields.update(overrides)
    return {"Object": fields}


def synthetic_uuid(seed: int) -> UUID:
    """Return one fixed documentation-safe RFC 4122 UUID from a seed."""
    return UUID(int=seed) if seed >= 0 else UUID(int=abs(seed))


def misp_rest_search(*events: dict[str, Any]) -> dict[str, Any]:
    """Build one synthetic MISP REST ``events/restSearch`` response body.

    The canonical normal JSON form verified against the current
    MISP/PyMISP contract is ``{"response": [{"Event": {...}}, ...]}``; each
    ``events`` argument is an Event envelope produced by
    :func:`misp_event`. The envelope is validated/adapted only by the
    PR 32C acquisition layer; the semantic parser never sees the search
    envelope itself.
    """
    return {"response": list(events)}


def misp_rest_event(
    *,
    uuid: str = EVENT_UUID,
    info: str = "Synthetic MISP event for ATI documentation testing",
    attributes: tuple[dict[str, Any], ...] = (),
    objects: tuple[dict[str, Any], ...] = (),
    **overrides: Any,
) -> dict[str, Any]:
    """Build one synthetic MISP Event envelope for a REST search page.

    Thin identity-scoped convenience over :func:`misp_event` so one REST
    response can carry several distinct Events with documentation-safe
    UUIDs.
    """
    return misp_event(
        uuid=uuid,
        info=info,
        attributes=attributes,
        objects=objects,
        **overrides,
    )
