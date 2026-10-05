# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic human-readable Evidence descriptions (PR 35-1 Part 1).

The public Evidence list needs a concise, deterministic characterization of
one exact admitted observation so an analyst can distinguish otherwise
similar rows (for example the four Fake World ``update-package.test`` DNS
records). This module is a pure presentation helper at the API boundary:

- it consumes only already-normalized :class:`EvidenceReadItem` state;
- it never reads raw provider payloads, performs I/O, calls an LLM, or
  touches the database;
- it dispatches on the typed ``EvidenceType`` and known normalized fields,
  never on arbitrary dictionary insertion order;
- every value is bounded so a list render can never be overwhelmed.

The result is presentation metadata only. The authoritative normalized
``facts`` are unchanged and remain the single source of Evidence semantics.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentic_threat_investigator.app.query.evidence import EvidenceReadItem
from agentic_threat_investigator.domain.evidence import EvidenceType

_MAX_DESCRIPTION_LENGTH = 240
_MAX_DNS_ANSWERS = 3
_MAX_TXT_LENGTH = 120

_TYPE_FALLBACKS: dict[EvidenceType, str] = {
    EvidenceType.DNS: "DNS observation",
    EvidenceType.REGISTRATION: "Registration observation",
    EvidenceType.NETWORK: "Network observation",
    EvidenceType.GEOLOCATION: "Geolocation observation",
    EvidenceType.REPUTATION: "Reputation observation",
    EvidenceType.THREAT_INTELLIGENCE: "Threat intelligence observation",
    EvidenceType.VULNERABILITY: "Vulnerability observation",
    EvidenceType.THREAT_RESEARCH: "Threat research observation",
}


def evidence_description(item: EvidenceReadItem) -> str:
    """Return the bounded deterministic description of one admitted observation."""
    facts = item.observation.facts
    evidence_type = item.evidence.type
    if evidence_type is EvidenceType.DNS:
        description = _dns_description(facts)
    elif evidence_type is EvidenceType.THREAT_INTELLIGENCE:
        description = _threat_intelligence_description(facts)
    elif evidence_type is EvidenceType.REGISTRATION:
        description = _registration_description(facts)
    elif evidence_type is EvidenceType.NETWORK:
        description = _network_description(facts)
    elif evidence_type is EvidenceType.REPUTATION:
        description = _reputation_description(facts)
    else:
        description = None
    if description is None:
        description = _TYPE_FALLBACKS.get(evidence_type, "Evidence observation")
    return _bounded(description)


def _dns_description(facts: Mapping[str, Any]) -> str | None:
    """Describe the normalized DNS query/answer semantics."""
    query_type = _as_str(facts.get("query_type"))
    answers = facts.get("answers")
    if (
        query_type is None
        or not isinstance(answers, (list, tuple))
        or len(answers) == 0
    ):
        return None
    normalized_type = query_type.upper()
    if normalized_type == "MX":
        return _dns_mx(answers)
    if normalized_type == "NS":
        return _dns_single(answers, "NS")
    if normalized_type == "TXT":
        return _dns_txt(answers)
    return _dns_chain(facts, normalized_type, answers)


def _dns_chain(
    facts: Mapping[str, Any],
    query_type: str,
    answers: list[Any] | tuple[Any, ...],
) -> str | None:
    """Describe an address/CNAME resolution chain from the query name onward."""
    nodes: list[str] = []
    query_name = _as_str(facts.get("query_name"))
    if query_name is not None:
        nodes.append(query_name)
    for answer in answers:
        record = _as_mapping(answer)
        if record is None:
            continue
        target = _dns_target(record)
        if target is not None:
            nodes.append(target)
    if not nodes:
        return None
    limit = _MAX_DNS_ANSWERS + 1
    extra = max(0, len(nodes) - limit)
    shown = nodes[:limit]
    suffix = f" (+{extra} more)" if extra else ""
    return _bounded(f"{query_type}: {' -> '.join(shown)}{suffix}")


def _dns_mx(answers: list[Any] | tuple[Any, ...]) -> str | None:
    """Describe MX exchange hosts with their deterministic preference."""
    parts: list[str] = []
    total = 0
    for answer in answers:
        record = _as_mapping(answer)
        if record is None:
            continue
        exchange = _as_str(record.get("exchange")) or _as_str(record.get("value"))
        if exchange is None:
            continue
        total += 1
        if len(parts) >= _MAX_DNS_ANSWERS:
            continue
        preference = _as_int(record.get("preference"))
        parts.append(
            exchange if preference is None else f"{exchange} (priority {preference})"
        )
    if not parts:
        return None
    extra = max(0, total - len(parts))
    suffix = f" (+{extra} more)" if extra else ""
    return _bounded(f"MX: {', '.join(parts)}{suffix}")


def _dns_single(answers: list[Any] | tuple[Any, ...], label: str) -> str | None:
    """Describe name-server (or equivalent single-value) answers."""
    parts: list[str] = []
    total = 0
    for answer in answers:
        record = _as_mapping(answer)
        if record is None:
            continue
        value = _as_str(record.get("value")) or _as_str(record.get("exchange"))
        if value is None:
            continue
        total += 1
        if len(parts) < _MAX_DNS_ANSWERS:
            parts.append(value)
    if not parts:
        return None
    extra = max(0, total - len(parts))
    suffix = f" (+{extra} more)" if extra else ""
    return _bounded(f"{label}: {', '.join(parts)}{suffix}")


def _dns_txt(answers: list[Any] | tuple[Any, ...]) -> str | None:
    """Describe TXT answers with a bounded readable value."""
    parts: list[str] = []
    total = 0
    for answer in answers:
        record = _as_mapping(answer)
        if record is None:
            continue
        value = _as_str(record.get("value"))
        if value is None:
            continue
        total += 1
        if len(parts) < _MAX_DNS_ANSWERS:
            parts.append(value[:_MAX_TXT_LENGTH])
    if not parts:
        return None
    extra = max(0, total - len(parts))
    suffix = f" (+{extra} more)" if extra else ""
    return _bounded(f"TXT: {', '.join(parts)}{suffix}")


def _dns_target(record: Mapping[str, Any]) -> str | None:
    """Return the semantic target of one normalized DNS answer record."""
    exchange = _as_str(record.get("exchange"))
    if exchange is not None:
        preference = _as_int(record.get("preference"))
        return exchange if preference is None else f"{exchange} (priority {preference})"
    return _as_str(record.get("value"))


def _threat_intelligence_description(facts: Mapping[str, Any]) -> str | None:
    """Describe the first normalized threat-intelligence match."""
    matches = facts.get("matches")
    if not isinstance(matches, (list, tuple)) or len(matches) == 0:
        return None
    match = _as_mapping(matches[0])
    if match is None:
        return None
    ioc = _as_str(match.get("ioc"))
    ioc_type = _as_str(match.get("ioc_type"))
    malware = _as_str(match.get("malware_printable")) or _as_str(match.get("malware"))
    threat_type = _as_str(match.get("threat_type_description")) or _as_str(
        match.get("threat_type")
    )
    confidence = _as_int(match.get("confidence_level"))
    parts: list[str] = []
    if ioc is not None and ioc_type is not None:
        parts.append(f"{ioc_type} {ioc}")
    elif ioc is not None:
        parts.append(ioc)
    if malware is not None:
        parts.append(malware)
    if threat_type is not None:
        parts.append(threat_type)
    if confidence is not None:
        parts.append(f"confidence {confidence}")
    if not parts:
        return None
    return _bounded(f"Threat intelligence: {'; '.join(parts)}")


def _registration_description(facts: Mapping[str, Any]) -> str | None:
    """Describe a normalized registration record."""
    object_class = _as_str(facts.get("object_class_name"))
    handle = _as_str(facts.get("handle"))
    registrar = _as_str(facts.get("registrar"))
    identity_parts = [part for part in (object_class, handle) if part is not None]
    if not identity_parts and registrar is None:
        return None
    head = " ".join(identity_parts) if identity_parts else "registration"
    if registrar is not None:
        return _bounded(f"Registration: {head} (registrar {registrar})")
    return _bounded(f"Registration: {head}")


def _network_description(facts: Mapping[str, Any]) -> str | None:
    """Describe a normalized network/prefix record."""
    object_class = _as_str(facts.get("object_class_name"))
    handle = _as_str(facts.get("handle"))
    cidrs: list[str] = []
    raw_cidrs = facts.get("cidr0_cidrs")
    if isinstance(raw_cidrs, (list, tuple)):
        for raw_cidr in raw_cidrs:
            cidr = _as_mapping(raw_cidr)
            if cidr is None:
                continue
            prefix = _as_str(cidr.get("prefix"))
            length = _as_int(cidr.get("length"))
            if prefix is None or length is None:
                continue
            cidrs.append(f"{prefix}/{length}")
    identity_parts = [part for part in (object_class, handle) if part is not None]
    if not identity_parts and not cidrs:
        return None
    head = " ".join(identity_parts) if identity_parts else "network"
    if cidrs:
        return _bounded(f"Network: {head}; {', '.join(cidrs[:_MAX_DNS_ANSWERS])}")
    return _bounded(f"Network: {head}")


def _reputation_description(facts: Mapping[str, Any]) -> str | None:
    """Describe a normalized reputation record."""
    score = _as_int(facts.get("abuse_confidence_score"))
    reports = _as_int(facts.get("total_reports"))
    country = _as_str(facts.get("country_code"))
    parts: list[str] = []
    if score is not None:
        parts.append(f"abuse confidence {score}")
    if reports is not None:
        parts.append(f"{reports} reports")
    if country is not None:
        parts.append(country)
    if not parts:
        return None
    return _bounded(f"Reputation: {'; '.join(parts)}")


def _as_mapping(value: Any) -> Mapping[str, Any] | None:
    """Return one JSON object value, or ``None`` when the shape is unexpected."""
    return value if isinstance(value, Mapping) else None


def _as_str(value: Any) -> str | None:
    """Return one non-blank string value, or ``None``."""
    if isinstance(value, str) and value.strip() != "":
        return value
    return None


def _as_int(value: Any) -> int | None:
    """Return one strict integer value (booleans excluded), or ``None``."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return int(value)


def _bounded(text: str) -> str:
    """Truncate one description to the public presentation bound."""
    if len(text) <= _MAX_DESCRIPTION_LENGTH:
        return text
    return text[: _MAX_DESCRIPTION_LENGTH - 1].rstrip() + "…"
