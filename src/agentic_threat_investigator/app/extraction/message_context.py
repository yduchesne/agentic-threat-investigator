# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Consumer-side extraction input built from durable Evidence-message content (PR 28E).

The durable log stores source Evidence (:class:`EvidenceMessage`), never
derived graph state. Before the PR 28E batch consumer can run the existing
deterministic extractors it must reconstruct the smallest execution view
they already require (:class:`EvidenceExtractionView`): the stable
:class:`Evidence`, the material observation candidate, and the transient
provider invocation Entity. This module owns that message-to-view seam:

- exactly one supported semantic source contract today (ThreatFox);
- the invocation Entity is **execution context only** — it is never
  persisted as Evidence ownership and no subject field is added to
  ``EvidenceMessage``;
- the invocation identity is derived deterministically from the durable
  normalized fact ``matches[].ioc`` / ``matches[].ioc_type`` exactly as the
  current ThreatFox semantic contract defines it (``domain`` and ``ip:port``
  only);
- unsupported sources/evidence types and malformed facts fail closed with
  typed :class:`EvidenceExtractionError` subclasses, so an unprocessable
  message never fabricates graph structure.

The helper is pure: no database, network, broker, clock, or UnitOfWork.
Reconstruction reuses the PR 28C contract (``converted_evidence_from_message``)
and the existing extraction dispatcher; it never re-parses raw payloads and
never reimplements ThreatFox graph semantics.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.evidence_message import EvidenceMessage
from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionError,
    EvidenceExtractionView,
    ExtractionErrorReason,
)
from agentic_threat_investigator.domain.entities import (
    Entity,
    EntityType,
    canonicalize,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import ConvertedEvidence
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)

_THREATFOX_SOURCE = SourceId.THREATFOX.value
_THREATFOX_SEMANTIC_FORMAT = SemanticFormatId.THREATFOX
"""The one supported durable-message extraction source (PR 28E).

Anything else fails closed with :class:`UnsupportedMessageExtractionError`
until a source producer publishes PR 28C messages with an approved durable
extraction adapter (PR 28F owns producer migration).
"""


class UnsupportedMessageExtractionError(EvidenceExtractionError):
    """A message source/evidence type has no durable extraction adapter.

    The error is typed, bounded, and safe to surface: only the source
    identifier, the stable reason category, and the Evidence identity are
    carried; no payload content is echoed.
    """

    def __init__(self, source: str, *, evidence_id: UUID | None = None) -> None:
        """Record the safe failure context of the unsupported source."""
        super().__init__(
            source,
            ExtractionErrorReason.UNSUPPORTED_EVIDENCE_TYPE,
            "evidence message carries no durable extraction adapter",
            evidence_id=evidence_id,
        )


class MalformedMessageExtractionError(EvidenceExtractionError):
    """A supported message carries durable facts that cannot reconstruct.

    The facts violate the documented normalized shape (for example missing
    matches, a malformed or non-canonical IOC, or matches that disagree on
    the IOC identity); reconstruction fails closed with the bounded reason.
    """

    def __init__(
        self, source: str, message: str, *, evidence_id: UUID | None = None
    ) -> None:
        """Record the static message and the safe failure context."""
        super().__init__(
            source,
            ExtractionErrorReason.MALFORMED_FACTS,
            message,
            evidence_id=evidence_id,
        )


def extraction_view_from_message(
    message: EvidenceMessage,
    converted: ConvertedEvidence,
) -> EvidenceExtractionView:
    """Build the smallest extraction view one message can reconstruct.

    Only the currently supported ThreatFox semantic format is accepted; any
    other source/evidence-type combination raises
    :class:`UnsupportedMessageExtractionError`. The invocation Entity is
    derived from the durable normalized ``matches[].ioc`` facts and carries
    no ``id`` or display metadata: it is execution context only.
    """
    source = message.source_id.value
    if (
        message.semantic_format is not _THREATFOX_SEMANTIC_FORMAT
        or source != _THREATFOX_SOURCE
    ):
        raise UnsupportedMessageExtractionError(source, evidence_id=message.evidence_id)
    invocation = _threatfox_invocation_entity(message)
    return EvidenceExtractionView(
        evidence=converted.evidence,
        observation=converted.observation,
        invocation_entity=invocation,
    )


def _threatfox_invocation_entity(message: EvidenceMessage) -> Entity:
    """Derive the canonical ThreatFox IOC invocation Entity from durable facts.

    ``facts.matches`` must be a non-empty array; every match must carry a
    valid ``ioc`` and a supported ``ioc_type`` (``domain`` or ``ip:port``);
    every match must canonicalize to the **same** IOC identity (one Evidence
    item describes one IOC); and the durable identity must already be in
    canonical form. Any violation fails closed with
    :class:`MalformedMessageExtractionError`.
    """
    facts = message.facts
    matches = facts.get("matches")
    if not isinstance(matches, (list, tuple)) or not matches:
        raise MalformedMessageExtractionError(
            _THREATFOX_SOURCE,
            "ThreatFox message must carry validated matches",
            evidence_id=message.evidence_id,
        )
    identities: set[tuple[EntityType, str]] = set()
    for match in matches:
        identities.add(_match_identity(match, message.evidence_id))
    if len(identities) != 1:
        raise MalformedMessageExtractionError(
            _THREATFOX_SOURCE,
            "ThreatFox message matches disagree on the IOC identity",
            evidence_id=message.evidence_id,
        )
    entity_type, value = next(iter(identities))
    return Entity(type=entity_type, value=value)


def _match_identity(match: Any, evidence_id: UUID) -> tuple[EntityType, str]:
    """Derive the canonical IOC entity identity of one validated match fact.

    The ``ioc`` value is the durable normalized identity input; the
    ``ioc_type`` maps exactly to the ThreatFox semantic contract:
    ``domain`` -> ``EntityType.DOMAIN`` with the canonicalized domain, and
    ``ip:port`` -> ``EntityType.IP_ADDRESS`` with the canonicalized host of
    the unambiguous ``host``/``host:port``/``[v6]:port`` form. A ``url`` IOC
    is a supported semantic type that the current ThreatFox extractor cannot
    accept as an invocation subject, so it fails closed as unsupported
    rather than fabricating graph structure.
    """
    if not isinstance(match, Mapping):
        raise MalformedMessageExtractionError(
            _THREATFOX_SOURCE,
            "ThreatFox match must be an object",
            evidence_id=evidence_id,
        )
    ioc = match.get("ioc")
    ioc_type = match.get("ioc_type")
    if not isinstance(ioc, str) or not ioc:
        raise MalformedMessageExtractionError(
            _THREATFOX_SOURCE,
            "ThreatFox match carries an invalid ioc",
            evidence_id=evidence_id,
        )
    if not isinstance(ioc_type, str):
        raise MalformedMessageExtractionError(
            _THREATFOX_SOURCE,
            "ThreatFox match carries an invalid ioc_type",
            evidence_id=evidence_id,
        )
    if ioc_type == "domain":
        return _canonical_domain_identity(ioc, evidence_id)
    if ioc_type == "ip:port":
        return _canonical_ip_identity(ioc, evidence_id)
    if ioc_type == "url":
        raise UnsupportedMessageExtractionError(
            _THREATFOX_SOURCE, evidence_id=evidence_id
        )
    raise MalformedMessageExtractionError(
        _THREATFOX_SOURCE,
        "ThreatFox match carries an unsupported ioc_type",
        evidence_id=evidence_id,
    )


def _canonical_domain_identity(ioc: str, evidence_id: UUID) -> tuple[EntityType, str]:
    """Return the canonical domain identity, fail closed on non-canonical input.

    The domain is validated with the strict provider DNS-name validator the
    ThreatFox semantic contract uses (``validate_dns_name``), so a durable
    fact the semantic parser could never emit (an IP-looking string, empty
    labels, malformed IDNA, overlong names) fails closed; the durable value
    must also already equal its canonical form.
    """
    try:
        canonical = validate_dns_name(ioc)
    except ValueError as exc:
        raise MalformedMessageExtractionError(
            _THREATFOX_SOURCE,
            "ThreatFox match carries a malformed domain ioc",
            evidence_id=evidence_id,
        ) from exc
    if canonical != ioc:
        raise MalformedMessageExtractionError(
            _THREATFOX_SOURCE,
            "ThreatFox match domain ioc is not in canonical form",
            evidence_id=evidence_id,
        )
    return EntityType.DOMAIN, canonical


def _canonical_ip_identity(ioc: str, evidence_id: UUID) -> tuple[EntityType, str]:
    """Return the canonical host identity of an ``ip:port`` fact.

    The host of the unambiguous ``host``/``host:port``/``[v6]:port`` form
    must already be in canonical form (exactly as the durable normalized
    fact contract promises); any other spelling fails closed.
    """
    parsed = _parse_ip_port(ioc)
    if parsed is None:
        raise MalformedMessageExtractionError(
            _THREATFOX_SOURCE,
            "ThreatFox match carries a malformed ip:port ioc",
            evidence_id=evidence_id,
        )
    host, _port = parsed
    return EntityType.IP_ADDRESS, host


def _parse_ip_port(value: str) -> tuple[str, int | None] | None:
    """Parse one unambiguous host / host:port / [v6]:port source IOC value.

    Mirrors the documented unambiguous forms of the ThreatFox semantic
    contract: a whole value that parses as an IPv4/IPv6 address is a bare
    IP; an IPv4 ``address:port`` pair and a bracketed RFC 3986
    ``[address]:port`` pair are accepted when the port is in ``1..65535``;
    an unbracketed colon-containing value is accepted only when it parses
    as a whole bare IPv6 address — ambiguous spellings are rejected rather
    than guessed. The returned host is canonical.
    """
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1:
            return None
        host_text = value[1:closing]
        remainder = value[closing + 1 :]
        if not remainder.startswith(":"):
            return None
        try:
            port = int(remainder[1:])
        except ValueError:
            return None
        if not 1 <= port <= 65535:
            return None
        try:
            address = ipaddress.ip_address(host_text)
        except ValueError:
            return None
        if address.version != 6:
            return None
        canonical = _canonical_host(host_text)
        return None if canonical is None else (canonical, port)

    colon_count = value.count(":")
    if colon_count == 0:
        canonical = _canonical_host(value)
        return (canonical, None) if canonical is not None else None
    if colon_count == 1:
        host_text, _, port_text = value.partition(":")
        try:
            port = int(port_text)
        except ValueError:
            return None
        if not 1 <= port <= 65535:
            return None
        canonical = _canonical_host(host_text)
        return (canonical, port) if canonical is not None else None
    # Multiple colons: only a whole bare IPv6 address is unambiguous.
    canonical = _canonical_host(value)
    return (canonical, None) if canonical is not None else None


def _canonical_host(value: str) -> str | None:
    """Return the canonical IP host text, or ``None`` when malformed."""
    try:
        return canonicalize(EntityType.IP_ADDRESS, value)
    except ValueError:
        return None
