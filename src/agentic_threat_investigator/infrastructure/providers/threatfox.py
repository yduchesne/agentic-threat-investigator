# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ThreatFox provider for IOC-to-malware threat-intelligence evidence.

Queries the official abuse.ch ThreatFox Community API v1 ``search_ioc``
endpoint (``https://threatfox-api.abuse.ch/api/v1/``) with ``Auth-Key``
header authentication, ``exact_match=true``, and strict response
validation via the extracted PR 27C ThreatFox semantic parser
(``infrastructure.datasources.threatfox_semantics``), and normalizes the
validated matching records into immutable ``THREAT_INTELLIGENCE``
evidence. Provider confidence levels, threat types, timestamps, and
references are retained as source facts only: the provider never assesses
maliciousness, never weights assessment confidence, never persists, never
creates relationships, and never instantiates discovered entities. The
normalized ``matches`` facts carry the validated ThreatFox machine malware
identifier and printable name so a deterministic persistence-boundary
extractor can later derive the canonical ``MALWARE`` entity and the
queried IOC ``ASSOCIATED_WITH`` malware relationship. A no-result response
is an empty result, never a benign assessment.

This legacy provider remains the transitional pre-PR27D Evidence path: it
reuses the extracted semantic parser and maps its typed outcome onto
``ProviderResult``. Evidence-specific construction (``_build_match_facts``
and ``format_threatfox_fact_timestamp``) intentionally stays in this
module, outside the semantic module.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderErrorCode,
    ProviderResult,
    normalize_retrieval_timestamp,
    provider_error_result,
    validate_investigation_entity,
)
from agentic_threat_investigator.domain.entities import (
    Entity,
    EntityType,
)
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
    parse_source_ip_ioc,
    parse_threatfox_response,
    record_matches_query,
)
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient

_THREATFOX_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"
"""Fixed ThreatFox Community API v1 authority; the JSON body carries the query."""

# PR 27C compatibility re-exports: the strict ThreatFox semantic model and
# matching helpers now live in the format-specific semantic module and are
# re-exported here so the legacy provider contract (and its tests) remain
# import-stable. They are the same objects, never duplicated copies.
__all__ = [
    "ThreatFoxProvider",
    "ThreatFoxRecord",
    "parse_source_ip_ioc",
    "record_matches_query",
    "format_threatfox_fact_timestamp",
]


@dataclass(frozen=True)
class _SearchContext:
    """Invocation context for one ``search_ioc`` normalization pass."""

    investigation_id: UUID
    entity: Entity
    canonical_value: str
    retrieved_at: datetime


class ThreatFoxProvider(EvidenceProvider):
    """Provider using the ThreatFox Community API v1 ``search_ioc`` query."""

    def __init__(
        self,
        http_client: ProviderHttpClient,
        *,
        auth_key: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the provider with an HTTP client and a resolved key.

        The HTTP client is owned by the caller. ``auth_key`` must be the
        abuse.ch Auth-Key already resolved during composition/bootstrap;
        the provider never reads configuration or the environment and the
        value is used only in the ``Auth-Key`` header, never in URLs,
        bodies, facts, errors, or logs. The UTC wall clock is used only
        for Evidence ``retrieved_at`` timestamps; tests may inject a
        deterministic replacement, otherwise ``datetime.now(UTC)`` is
        used.
        """
        if not auth_key.strip():
            raise ValueError("ThreatFox Auth-Key must not be blank")
        self._http = http_client
        self._auth_key = auth_key.strip()
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def id(self) -> str:
        """Return the stable ``urn:ati:source:threatfox`` identifier."""
        return SourceId.THREATFOX.value

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to domain and IP-address entities.

        URL entities are unsupported: ATI has no approved URL
        canonicalization or exact URL identity contract yet.
        """
        return entity.type in (EntityType.DOMAIN, EntityType.IP_ADDRESS)

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Retrieve ThreatFox IOC facts for one supported entity.

        The shared validation helper rejects unsupported entity types and
        uncanonicalizable values before any HTTP I/O. A successful search
        emits exactly one immutable ``THREAT_INTELLIGENCE`` evidence
        observation carrying every validated matching record; a valid
        no-result emits an empty result and is not a benign assessment; a
        malformed response yields one typed error and no evidence. The
        provider never persists, creates relationships, instantiates
        discovered entities, or assesses maliciousness.
        """
        validation = validate_investigation_entity(self, entity)
        rejection = validation[1]
        if rejection is not None:
            return rejection
        canonical_value = validation[0]
        assert canonical_value is not None
        return await self._search(
            investigation_id=investigation_id,
            entity=entity,
            canonical_value=canonical_value,
            retrieved_at=normalize_retrieval_timestamp(self._clock),
        )

    async def _search(
        self,
        *,
        investigation_id: UUID,
        entity: Entity,
        canonical_value: str,
        retrieved_at: datetime,
    ) -> ProviderResult:
        """Query ``search_ioc`` and normalize one grouped evidence observation."""
        outcome = await self._http.request_json(
            "POST",
            _THREATFOX_ENDPOINT,
            # The JSON body carries the search; the Auth-Key travels only in
            # its dedicated header and never in the URL or body.
            json_body={
                "query": "search_ioc",
                "search_term": canonical_value,
                "exact_match": True,
            },
            headers={"Auth-Key": self._auth_key},
        )

        if outcome.final_error_code is not None:
            return provider_error_result(
                self.id,
                outcome.final_error_code,
                outcome.final_error_message or "ThreatFox request failed",
                retry_after_seconds=outcome.retry_after_seconds,
            )

        return self._normalize_search_response(
            outcome.response_json,
            _SearchContext(
                investigation_id=investigation_id,
                entity=entity,
                canonical_value=canonical_value,
                retrieved_at=retrieved_at,
            ),
        )

    def _normalize_search_response(
        self, response_json: Any, context: _SearchContext
    ) -> ProviderResult:
        """Normalize one grouped evidence from the validated ThreatFox semantics.

        The extracted semantic parser validates the envelope, every record,
        query matching, and duplicate rules fail-closed; this method maps the
        typed outcome onto the legacy Evidence path. The body-encoded
        ``ratelimited`` status maps to the typed rate-limit error; any other
        semantic failure becomes one non-retryable INVALID_RESPONSE error.
        """
        semantic = parse_threatfox_response(
            response_json,
            entity_type=context.entity.type,
            canonical_value=context.canonical_value,
        )
        if semantic.error is not None:
            if semantic.error.code == "rate_limited":
                return provider_error_result(
                    self.id, ProviderErrorCode.RATE_LIMITED, "rate limited"
                )
            return _malformed_result(self.id, "invalid ThreatFox response")
        if not semantic.records:
            # A valid no-result is an empty result, never a benign assessment.
            return ProviderResult(provider=self.id)

        subject = EvidenceEntityRef(
            id=context.entity.id,
            type=context.entity.type,
            value=context.canonical_value,
        )
        evidence = Evidence(
            investigation_id=context.investigation_id,
            type=EvidenceType.THREAT_INTELLIGENCE,
            subject=subject,
            source=self.id,
            source_url=_THREATFOX_ENDPOINT,
            observed_at=max(
                record.last_seen if record.last_seen is not None else record.first_seen
                for record in semantic.records
            ),
            retrieved_at=context.retrieved_at,
            facts={
                "matches": [_build_match_facts(record) for record in semantic.records]
            },
            raw_payload=None,
        )
        return ProviderResult(provider=self.id, evidence=(evidence,))


def _malformed_result(provider_id: str, message: str) -> ProviderResult:
    """Build a standard non-retryable ``INVALID_RESPONSE`` failure result."""
    return provider_error_result(
        provider_id, ProviderErrorCode.INVALID_RESPONSE, message
    )


def format_threatfox_fact_timestamp(value: datetime) -> str:
    """Format an already validated timezone-aware UTC datetime as ``...Z``.

    Normalized ThreatFox fact timestamps use the canonical UTC ISO 8601
    form ending in ``Z``, for example ``2026-08-20T12:00:00Z``.
    """
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_match_facts(record: ThreatFoxRecord) -> dict[str, Any]:
    """Build one normalized match fact object from a validated record.

    Each match contains exactly the approved handoff keys. The malware
    machine identifier is retained verbatim as the canonical identity
    input for later deterministic entity discovery; the printable name is
    display metadata only. Timestamps are normalized to UTC ISO 8601,
    source order is preserved, and no derived risk labels, verdicts, or
    confidence weightings are ever synthesized.
    """
    return {
        "threatfox_id": record.id,
        "ioc": record.ioc,
        "ioc_type": record.ioc_type,
        "threat_type": record.threat_type,
        "threat_type_description": record.threat_type_desc,
        "malware": record.malware,
        "malware_printable": record.malware_printable,
        "confidence_level": record.confidence_level,
        "first_seen": format_threatfox_fact_timestamp(record.first_seen),
        "last_seen": (
            None
            if record.last_seen is None
            else format_threatfox_fact_timestamp(record.last_seen)
        ),
        "reference": record.reference,
        "tags": None if record.tags is None else list(record.tags),
    }
