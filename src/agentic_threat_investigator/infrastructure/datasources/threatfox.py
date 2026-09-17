# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ThreatFox acquisition-to-semantic reference path (PR 27C).

A narrow production datasource acquirer that retrieves one ThreatFox
``search_ioc`` response through the existing bounded :class:`ProviderHttpClient`,
parses it with the extracted ThreatFox semantic parser, and emits validated
source-native :class:`ThreatFoxRecord` objects plus a cross-cutting
:class:`SemanticSourceContext`. It is **not** an ``EvidenceProvider`` and
constructs no ATI Evidence (PR 27D owns conversion).

The acquirer validates the explicit datasource dimensions against the fixed
ThreatFox contract (THREATFOX source, HTTPS protocol, JSON serialization,
THREATFOX semantics) before any I/O and fails closed on mismatch. Each
operational lifecycle stage is appended through the injected PR 27B
:class:`DatasourceExecutionRecorder` in its own short committed transaction;
no database transaction is ever held across the HTTP request or the semantic
parse. The Auth-Key travels only in the ``Auth-Key`` header and never in
URLs, provenance, logs, or error text.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TypeVar

from agentic_threat_investigator.app.datasource_execution import (
    DatasourceExecutionRecorder,
)
from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    DatasourceStageError,
    SemanticAcquisitionResult,
    SemanticSourceContext,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.entities import (
    Entity,
    EntityType,
    canonicalize_ip_address,
    validate_dns_name,
)
from agentic_threat_investigator.domain.identifiers import SemanticFormatId, SourceId
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
    parse_threatfox_response,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    HttpOutcome,
    ProviderHttpClient,
)

_THREATFOX_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"
"""Fixed ThreatFox Community API v1 authority; mirrors the legacy provider.

The official endpoint is acquisition configuration for the ThreatFox
datasource; the legacy ``EvidenceProvider`` keeps its own private copy until
PR 27E migrates it to this path.
"""

_THREATFOX_ERROR_CODE_BY_PROVIDER_CODE = {
    "timeout": "timeout",
    "rate_limited": "rate_limited",
    "authentication_failed": "authentication_failed",
    "forbidden": "forbidden",
    "not_found": "not_found",
    "provider_unavailable": "provider_unavailable",
}
"""Stable bounded terminal codes for deterministic HTTP failure classes."""


def canonicalize_threatfox_search_value(entity: Entity) -> str | None:
    """Return the canonical search value of a supported entity, or ``None``.

    Mirrors the legacy provider's supported set (``DOMAIN`` minus malformed
    DNS names, and ``IP_ADDRESS``) without any Evidence dependency. A
    documented ``None`` means the entity is unsupported or uncanonicalizable.
    """
    if entity.type is EntityType.DOMAIN:
        try:
            return validate_dns_name(entity.value)
        except ValueError:
            return None
    if entity.type is EntityType.IP_ADDRESS:
        try:
            return canonicalize_ip_address(entity.value)
        except ValueError:
            return None
    return None


def _outcome_error(outcome: HttpOutcome) -> DatasourceStageError:
    """Map one typed HTTP failure outcome to a bounded stage-aware error.

    The stage comes from the typed ``final_error_stage`` (never from
    matching ``final_error_message`` text); serialization-class failures use
    the bounded ``serialization_failed`` code, all other failures use the
    mapped acquisition code.
    """
    code = outcome.final_error_code
    assert code is not None
    stage = (
        DatasourceStage.SERIALIZATION
        if outcome.final_error_stage is DatasourceStage.SERIALIZATION
        else DatasourceStage.ACQUISITION
    )
    if code.value in _THREATFOX_ERROR_CODE_BY_PROVIDER_CODE:
        terminal_code = _THREATFOX_ERROR_CODE_BY_PROVIDER_CODE[code.value]
    elif stage is DatasourceStage.SERIALIZATION:
        terminal_code = "serialization_failed"
    else:
        terminal_code = "acquisition_failed"
    return DatasourceStageError(
        stage=stage,
        code=terminal_code,
        retryable=code.retryable,
        retry_after_seconds=outcome.retry_after_seconds,
    )


T = TypeVar("T")


class ThreatFoxDatasource:
    """Production ThreatFox acquisition-to-semantic datasource acquirer."""

    def __init__(
        self,
        http_client: ProviderHttpClient,
        *,
        auth_key: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the acquirer with an owned HTTP client and a resolved key.

        ``auth_key`` must already be resolved during composition; the value
        is used only in the ``Auth-Key`` header, never in URLs, bodies,
        context, or logs. The UTC clock stamps the semantic retrieval time;
        tests may inject a deterministic replacement.
        """
        if not auth_key.strip():
            raise ValueError("ThreatFox Auth-Key must not be blank")
        self._http = http_client
        self._auth_key = auth_key.strip()
        self._clock = clock or (lambda: datetime.now(UTC))

    @staticmethod
    def _validate_definition(definition: DatasourceDefinition) -> None:
        """Fail closed unless the definition matches the ThreatFox contract.

        No mismatch is inferred, repaired, or silently accepted: the
        datasource must declare THREATFOX source, HTTPS protocol, JSON
        serialization, and ThreatFox semantic format.
        """
        if definition.source_id is not SourceId.THREATFOX:
            raise ValueError("definition source_id must be THREATFOX")
        if definition.protocol is not DatasourceProtocol.HTTPS:
            raise ValueError("definition protocol must be HTTPS")
        if definition.serialization_format is not SerializationFormat.JSON:
            raise ValueError("definition serialization_format must be JSON")
        if definition.semantic_format is not SemanticFormatId.THREATFOX:
            raise ValueError("definition semantic_format must be THREATFOX")

    def supports(self, entity: Entity) -> bool:
        """Return deterministic applicability without external I/O.

        Mirrors the legacy ThreatFox provider's supported set (DOMAIN and
        IP_ADDRESS entity types). Unknown entity types return ``False``
        and never raise; canonicalization of a supported value is the
        acquirer's concern.
        """
        return entity.type in (EntityType.DOMAIN, EntityType.IP_ADDRESS)

    async def acquire(
        self,
        *,
        definition: DatasourceDefinition,
        entity: Entity,
        recorder: DatasourceExecutionRecorder,
    ) -> SemanticAcquisitionResult[ThreatFoxRecord]:
        """Acquire and parse one ThreatFox search, appending stage events.

        Dimensions are validated before any I/O. The recorder must already be
        STARTED by the caller-owned runner; this acquirer appends
        ``ACQUIRED`` (after a decoded response) and ``DECODED`` (after
        successful semantic parsing) in short committed transactions, while
        the HTTP request and the semantic parse run with no database
        transaction open. Terminal recording is the runner's responsibility.
        """
        # Fail closed on dimension mismatch before any request is issued.
        self._validate_definition(definition)

        retrieved_at = self._clock()
        if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        context = SemanticSourceContext.from_definition(
            definition,
            retrieved_at=retrieved_at.astimezone(UTC),
            source_reference=_THREATFOX_ENDPOINT,
        )

        canonical_value = canonicalize_threatfox_search_value(entity)
        if canonical_value is None:
            return SemanticAcquisitionResult(
                context=context,
                error=DatasourceStageError(
                    stage=DatasourceStage.SEMANTIC_VALIDATION,
                    code="unsupported_indicator",
                    retryable=False,
                ),
            )

        outcome = await self._http.request_json(
            "POST",
            _THREATFOX_ENDPOINT,
            json_body={
                "query": "search_ioc",
                "search_term": canonical_value,
                "exact_match": True,
            },
            headers={"Auth-Key": self._auth_key},
        )

        if outcome.final_error_code is not None:
            return SemanticAcquisitionResult(
                context=context, error=_outcome_error(outcome)
            )

        byte_count = (
            0 if outcome.response_bytes is None else len(outcome.response_bytes)
        )
        await recorder.acquired(byte_count=byte_count)

        semantic = parse_threatfox_response(
            outcome.response_json,
            entity_type=entity.type,
            canonical_value=canonical_value,
        )
        if semantic.error is not None:
            return SemanticAcquisitionResult(context=context, error=semantic.error)
        await recorder.decoded(item_count=len(semantic.records))
        return SemanticAcquisitionResult(context=context, objects=semantic.records)


async def _best_effort_terminal(
    recorder: DatasourceExecutionRecorder, *, cancelled: bool
) -> None:
    """Best-effort terminal recording that never masks the original outcome.

    Cancellation appends CANCELLED; other terminal recording appends FAILED
    with the safe default. A database failure during the append is ignored so
    the original outcome always propagates (mirrors the PR 27B recorder
    contract).
    """
    try:
        if cancelled:
            await recorder.cancel()
        else:
            await recorder.fail(error_code="unexpected_error")
    except Exception:  # noqa: BLE001 - best-effort terminal recording must not mask the original outcome
        return


async def acquire_threatfox_execution(
    *,
    datasource: ThreatFoxDatasource,
    definition: DatasourceDefinition,
    entity: Entity,
    uow_factory: Callable[[], UnitOfWork],
    clock: Callable[[], datetime] | None = None,
) -> SemanticAcquisitionResult[ThreatFoxRecord]:
    """Run one complete ThreatFox acquisition execution with terminal logging.

    Owns one fresh recorder for one ``execution_id`` and one datasource ID:
    STARTED, the acquirer's stage appends, then exactly one terminal outcome
    (COMPLETED on success, FAILED with the bounded safe code on a typed
    failure, CANCELLED on ``asyncio.CancelledError``, which always
    propagates). This tiny runner coordinates the recorder and the acquirer;
    it is not a workflow engine.
    """
    recorder = DatasourceExecutionRecorder(
        definition.datasource_id,
        uow_factory=uow_factory,
        clock=clock,
    )
    await recorder.start()
    try:
        result = await datasource.acquire(
            definition=definition, entity=entity, recorder=recorder
        )
    except asyncio.CancelledError:
        await _best_effort_terminal(recorder, cancelled=True)
        raise
    except Exception:
        await _best_effort_terminal(recorder, cancelled=False)
        raise
    else:
        if result.error is not None:
            await recorder.fail(error_code=result.error.code)
        else:
            await recorder.complete()
        return result
