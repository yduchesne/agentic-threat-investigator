# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Native MISP REST acquisition (PR 32C).

Bounded HTTPS acquisition of a native MISP Event collection from a
configured MISP server through the existing :class:`ProviderHttpClient`:

```text
MISP REST POST {base_url}/events/restSearch
  -> PR 32C acquirer
  -> decoded Event envelopes
  -> PR 32A parse_misp_event()
  -> MispSemanticRecord
```

The acquirer validates the explicit datasource dimensions (MISP source,
HTTPS protocol, JSON serialization, MISP semantic format) before any I/O,
authenticates with a ``SecretsResolver``-resolved API key carried only in
the ``Authorization`` header, adapts each REST search response member into
the exact ``{"Event": {...}}`` envelope PR 32A accepts (the REST envelope
is validated here, never in ``misp_semantics.py``), and returns one typed
:class:`SemanticAcquisitionResult`. Pagination is strictly sequential and
explicitly bounded (at most ``page_size * max_pages`` Events); page N is
fully processed before page N+1 is requested, reaching ``max_pages`` means
the bounded acquisition window completed (never that the server is
exhausted), and no request is ever issued past the bound. Any later-page
or parse failure fails the whole acquisition with zero objects; an empty
search is successful empty semantics. One injected UTC clock stamps the
single ``retrieved_at`` shared by the context.

The acquirer never constructs ATI Evidence, never performs persistence
beyond the PR 27B recorder's own short committed transactions, and never
prefetches pages. ``ProviderHttpClient`` owns every HTTP bound (retry,
response size, concurrency admission, rate limiting, cancellation); no
second limiter or task group is stacked here. PR 32D owns production
runtime composition.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TypeAlias

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
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.misp_semantics import (
    MispSemanticRecord,
    parse_misp_event,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    HttpOutcome,
    ProviderHttpClient,
    validate_entity_url_path,
)

_REST_SEARCH_PATH = "events/restSearch"
"""MISP REST search endpoint path relative to the configured base URL.

Verified against the current official MISP/PyMISP contract: a POST to
``{base_url}/events/restSearch`` with an explicit ``page`` and ``limit``
JSON body returns ``{"response": [{"Event": {...}}, ...]}`` (the client
unwraps the single ``response`` member after unwrapping the top-level
``{"response": ...}`` envelope). Only the normal JSON response shape is
supported.
"""

_MIN_PAGE_SIZE = 1
_MAX_PAGE_SIZE = 1000
_MIN_MAX_PAGES = 1
_MAX_MAX_PAGES = 1000
"""Hard bounds of the explicit MISP page-size/max-page acquisition window."""

_MISP_ERROR_CODE_BY_PROVIDER_CODE: dict[str, str] = {
    "timeout": "timeout",
    "rate_limited": "rate_limited",
    "authentication_failed": "authentication_failed",
    "forbidden": "forbidden",
    "not_found": "not_found",
    "provider_unavailable": "provider_unavailable",
}
"""Stable bounded terminal codes for deterministic HTTP failure classes.

Every externally reported failure is one of these bounded codes; no raw
response body, server message, header, or URL detail is ever promoted.
"""

MispSemanticRecordCollection: TypeAlias = tuple[MispSemanticRecord, ...]
"""One ordered collection of validated MISP semantic records."""


def extract_misp_event_envelopes(decoded: object) -> tuple[dict[str, object], ...]:
    """Extract the ordered native Event envelopes from a decoded search response.

    Validates only the REST search envelope (a JSON object carrying a
    ``response`` list of ``{"Event": {...}}`` members) and preserves source
    order; it never interprets IOC or Event semantics — every returned
    envelope is passed whole to :func:`parse_misp_event` by the caller. An
    invalid root, a missing/non-list ``response`` member, or a member that
    is not a ``{"Event": {...}}`` object raises ``ValueError`` so the caller
    fails the whole acquisition with zero objects.
    """
    if not isinstance(decoded, dict):
        raise ValueError("MISP search response must be a JSON object")
    members = decoded.get("response")
    if members is None:
        raise ValueError("MISP search response is missing the response member")
    if not isinstance(members, list):
        raise ValueError("MISP search response must be an array")
    envelopes: list[dict[str, object]] = []
    for member in members:
        if not isinstance(member, dict):
            raise ValueError("MISP search response members must be JSON objects")
        event_value = member.get("Event")
        if not isinstance(event_value, dict) or not event_value:
            raise ValueError("MISP search response members must be Event envelopes")
        envelopes.append(member)
    return tuple(envelopes)


def _semantic_validation_error() -> DatasourceStageError:
    """Build the standard non-retryable semantic-validation stage error."""
    return DatasourceStageError(
        stage=DatasourceStage.SEMANTIC_VALIDATION,
        code="semantic_validation_failed",
        retryable=False,
    )


def _outcome_error(outcome: HttpOutcome) -> DatasourceStageError:
    """Map one typed HTTP failure outcome to a bounded stage-aware error.

    The stage comes from the typed ``final_error_stage`` (never from
    matching ``final_error_message`` text, and never from the response
    body); serialization-class failures use the bounded
    ``serialization_failed`` code and all other failures use the mapped
    acquisition code. The provider-directed ``retry_after_seconds`` is
    preserved for rate-limited outcomes.
    """
    code = outcome.final_error_code
    assert code is not None
    stage = (
        DatasourceStage.SERIALIZATION
        if outcome.final_error_stage is DatasourceStage.SERIALIZATION
        else DatasourceStage.ACQUISITION
    )
    if code.value in _MISP_ERROR_CODE_BY_PROVIDER_CODE:
        terminal_code = _MISP_ERROR_CODE_BY_PROVIDER_CODE[code.value]
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


class MispDatasource:
    """Bounded native MISP Event collection acquirer (PR 32C).

    Retrieves at most ``page_size * max_pages`` native MISP Events from the
    configured server through one owned :class:`ProviderHttpClient`,
    authenticating with an already-resolved API key that travels only in
    the ``Authorization`` header, and returns one typed
    :class:`SemanticAcquisitionResult` of PR 32A semantic records. It is
    **not** an ``EvidenceProvider`` and constructs no ATI Evidence; PR 32D
    owns runtime composition.
    """

    def __init__(
        self,
        http_client: ProviderHttpClient,
        *,
        api_key: str,
        base_url: str | None = None,
        page_size: int = 100,
        max_pages: int = 10,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the acquirer with an owned HTTP client and resolved key.

        ``api_key`` must already be resolved during composition; the value
        is used only in the ``Authorization`` header, never in URLs, bodies,
        context, provenance, logs, or errors. ``base_url`` must be a valid
        credential-free HTTPS URL and is joined to the fixed
        ``events/restSearch`` path; a blank/``None`` value keeps the
        acquirer legal before PR 32D but ``acquire`` fails before any I/O.
        ``page_size`` and ``max_pages`` pin the explicit bounded acquisition
        window. The UTC clock stamps the single semantic retrieval time.
        """
        if not api_key.strip():
            raise ValueError("MISP API key must not be blank")
        if isinstance(page_size, bool) or not isinstance(page_size, int):
            raise ValueError("page_size must be an integer")
        if not _MIN_PAGE_SIZE <= page_size <= _MAX_PAGE_SIZE:
            raise ValueError(f"page_size must be in {_MIN_PAGE_SIZE}..{_MAX_PAGE_SIZE}")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int):
            raise ValueError("max_pages must be an integer")
        if not _MIN_MAX_PAGES <= max_pages <= _MAX_MAX_PAGES:
            raise ValueError(f"max_pages must be in {_MIN_MAX_PAGES}..{_MAX_MAX_PAGES}")
        self._http = http_client
        self._api_key = api_key.strip()
        self._page_size = page_size
        self._max_pages = max_pages
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )
        if base_url is None or not base_url.strip():
            self._endpoint_url: str | None = None
        else:
            self._endpoint_url = validate_entity_url_path(
                base_url.strip(), _REST_SEARCH_PATH
            )

    @property
    def endpoint_url(self) -> str | None:
        """The credential-free absolute REST search endpoint, or ``None``.

        Exposing the endpoint is safe: it contains no credentials, query,
        fragment, or request-body values. ``None`` means the base URL is
        unset (legal before PR 32D); acquisition then fails before I/O.
        """
        return self._endpoint_url

    @staticmethod
    def _validate_definition(definition: DatasourceDefinition) -> None:
        """Fail closed unless the definition matches the MISP contract.

        No mismatch is inferred, repaired, or silently accepted: the
        datasource must declare MISP source, HTTPS protocol, JSON
        serialization, and MISP semantic format. Each dimension is required
        explicitly; none is inferred from the others.
        """
        if definition.source_id is not SourceId.MISP:
            raise ValueError("definition source_id must be MISP")
        if definition.protocol is not DatasourceProtocol.HTTPS:
            raise ValueError("definition protocol must be HTTPS")
        if definition.serialization_format is not SerializationFormat.JSON:
            raise ValueError("definition serialization_format must be JSON")
        if definition.semantic_format is not SemanticFormatId.MISP:
            raise ValueError("definition semantic_format must be MISP")

    async def acquire(
        self,
        *,
        definition: DatasourceDefinition,
        recorder: DatasourceExecutionRecorder,
    ) -> SemanticAcquisitionResult[MispSemanticRecord]:
        """Acquire and parse one bounded MISP Event collection.

        Dimensions are validated before any I/O; an unset base URL fails
        with ``ValueError`` before any request. The recorder must already be
        STARTED by the caller-owned runner (usually
        :func:`acquire_misp_execution`). Pages are processed strictly
        sequentially: after a successful decode each page's Events are
        parsed through the real :class:`parse_misp_event` before page N+1 is
        requested, and any HTTP/serialization/parse failure fails the whole
        acquisition with zero objects. On overall success the caller's
        recorder receives exactly one ``ACQUIRED`` (total successful page
        response bytes) and one ``DECODED`` (total semantic record count)
        append in short committed transactions; HTTP, decoding, and parsing
        always run with no database transaction open. Cancellation
        propagates unchanged.
        """
        self._validate_definition(definition)
        if self._endpoint_url is None:
            raise ValueError("MISP base URL is not configured")

        retrieved_at = self._clock()
        if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        context = SemanticSourceContext.from_definition(
            definition,
            retrieved_at=retrieved_at.astimezone(UTC),
            source_reference=self._endpoint_url,
        )

        records: list[MispSemanticRecord] = []
        total_bytes = 0
        for page in range(1, self._max_pages + 1):
            page_bytes = 0
            outcome = await self._http.request_json(
                "POST",
                self._endpoint_url,
                json_body={"page": page, "limit": self._page_size},
                headers={"Authorization": self._api_key},
            )
            if outcome.final_error_code is not None:
                return SemanticAcquisitionResult(
                    context=context, error=_outcome_error(outcome)
                )
            if outcome.response_bytes is not None:
                page_bytes = len(outcome.response_bytes)
            try:
                envelopes = extract_misp_event_envelopes(outcome.response_json)
            except ValueError:
                return SemanticAcquisitionResult(
                    context=context, error=_semantic_validation_error()
                )
            total_bytes += page_bytes
            if not envelopes:
                break
            for envelope in envelopes:
                semantic = parse_misp_event(envelope)
                if semantic.error is not None:
                    return SemanticAcquisitionResult(
                        context=context, error=semantic.error
                    )
                records.extend(semantic.records)
            if len(envelopes) < self._page_size:
                break

        await recorder.acquired(byte_count=total_bytes)
        await recorder.decoded(item_count=len(records))
        return SemanticAcquisitionResult(context=context, objects=tuple(records))


async def _best_effort_terminal(
    recorder: DatasourceExecutionRecorder, *, cancelled: bool
) -> None:
    """Best-effort terminal recording that never masks the original outcome.

    Cancellation appends CANCELLED; other terminal recording appends FAILED
    with the safe default. A database failure during the append is ignored
    so the original outcome always propagates (mirrors the PR 27B recorder
    contract).
    """
    try:
        if cancelled:
            await recorder.cancel()
        else:
            await recorder.fail(error_code="unexpected_error")
    except Exception:  # noqa: BLE001 - best-effort terminal recording must not mask the original outcome
        return


async def acquire_misp_execution(
    *,
    datasource: MispDatasource,
    definition: DatasourceDefinition,
    uow_factory: Callable[[], UnitOfWork],
    clock: Callable[[], datetime] | None = None,
) -> SemanticAcquisitionResult[MispSemanticRecord]:
    """Run one complete bounded MISP acquisition execution with terminal logging.

    Owns one fresh recorder for one ``execution_id`` and one datasource ID:
    STARTED, the acquirer's single execution-level ACQUIRED/DECODED pair,
    then exactly one terminal outcome (COMPLETED on success, FAILED with the
    bounded safe code on a typed failure, CANCELLED on
    ``asyncio.CancelledError``, which always propagates). This tiny runner
    coordinates the recorder and the acquirer; it is not a workflow engine.
    """
    recorder = DatasourceExecutionRecorder(
        definition.datasource_id,
        uow_factory=uow_factory,
        clock=clock,
    )
    await recorder.start()
    try:
        result = await datasource.acquire(definition=definition, recorder=recorder)
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


__all__ = [
    "MispDatasource",
    "MispSemanticRecordCollection",
    "acquire_misp_execution",
    "extract_misp_event_envelopes",
]
