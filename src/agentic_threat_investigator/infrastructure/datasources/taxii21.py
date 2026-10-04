# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""TAXII 2.1 protocol and bounded collection acquisition (PR 33E).

Bounded HTTPS acquisition of one TAXII 2.1 collection-object feed through
the existing :class:`ProviderHttpClient`:

```text
TAXII 2.1 server / OpenCTI
  -> GET {api_root}/collections/{collection_id}/objects/
  -> TAXII envelope validation (this module)
  -> parse_stix21_object() per member (PR 33A seam, never a Bundle wrap)
  -> Stix21Object
```

TAXII is **protocol/acquisition only**. The TAXII envelope is validated here
(``objects`` array, ``more`` + opaque ``next`` pagination, content-type and
date-added headers); STIX semantics live exclusively in ``stix21_semantics.py``;
Evidence conversion lives exclusively in ``stix21_evidence.py`` and is
selected by ``SemanticFormatId.STIX_21``. No synthetic STIX Bundle is ever
manufactured, no source identity is inferred from the URL, and OpenCTI is
consumed through exactly this generic path (never an ``OpenCtiDatasource``).

Pagination is strictly sequential and explicitly bounded (at most
``page_size * max_pages`` objects): page N+1 depends on page N's opaque
``next`` token, so pages are never prefetched concurrently, and
``ProviderHttpClient`` owns every HTTP bound (retry, response size,
concurrency admission, rate limiting, cancellation) — no second limiter or
task group is stacked here. ``added_after`` incremental retrieval uses the
durable per-datasource checkpoint (Part 7) on the first page only; every
later page uses the server's opaque ``next`` token. Any later-page or parse
failure fails the whole acquisition with zero objects; an empty envelope is
successful empty semantics; reaching ``max_pages`` while ``more`` remains
true is a successful bounded window that advances the checkpoint only
through the objects actually admitted.

The acquirer never constructs ATI Evidence, never performs persistence
beyond the PR 27B recorder's own short committed transactions, and never
persists the durable checkpoint (the producer's post-publication progress
committer owns that). Durable checkpoint values use TAXII date-added
semantics ([X-]TAXII-Date-Added-Last), never STIX ``created``/``modified``,
Sighting/Relationship times, or ATI ``retrieved_at``/``observed_at``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, TypeAlias
from urllib.parse import quote

from agentic_threat_investigator.app.datasource_execution import (
    DatasourceExecutionRecorder,
)
from agentic_threat_investigator.app.datasource_semantics import (
    CollectionAcquisitionProgress,
    DatasourceStage,
    DatasourceStageError,
    SemanticAcquisitionResult,
    SemanticSourceContext,
)
from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceCheckpoint,
    UnitOfWork,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.identifiers import SemanticFormatId
from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    Stix21Object,
    Stix21SemanticError,
    parse_stix21_object,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    HttpOutcome,
    ProviderHttpClient,
    validate_entity_url_path,
)

TAXII_ACCEPT_HEADER = "application/taxii+json;version=2.1"
"""TAXII 2.1 collection-object Accept/content-type contract."""

TAXII_JSON_MEDIA_TYPE = "application/taxii+json"
"""TAXII 2.1 JSON media type (without the version parameter)."""

TAXII_CHECKPOINT_KIND = "taxii_added_after"
"""Durable checkpoint kind interpreting the value as a TAXII date-added cursor.

The value is a canonical UTC RFC 3339 timestamp in the fixed-width
``YYYY-MM-DDTHH:MM:SS.ffffffZ`` form so canonical values compare
lexically and chronologically identically.
"""

TAXII_DATE_ADDED_HEADERS = frozenset(
    {"x-taxii-date-added-first", "x-taxii-date-added-last"}
)
"""Response header names the TAXII adapter opts into on the HTTP seam."""

_MIN_PAGE_SIZE = 1
_MAX_PAGE_SIZE = 1000
_MIN_MAX_PAGES = 1
_MAX_MAX_PAGES = 1000
"""Hard bounds of the explicit TAXII page-size/max-page acquisition window."""

_MAX_COLLECTION_ID_LENGTH = 128
"""Bounded length of one TAXII collection identifier component."""

_TAXII_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
"""Canonical fixed-width UTC timestamp form of durable TAXII checkpoints."""

_TAXII_ERROR_CODE_BY_PROVIDER_CODE: dict[str, str] = {
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


class Taxii21Error(ValueError):
    """Raised when a TAXII 2.1 response violates the bounded protocol contract."""


def canonicalize_taxii_timestamp(value: str) -> datetime:
    """Parse and canonicalize one TAXII RFC 3339 timestamp to UTC.

    Accepts RFC 3339 forms with ``Z`` or an explicit numeric offset and
    optional fractional seconds; requires an explicit timezone. Returns the
    truncated-to-microsecond UTC-aware ``datetime``. Blank, non-parseable,
    and timezone-naive values raise :class:`Taxii21Error` so the acquisition
    fails closed deterministically.
    """
    if not value or not value.strip():
        raise Taxii21Error("TAXII timestamp must not be blank")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise Taxii21Error("invalid TAXII RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise Taxii21Error("TAXII timestamp must be timezone-aware")
    return parsed.astimezone(UTC).replace(tzinfo=UTC)


def format_taxii_timestamp(value: datetime) -> str:
    """Format an already validated timezone-aware datetime into the canonical form.

    The canonical form is the fixed-width UTC ``YYYY-MM-DDTHH:MM:SS.ffffffZ``
    used by durable TAXII ``added_after`` checkpoint values, so canonical
    strings compare lexically and chronologically identically.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("TAXII canonical timestamps must be timezone-aware")
    return value.astimezone(UTC).strftime(_TAXII_TIMESTAMP_FORMAT)


@dataclass(frozen=True)
class Taxii21ObjectPage:
    """One validated immutable TAXII 2.1 collection-object page.

    ``objects`` preserves the server's source order exactly (never sorted or
    deduplicated); each member is a raw decoded JSON value that the caller
    passes individually through :func:`parse_stix21_object`. ``more``/``next``
    own the pagination contract: ``more=true`` requires a nonblank opaque
    ``next`` token, which is preserved verbatim and never parsed or
    synthesized. ``date_added_first``/``date_added_last`` are the canonical
    UTC instants of the TAXII date-added response headers, ``None`` when the
    server did not provide the header (date-added-last of a page with no
    objects is never a safe checkpoint signal).
    """

    objects: tuple[object, ...]
    more: bool
    next_token: str | None
    date_added_first: datetime | None
    date_added_last: datetime | None


def parse_taxii21_object_page(
    decoded: object,
    *,
    date_added_first: str | None,
    date_added_last: str | None,
) -> Taxii21ObjectPage:
    """Validate one decoded TAXII 2.1 collection-object envelope.

    Validates only the bounded envelope/transport contract (``objects``
    array, ``more`` + opaque ``next`` pagination, and the TAXII date-added
    headers); it never interprets STIX semantics and never inspects object
    members beyond the array shape. An empty ``objects`` array is valid
    empty semantics; ``more=true`` without a nonblank ``next`` fails closed;
    a malformed root or member array fails closed with zero objects from the
    whole execution. Object order is preserved exactly. A server-controlled
    error body is never echoed back to the caller.
    """
    if not isinstance(decoded, dict):
        raise Taxii21Error("TAXII response must be a JSON object")
    members = decoded.get("objects")
    if members is None:
        raise Taxii21Error("TAXII response is missing the objects member")
    if not isinstance(members, list):
        raise Taxii21Error("TAXII objects must be an array")

    more_value = decoded.get("more", False)
    if not isinstance(more_value, bool):
        raise Taxii21Error("TAXII more must be a boolean")
    next_value = decoded.get("next")
    if next_value is not None and not isinstance(next_value, str):
        raise Taxii21Error("TAXII next must be a string")
    next_token: str | None = next_value.strip() if next_value else None
    if more_value and not next_token:
        raise Taxii21Error("TAXII more=true requires a nonblank next token")

    first = canonicalize_taxii_timestamp(date_added_first) if date_added_first else None
    last = canonicalize_taxii_timestamp(date_added_last) if date_added_last else None
    return Taxii21ObjectPage(
        objects=tuple(members),
        more=bool(more_value),
        next_token=next_token,
        date_added_first=first,
        date_added_last=last,
    )


def _protocol_validation_error() -> DatasourceStageError:
    """Build the standard non-retryable protocol validation stage error."""
    return DatasourceStageError(
        stage=DatasourceStage.SEMANTIC_VALIDATION,
        code="protocol_validation_failed",
        retryable=False,
    )


def _semantic_validation_error() -> DatasourceStageError:
    """Build the standard non-retryable semantic-validation stage error."""
    return DatasourceStageError(
        stage=DatasourceStage.SEMANTIC_VALIDATION,
        code="semantic_validation_failed",
        retryable=False,
    )


def _outcome_error(outcome: HttpOutcome) -> DatasourceStageError:
    """Map one typed HTTP failure outcome to a bounded stage-aware error.

    Mirrors the MISP mapping conventions: the stage comes from the typed
    ``final_error_stage`` (never from matching message text and never from
    the response body); serialization-class failures use the bounded
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
    if code.value in _TAXII_ERROR_CODE_BY_PROVIDER_CODE:
        terminal_code = _TAXII_ERROR_CODE_BY_PROVIDER_CODE[code.value]
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


TAXII_CHECKPOINT_READER: TypeAlias = Callable[
    [], Awaitable[DatasourceCheckpoint | None]
]
"""Injected seam returning the durable checkpoint row the execution starts from.

The callable performs its own short committed UnitOfWork read and closes the
transaction before returning; the datasource never holds a UnitOfWork across
HTTP or Kafka I/O (PR 33E section 3.9).
"""


class Taxii21Datasource:
    """Bounded TAXII 2.1 collection-object acquirer (PR 33E).

    Retrieves at most ``page_size * max_pages`` STIX objects from one
    configured TAXII collection through one owned :class:`ProviderHttpClient`,
    authenticating with an already-resolved bearer token (``None`` = public
    collection) that travels only in the ``Authorization`` header. Every
    TAXII object passes individually through :func:`parse_stix21_object`;
    the acquirer is **not** an ``EvidenceProvider`` and constructs no ATI
    Evidence. PR 33E production composition owns wiring.
    """

    def __init__(
        self,
        http_client: ProviderHttpClient,
        *,
        api_root_url: str | None = None,
        collection_id: str | None = None,
        bearer_token: str | None = None,
        page_size: int = 100,
        max_pages: int = 100,
        initial_added_after: str | None = None,
        checkpoint_reader: TAXII_CHECKPOINT_READER | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize the acquirer with an owned HTTP client and resolved token.

        ``bearer_token`` must already be resolved during composition; the
        value is used only in the ``Authorization`` header, never in URLs,
        bodies, context, provenance, logs, or errors. ``api_root_url`` must
        be a valid credential-free HTTPS URL; a blank/``None`` value keeps
        the acquirer legal before composition but ``acquire`` fails before any
        I/O. ``initial_added_after`` is an optional RFC 3339 TAXII timestamp
        canonicalized here; it is used only when no durable checkpoint
        exists. ``checkpoint_reader`` is an optional injected seam returning
        the durable checkpoint row this execution starts from (a short UoW
        read performed and closed before any HTTP). ``page_size`` and
        ``max_pages`` pin the explicit bounded acquisition window.
        """
        if isinstance(page_size, bool) or not isinstance(page_size, int):
            raise ValueError("page_size must be an integer")
        if not _MIN_PAGE_SIZE <= page_size <= _MAX_PAGE_SIZE:
            raise ValueError(f"page_size must be in {_MIN_PAGE_SIZE}..{_MAX_PAGE_SIZE}")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int):
            raise ValueError("max_pages must be an integer")
        if not _MIN_MAX_PAGES <= max_pages <= _MAX_MAX_PAGES:
            raise ValueError(f"max_pages must be in {_MIN_MAX_PAGES}..{_MAX_MAX_PAGES}")
        if bearer_token is not None and not bearer_token.strip():
            raise ValueError("bearer token must not be blank when configured")
        self._http = http_client
        self._bearer_token = bearer_token.strip() if bearer_token is not None else None
        self._page_size = page_size
        self._max_pages = max_pages
        self._checkpoint_reader = checkpoint_reader
        self._initial_added_after: datetime | None = (
            canonicalize_taxii_timestamp(initial_added_after)
            if initial_added_after
            else None
        )
        self._initial_added_after_raw: str | None = (
            initial_added_after.strip() if initial_added_after else None
        )
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )
        self._api_root_url: str | None = (
            api_root_url.strip() if api_root_url and api_root_url.strip() else None
        )
        self._collection_id: str | None = (
            collection_id.strip() if collection_id and collection_id.strip() else None
        )
        self._objects_url: str | None = None
        if self._api_root_url is not None and self._collection_id is not None:
            if len(self._collection_id) > _MAX_COLLECTION_ID_LENGTH:
                raise ValueError("TAXII collection_id exceeds the maximum length")
            encoded_collection_id = quote(self._collection_id, safe="")
            self._objects_url = validate_entity_url_path(
                self._api_root_url,
                f"collections/{encoded_collection_id}/objects/",
            )

    def with_checkpoint_reader(
        self, reader: TAXII_CHECKPOINT_READER | None
    ) -> "Taxii21Datasource":
        """Return an equivalent acquirer bound to the given checkpoint reader.

        The returned instance reuses this acquirer's exact HTTP client,
        resolved bearer token, endpoint configuration, page bounds, initial
        cursor, and clock; only the injected checkpoint-reading seam is
        replaced. Composition uses this immutable rebinding to attach the
        durable-checkpoint reader to an infrastructurally composed acquirer;
        the reader is always invoked at the start of :meth:`acquire`, in its
        own short committed UnitOfWork, before any HTTP I/O.
        """
        return Taxii21Datasource(
            self._http,
            api_root_url=self._api_root_url,
            collection_id=self._collection_id,
            bearer_token=self._bearer_token,
            page_size=self._page_size,
            max_pages=self._max_pages,
            initial_added_after=self._initial_added_after_raw,
            checkpoint_reader=reader,
            clock=self._clock,
        )

    @property
    def objects_url(self) -> str | None:
        """The credential-free TAXII collection-objects URL, or ``None``.

        Exposing the URL is safe: it contains no credentials, query,
        fragment, or request-body values, and the collection identifier is
        percent-encoded as a single path segment. ``None`` means the API
        root/collection is unset (legal before composition); acquisition then
        fails before I/O.
        """
        return self._objects_url

    @staticmethod
    def _validate_definition(definition: DatasourceDefinition) -> None:
        """Fail closed unless the definition matches the TAXII/STIX contract.

        TAXII requires exactly the TAXII_21 protocol, JSON serialization, and
        STIX_21 semantic dimensions. The ``source_id`` is deliberately
        unrestricted: TAXII is a generic acquisition protocol, so any
        configured source identity (OpenCTI or another explicit TIP) whose
        definition otherwise satisfies these dimensions is acquired through
        this generic path. No dimension is inferred from another.
        """
        if definition.protocol is not DatasourceProtocol.TAXII_21:
            raise ValueError("definition protocol must be TAXII_21")
        if definition.serialization_format is not SerializationFormat.JSON:
            raise ValueError("definition serialization_format must be JSON")
        if definition.semantic_format is not SemanticFormatId.STIX_21:
            raise ValueError("definition semantic_format must be STIX_21")

    @staticmethod
    def _starting_added_after(
        checkpoint: DatasourceCheckpoint | None,
        initial: datetime | None,
    ) -> tuple[str, datetime | None]:
        """Derive the execution's starting ``added_after`` and previous instant.

        The durable checkpoint always wins over the configured initial value;
        with neither, ``added_after`` is omitted (the server's bounded
        initial collection window applies) and ``previous`` is ``None``. The
        previous instant is only ever derived from the durable checkpoint or
        the configured initial cursor — never from wall-clock retrieval time.
        """
        if checkpoint is not None:
            previous_dt = canonicalize_taxii_timestamp(checkpoint.checkpoint_value)
            return format_taxii_timestamp(previous_dt), previous_dt
        if initial is not None:
            return format_taxii_timestamp(initial), initial
        return "", None

    async def acquire(
        self,
        *,
        definition: DatasourceDefinition,
        recorder: DatasourceExecutionRecorder,
    ) -> SemanticAcquisitionResult[Stix21Object]:
        """Acquire and parse one bounded TAXII collection execution.

        Dimensions are validated before any I/O; an unset objects URL fails
        with ``ValueError`` before any request. The recorder must already be
        STARTED by the caller-owned runner. Pages are processed strictly
        sequentially: after a successful decode each page's STIX objects are
        parsed individually through :func:`parse_stix21_object` before page
        N+1 is requested, and any HTTP/serialization/protocol/parse failure
        fails the whole acquisition with zero objects. On overall success the
        caller's recorder receives exactly one ``ACQUIRED`` (total successful
        page response bytes) and one ``DECODED`` (total STIX object count)
        append in short committed transactions; HTTP, decoding, and parsing
        always run with no database transaction open. The durable checkpoint
        is **not** persisted here: the returned
        :class:`CollectionAcquisitionProgress` candidate is committed by the
        producer's post-publication progress committer. Cancellation
        propagates unchanged.
        """
        self._validate_definition(definition)
        if self._objects_url is None:
            raise ValueError("TAXII API root/collection is not configured")

        retrieved_at = self._clock()
        if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        context = SemanticSourceContext.from_definition(
            definition,
            retrieved_at=retrieved_at.astimezone(UTC),
            source_reference=self._objects_url,
        )

        checkpoint: DatasourceCheckpoint | None = None
        if self._checkpoint_reader is not None:
            checkpoint = await self._checkpoint_reader()
        starting, previous_dt = self._starting_added_after(
            checkpoint, self._initial_added_after
        )

        first_page_params: dict[str, Any] = {"limit": self._page_size}
        if starting:
            first_page_params["added_after"] = starting
        base_params = dict(first_page_params)

        objects: list[Stix21Object] = []
        total_bytes = 0
        next_token: str | None = None
        candidate_dt: datetime | None = None
        for _page in range(1, self._max_pages + 1):
            page_params = dict(base_params)
            if next_token is not None:
                # Continuation pages use the server's opaque next token only;
                # added_after belongs to the first page of one execution.
                page_params.pop("added_after", None)
                page_params["next"] = next_token
            request_headers = {"Accept": TAXII_ACCEPT_HEADER}
            if self._bearer_token is not None:
                request_headers["Authorization"] = f"Bearer {self._bearer_token}"
            outcome = await self._http.request_json(
                "GET",
                self._objects_url,
                params=page_params,
                headers=request_headers,
                accepted_media_types=(TAXII_JSON_MEDIA_TYPE,),
                response_header_names=TAXII_DATE_ADDED_HEADERS,
            )
            if outcome.final_error_code is not None:
                return SemanticAcquisitionResult(
                    context=context, error=_outcome_error(outcome)
                )
            if outcome.response_bytes is not None:
                total_bytes += len(outcome.response_bytes)
            received_headers = outcome.response_headers or {}
            try:
                page = parse_taxii21_object_page(
                    outcome.response_json,
                    date_added_first=received_headers.get("x-taxii-date-added-first"),
                    date_added_last=received_headers.get("x-taxii-date-added-last"),
                )
            except Taxii21Error:
                return SemanticAcquisitionResult(
                    context=context, error=_protocol_validation_error()
                )
            try:
                for member in page.objects:
                    objects.append(parse_stix21_object(member))
            except Stix21SemanticError:
                return SemanticAcquisitionResult(
                    context=context, error=_semantic_validation_error()
                )
            # A date-added-last is a safe durable-checkpoint signal only when
            # the page actually returned objects; an empty page's headers are
            # never used to advance the cursor.
            if (
                page.objects
                and page.date_added_last is not None
                and (candidate_dt is None or page.date_added_last > candidate_dt)
            ):
                candidate_dt = page.date_added_last
            if not page.more:
                break
            if page.next_token is None:  # pragma: no cover - parser enforces
                return SemanticAcquisitionResult(
                    context=context, error=_protocol_validation_error()
                )
            next_token = page.next_token

        await recorder.acquired(byte_count=total_bytes)
        await recorder.decoded(item_count=len(objects))

        progress: CollectionAcquisitionProgress | None = None
        if candidate_dt is not None:
            if previous_dt is not None and candidate_dt <= previous_dt:
                safe_candidate = format_taxii_timestamp(previous_dt)
            else:
                safe_candidate = format_taxii_timestamp(candidate_dt)
            progress = CollectionAcquisitionProgress(
                kind=TAXII_CHECKPOINT_KIND,
                previous=(
                    format_taxii_timestamp(previous_dt)
                    if previous_dt is not None
                    else None
                ),
                candidate=safe_candidate,
            )
        elif previous_dt is not None:
            # No safe server advancement: propose an idempotent no-op at the
            # starting value so the commit seam is always exercised.
            progress = CollectionAcquisitionProgress(
                kind=TAXII_CHECKPOINT_KIND,
                previous=format_taxii_timestamp(previous_dt),
                candidate=format_taxii_timestamp(previous_dt),
            )
        return SemanticAcquisitionResult(
            context=context, objects=tuple(objects), progress=progress
        )


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


async def acquire_taxii_execution(
    *,
    datasource: Taxii21Datasource,
    definition: DatasourceDefinition,
    uow_factory: Callable[[], UnitOfWork],
    clock: Callable[[], datetime] | None = None,
) -> SemanticAcquisitionResult[Stix21Object]:
    """Run one complete bounded TAXII acquisition execution with terminal logging.

    Owns one fresh recorder for one ``execution_id`` and one datasource ID:
    STARTED, the acquirer's single execution-level ACQUIRED/DECODED pair,
    then exactly one terminal outcome (COMPLETED on success, FAILED with the
    bounded safe code on a typed failure, CANCELLED on
    ``asyncio.CancelledError``, which always propagates). This tiny runner
    coordinates the recorder and the acquirer; it is not a workflow engine.
    """
    from agentic_threat_investigator.app.datasource_provider import (
        observe_collection_acquisition,
    )

    recorder = DatasourceExecutionRecorder(
        definition.datasource_id,
        uow_factory=uow_factory,
        clock=clock,
    )
    await recorder.start()
    try:
        result = await observe_collection_acquisition(
            datasource, definition=definition, recorder=recorder
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


__all__ = [
    "TAXII_ACCEPT_HEADER",
    "TAXII_CHECKPOINT_KIND",
    "TAXII_DATE_ADDED_HEADERS",
    "TAXII_JSON_MEDIA_TYPE",
    "Taxii21Datasource",
    "Taxii21Error",
    "Taxii21ObjectPage",
    "acquire_taxii_execution",
    "canonicalize_taxii_timestamp",
    "format_taxii_timestamp",
    "parse_taxii21_object_page",
]
