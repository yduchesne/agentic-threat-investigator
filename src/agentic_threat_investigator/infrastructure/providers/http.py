# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Reusable HTTP request infrastructure for live evidence providers.

Provides bounded retry, exponential backoff, concurrency limiting, request
rate limiting, response-size enforcement, Content-Type verification, and URL
safety checks.
"""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import json
import logging
import math
import random as _random
import re
import time as _time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from agentic_threat_investigator.app.providers import ProviderErrorCode

_logger = logging.getLogger(__name__)

_USER_AGENT = "AgenticThreatInvestigator/0.1.0"
_DEFAULT_TIMEOUT_SECONDS = 15.0
_DEFAULT_MAX_RETRIES = 2
_DEFAULT_BASE_DELAY_SECONDS = 1.0
_DEFAULT_MAX_DELAY_SECONDS = 30.0
_DEFAULT_JITTER_RATIO = 0.1
_DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES_LIMIT = 100_000_000

_DEFAULT_ACCEPTED_MEDIA_TYPES = ("application/json",)
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

Clock = Callable[[], float]
"""Monotonic clock returning current time as float seconds."""

UtcClock = Callable[[], datetime]
"""Clock returning current timezone-aware UTC datetime."""

AsyncSleep = Callable[[float], Awaitable[None]]
"""Asynchronous non-blocking sleep callable."""

JitterFn = Callable[[], float]
"""Jitter callable returning float in [0.0, 1.0]."""


_STATUS_CODE_MAP = {
    401: ProviderErrorCode.AUTHENTICATION_FAILED,
    403: ProviderErrorCode.FORBIDDEN,
    404: ProviderErrorCode.NOT_FOUND,
    429: ProviderErrorCode.RATE_LIMITED,
}


@dataclass(frozen=True)
class HttpOutcome:  # pylint: disable=too-many-instance-attributes
    """Internal result metadata after a provider HTTP request.

    When the request succeeded ``final_error_code`` is None and
    ``response_json`` carries the parsed body. On failure the error fields
    carry the classification.
    """

    attempt_count: int
    retry_count: int
    final_status: int | None
    final_error_code: ProviderErrorCode | None
    final_error_message: str | None
    duration_seconds: float
    retry_after_seconds: int | None = None
    response_bytes: bytes | None = None
    response_json: Any = None


@dataclass(frozen=True)
class ProviderHttpPolicy:
    """Validated configuration policy for ProviderHttpClient."""

    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    max_retries: int = _DEFAULT_MAX_RETRIES
    base_delay_seconds: float = _DEFAULT_BASE_DELAY_SECONDS
    max_delay_seconds: float = _DEFAULT_MAX_DELAY_SECONDS
    jitter_ratio: float = _DEFAULT_JITTER_RATIO
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        """Enforce parameter bounds on policy settings."""
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.base_delay_seconds < 0:
            raise ValueError("base_delay_seconds must be non-negative")
        if self.max_delay_seconds < self.base_delay_seconds:
            raise ValueError("max_delay_seconds must be >= base_delay_seconds")
        if not 0.0 <= self.jitter_ratio <= 1.0:
            raise ValueError("jitter_ratio must be between 0.0 and 1.0")
        if not 0 < self.max_response_bytes <= _MAX_RESPONSE_BYTES_LIMIT:
            raise ValueError(
                f"max_response_bytes must be in 1..{_MAX_RESPONSE_BYTES_LIMIT}"
            )


@dataclass(frozen=True)
class RateLimiterSettings:
    """Settings for a provider's concurrency and request-rate limiter."""

    max_concurrency: int = 10
    requests_per_second: float | None = None

    def __post_init__(self) -> None:
        """Validate concurrency and rate bounds."""
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        if self.requests_per_second is not None and self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")


async def _default_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def _default_jitter() -> float:
    return _random.random()


def _default_monotonic() -> float:
    return _time.monotonic()


def _default_utc_now() -> datetime:
    return datetime.now(UTC)


def _canonical_host(hostname: str) -> str:
    """Return the canonical, IDNA-normalized, lowercase DNS hostname.

    IP literals are rejected here; callers handle them separately so IPv6
    semantics can be preserved exactly.
    """
    host = hostname.rstrip(".").lower()
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("provider URL has an invalid hostname") from exc
    labels = ascii_host.split(".")
    if not labels or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("provider URL has an invalid hostname")
    return ascii_host


def validate_provider_url(url: str) -> str:
    """Validate a provider HTTPS URL and return its canonical form.

    Raises ``ValueError`` if the URL is not HTTPS, contains credentials,
    contains a fragment, or has a malformed host or port. The returned URL
    reconstructs the authority from the validated host so canonically
    equivalent spellings (host case, terminal DNS root dot, Unicode IDNA
    forms, IPv6 literals, and the default HTTPS port) compare equal. The
    path is preserved verbatim.
    """
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        # Parser-failure messages must never echo the raw input: malformed
        # syntax can embed credentials or query values that the category
        # checks below would otherwise reject before any text is raised.
        raise ValueError("malformed provider URL") from exc

    if parsed.scheme != "https":
        raise ValueError("provider URL must use https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("provider URL must not contain credentials")
    if not parsed.hostname:
        raise ValueError("provider URL must have a hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("provider URL has an invalid port") from exc
    if parsed.query:
        raise ValueError("provider URL must not contain a query")
    if parsed.fragment:
        raise ValueError("provider URL must not contain a fragment")

    hostname = parsed.hostname.rstrip(".").lower()
    try:
        # Preserve exact IPv4/IPv6 literal semantics via canonical text form.
        canonical_host = str(ipaddress.ip_address(hostname))
    except ValueError:
        canonical_host = _canonical_host(hostname)

    host_for_netloc = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    if port is not None and port != 443:
        netloc = f"{host_for_netloc}:{port}"
    else:
        netloc = host_for_netloc

    return urlunsplit(("https", netloc, parsed.path, "", ""))


def validate_entity_url_path(base: str, path: str) -> str:
    """Safely join a percent-encoded path to a validated base URL.

    Validates both the base and the joined URL, preventing credentials or
    fragments from being injected via the path.
    """
    canonical_base = validate_provider_url(base)

    try:
        parsed_path = urlsplit(path)
    except ValueError as exc:
        # As above, the parser-failure message must stay generic so that
        # malformed authority-like path input cannot leak embedded values.
        raise ValueError("malformed resource path") from exc

    if parsed_path.scheme or parsed_path.netloc:
        raise ValueError("path must not contain a scheme or authority")
    if parsed_path.query:
        raise ValueError("path must not contain a query")
    if parsed_path.fragment:
        raise ValueError("path must not contain a fragment")

    normalised_base = canonical_base.rstrip("/") + "/"
    joined = normalised_base + path.lstrip("/")
    return validate_provider_url(joined)


def check_content_type(
    content_type_header: str | None,
    accepted_types: tuple[str, ...],
) -> bool:
    """Verify that a response Content-Type matches accepted JSON media types."""
    if not content_type_header:
        return False
    media_type = content_type_header.split(";")[0].strip().lower()
    return media_type in accepted_types


async def read_bounded_body(
    response: httpx.Response,
    max_response_bytes: int,
) -> bytes:
    """Stream response bytes into a bounded bytearray, enforcing size limits."""
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            length_val = int(content_length.strip())
        except ValueError as exc:
            raise ValueError("invalid response size metadata") from exc
        if length_val < 0:
            raise ValueError("invalid response size metadata")
        if length_val > max_response_bytes:
            raise ValueError("response too large")

    buffer = bytearray()
    async for chunk in response.aiter_bytes():
        buffer.extend(chunk)
        if len(buffer) > max_response_bytes:
            raise ValueError("response too large")
    return bytes(buffer)


def classify_http_status(
    status: int,
    accept_statuses: set[int],
) -> ProviderErrorCode | None:
    """Classify an HTTP response status code into a ProviderErrorCode."""
    if status in accept_statuses:
        return None
    if status in _STATUS_CODE_MAP:
        return _STATUS_CODE_MAP[status]
    if status >= 500:
        return ProviderErrorCode.PROVIDER_UNAVAILABLE
    return ProviderErrorCode.INVALID_RESPONSE


def status_error_message(status: int, code: ProviderErrorCode) -> str:
    """Return a generic, safe error message for a classified HTTP status."""
    if code == ProviderErrorCode.AUTHENTICATION_FAILED:
        return "authentication failed"
    if code == ProviderErrorCode.FORBIDDEN:
        return "forbidden"
    if code == ProviderErrorCode.NOT_FOUND:
        return "not found"
    if code == ProviderErrorCode.RATE_LIMITED:
        return "rate limited"
    if code == ProviderErrorCode.PROVIDER_UNAVAILABLE:
        return f"server error {status}"
    return f"unexpected HTTP {status}"


def parse_retry_after_header(
    response: httpx.Response,
    utc_now: UtcClock,
) -> int | None:
    """Parse Retry-After header, preferring seconds over HTTP-date.

    A positive HTTP-date delay is rounded up to the next whole second so the
    returned value never expires before the provider-directed deadline: an
    HTTP-date has one-second precision while real clocks carry fractions of a
    second, and truncation would schedule the retry early. Past and negative
    dates are ignored. The configured maximum delay cap in
    :meth:`ProviderHttpClient.compute_backoff_delay` remains the hard upper
    bound regardless of the value returned here.
    """
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    raw = raw.strip()
    try:
        seconds = int(raw)
        return seconds if seconds >= 0 else None
    except ValueError:
        pass
    try:
        retry_after_dt = parsedate_to_datetime(raw)
        if retry_after_dt.tzinfo is None:
            retry_after_dt = retry_after_dt.replace(tzinfo=UTC)
        now = utc_now()
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        delta_seconds = (retry_after_dt - now).total_seconds()
        if delta_seconds < 0:
            return None
        return math.ceil(delta_seconds)
    except (ValueError, OverflowError, OSError):
        return None


class _AdmissionWaiter:  # pylint: disable=too-few-public-methods
    """A FIFO rate-admission waiter holding one reserved future start slot.

    ``slot`` is the absolute monotonic start time reserved for this waiter.
    ``wake`` is set when a cancellation ahead of this waiter reclaims a slot
    and shifts this reservation one interval earlier; the waiter then wakes
    from its wait and re-derives its remaining delay from the updated slot.
    """

    __slots__ = ("slot", "wake")

    def __init__(self, slot: float) -> None:
        self.slot = slot
        self.wake = asyncio.Event()


class BoundedLimiter:
    """Concurrency and request-rate limiter for one provider.

    Acquisition first waits for a concurrency permit (semaphore) and then for
    a rate slot. The first acquisition after construction is admitted
    immediately. Later acquisitions reserve future start slots spaced by the
    configured request interval in strict FIFO order: each waiter's slot is
    reserved under the scheduling lock, but the wait itself is slept outside
    the lock, so concurrent acquirers reserve ordered, non-overlapping slots
    without blocking each other.

    Rate admission is cancellation-safe. A waiter that is canceled before its
    slot comes due removes its reservation, shifts every later waiter one
    interval earlier to reclaim the canceled slot, and wakes them so they
    re-derive their remaining wait. Canceled waiters therefore never leave
    stale future reservations that would delay later requests, no two
    attempts can start in the same rate slot, and ``CancelledError`` always
    propagates unchanged. The concurrency permit is released on every
    cancellation, failure, and success path.
    """

    def __init__(
        self,
        settings: RateLimiterSettings,
        *,
        sleep: AsyncSleep = _default_sleep,
        clock: Clock = _default_monotonic,
    ) -> None:
        self._semaphore = asyncio.Semaphore(settings.max_concurrency)
        self._rps: float | None = settings.requests_per_second
        self._sleep = sleep
        self._clock = clock
        self._last_slot: float | None = None
        self._waiters: deque[_AdmissionWaiter] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire concurrency and rate-limit permits in an exception-safe manner."""
        await self._semaphore.acquire()
        acquired = False
        try:
            if self._rps is not None:
                await self._admit_within_rate()
            acquired = True
        finally:
            if not acquired:
                self._semaphore.release()

    def release(self) -> None:
        """Release a concurrency permit."""
        self._semaphore.release()

    async def _admit_within_rate(self) -> None:
        """Reserve and wait for the caller's FIFO rate slot.

        On any exception, including cancellation, the reserved slot is
        reclaimed for later waiters before the exception propagates.
        """
        assert self._rps is not None
        interval = 1.0 / self._rps
        async with self._lock:
            waiter = self._reserve_slot(interval)
        if waiter is None:
            return
        try:
            await self._wait_for_slot(waiter)
        except BaseException:
            async with self._lock:
                self._reclaim_reservation(waiter, interval)
            raise

    def _reserve_slot(self, interval: float) -> _AdmissionWaiter | None:
        """Reserve the caller's start slot; ``None`` means admitted immediately.

        The caller holds the scheduling lock. When the queue is empty and the
        previous slot is already due, the caller starts now and later
        reservations stay spaced from this start; otherwise the caller joins
        the FIFO queue one interval behind the last reserved slot.
        """
        now = self._clock()
        if self._last_slot is None:
            # The first request starts immediately; only elapsed time since
            # this start constrains later reservations.
            self._last_slot = now
            return None
        if self._waiters:
            slot = self._waiters[-1].slot + interval
        else:
            slot = self._last_slot + interval
            if slot <= now:
                self._last_slot = now
                return None
        waiter = _AdmissionWaiter(slot)
        self._waiters.append(waiter)
        self._last_slot = slot
        return waiter

    async def _wait_for_slot(self, waiter: _AdmissionWaiter) -> None:
        """Sleep until the waiter's reserved slot, re-deriving on reclaim wakes."""
        while True:
            async with self._lock:
                delay = waiter.slot - self._clock()
                if delay <= 0:
                    # The slot is already due: a reclaim shifted it into the
                    # past, or the clock advanced between waits.
                    self._waiters.remove(waiter)
                    return
            if await self._sleep_until_due(waiter, delay):
                # The wait elapsed, so the reserved slot is now due.
                async with self._lock:
                    self._waiters.remove(waiter)
                return

    async def _sleep_until_due(self, waiter: _AdmissionWaiter, delay: float) -> bool:
        """Sleep for ``delay`` or until the waiter is woken by a slot reclaim.

        Returns ``True`` when the sleep ran to completion, so the reserved
        slot is due; ``False`` when a reclaim ahead of this waiter woke it
        early to re-derive its remaining wait from its updated slot.
        """
        sleep_task = asyncio.ensure_future(self._sleep(delay))
        wake_task = asyncio.ensure_future(waiter.wake.wait())
        try:
            await asyncio.wait(
                {sleep_task, wake_task}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for task in (sleep_task, wake_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(sleep_task, wake_task, return_exceptions=True)
        if wake_task.done() and not wake_task.cancelled() and wake_task.result():
            waiter.wake.clear()
            return False
        return True

    def _reclaim_reservation(self, waiter: _AdmissionWaiter, interval: float) -> None:
        """Remove a non-admitted waiter and reclaim its slot for later waiters.

        Every waiter behind the removed one shifts one interval earlier and is
        woken so it re-derives its remaining wait, preserving FIFO order and
        start spacing. The caller holds the scheduling lock.
        """
        try:
            index = self._waiters.index(waiter)
        except ValueError:
            # The waiter's slot was already consumed by admission; there is
            # no reservation left to reclaim.
            return
        self._waiters.remove(waiter)
        for later in list(self._waiters)[index:]:
            later.slot -= interval
            later.wake.set()
        if self._waiters:
            self._last_slot = self._waiters[-1].slot
        else:
            assert self._last_slot is not None
            self._last_slot -= interval

    async def __aenter__(self) -> BoundedLimiter:
        await self.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc_val: object,
        exc_tb: object,
    ) -> None:
        self.release()


class ProviderHttpClient:  # pylint: disable=too-many-instance-attributes
    """Bounded, retry-capable HTTP client for live evidence providers.

    Enforces HTTPS URL validation, timeout, no-redirects, bounded streaming,
    and post-jitter retry delay clamping.
    """

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        *,
        client: httpx.AsyncClient | None = None,
        policy: ProviderHttpPolicy | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        base_delay_seconds: float = _DEFAULT_BASE_DELAY_SECONDS,
        max_delay_seconds: float = _DEFAULT_MAX_DELAY_SECONDS,
        jitter_ratio: float = _DEFAULT_JITTER_RATIO,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        sleep: AsyncSleep = _default_sleep,
        clock: Clock = _default_monotonic,
        utc_clock: UtcClock = _default_utc_now,
        jitter_fn: JitterFn = _default_jitter,
        limiter: BoundedLimiter | None = None,
    ) -> None:
        if policy is not None and any(
            value != default
            for value, default in (
                (timeout_seconds, _DEFAULT_TIMEOUT_SECONDS),
                (max_retries, _DEFAULT_MAX_RETRIES),
                (base_delay_seconds, _DEFAULT_BASE_DELAY_SECONDS),
                (max_delay_seconds, _DEFAULT_MAX_DELAY_SECONDS),
                (jitter_ratio, _DEFAULT_JITTER_RATIO),
                (max_response_bytes, _DEFAULT_MAX_RESPONSE_BYTES),
            )
        ):
            raise ValueError("policy cannot be combined with legacy policy arguments")
        if policy is not None:
            self._policy = policy
        else:
            self._policy = ProviderHttpPolicy(
                timeout_seconds=timeout_seconds,
                max_retries=max_retries,
                base_delay_seconds=base_delay_seconds,
                max_delay_seconds=max_delay_seconds,
                jitter_ratio=jitter_ratio,
                max_response_bytes=max_response_bytes,
            )

        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._policy.timeout_seconds),
                follow_redirects=False,
                headers={
                    "User-Agent": _USER_AGENT,
                    "Accept": "application/json",
                },
            )
            self._owns_client = True

        self._sleep = sleep
        self._clock = clock
        self._utc_clock = utc_clock
        self._jitter_fn = jitter_fn
        self._limiter = limiter

    @property
    def policy(self) -> ProviderHttpPolicy:
        """The active HTTP configuration policy."""
        return self._policy

    async def aclose(self) -> None:
        """Close the owned HTTP client, if any."""
        if self._owns_client:
            await self._client.aclose()

    def compute_backoff_delay(
        self,
        retry_number: int,
        retry_after_seconds: int | None = None,
    ) -> float:
        """Compute the backoff delay before the next retry attempt.

        The exponential delay for ``retry_number`` is computed first, and
        symmetric bounded jitter is applied to that component alone. When a
        valid ``retry_after_seconds`` is present, the delay is the larger of
        the jittered exponential delay and ``retry_after_seconds``, so a
        negative jitter can never schedule a retry earlier than a
        provider-directed minimum that lies within the local cap. The final
        result is clamped to ``[0, max_delay_seconds]``, keeping the
        configured maximum as the hard upper bound even when the provider
        asks for a longer wait. The externally reported
        ``retry_after_seconds`` value is never altered by this clamping.
        """
        exponential = self._policy.base_delay_seconds * (2.0**retry_number)
        jitter = (
            (self._jitter_fn() * 2.0 - 1.0) * self._policy.jitter_ratio * exponential
        )
        delay = max(0.0, exponential + jitter)
        if retry_after_seconds is not None and retry_after_seconds >= 0:
            delay = max(delay, float(retry_after_seconds))
        return max(0.0, min(delay, self._policy.max_delay_seconds))

    async def request_json(  # pylint: disable=too-many-arguments
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        accept_statuses: set[int] | None = None,
        accepted_media_types: tuple[str, ...] | None = None,
    ) -> HttpOutcome:
        """Execute a bounded, retry-capable HTTP request and return parsed JSON.

        Validates the URL before acquiring permits or performing I/O.
        Enforces timeout and no-redirect policies on every attempt.
        """
        canonical_url = validate_provider_url(url)
        accepted_statuses = {200} if accept_statuses is None else accept_statuses
        media_types = (
            _DEFAULT_ACCEPTED_MEDIA_TYPES
            if accepted_media_types is None
            else accepted_media_types
        )

        request_headers = {
            "User-Agent": _USER_AGENT,
            "Accept": "application/json",
        }
        if headers:
            request_headers.update(headers)

        return await self._execute_retry_loop(
            method,
            canonical_url,
            params,
            request_headers,
            accepted_statuses,
            media_types,
        )

    async def _execute_retry_loop(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None,
        headers: dict[str, str],
        accepted_statuses: set[int],
        media_types: tuple[str, ...],
    ) -> HttpOutcome:
        """Execute request attempts up to max_retries with backoff."""
        attempt = 0
        last_outcome: HttpOutcome | None = None
        start_time = self._clock()

        while attempt <= self._policy.max_retries:
            attempt += 1

            if self._limiter is not None:
                async with self._limiter:
                    raw_outcome = await self._execute_attempt(
                        method,
                        url,
                        params,
                        headers,
                        accepted_statuses,
                        media_types,
                        start_time,
                    )
            else:
                raw_outcome = await self._execute_attempt(
                    method,
                    url,
                    params,
                    headers,
                    accepted_statuses,
                    media_types,
                    start_time,
                )

            result = dataclasses.replace(
                raw_outcome,
                attempt_count=attempt,
                retry_count=attempt - 1,
            )
            last_outcome = result

            if result.final_error_code is None or not result.final_error_code.retryable:
                return result

            if attempt > self._policy.max_retries:
                return result

            delay = self.compute_backoff_delay(attempt - 1, result.retry_after_seconds)
            await self._sleep(delay)

        assert last_outcome is not None
        return last_outcome

    async def _execute_attempt(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None,
        headers: dict[str, str],
        accept_statuses: set[int],
        accepted_media_types: tuple[str, ...],
        start_time: float,
    ) -> HttpOutcome:
        """Execute a single attempt with streaming, Content-Type, and bounds checks."""
        try:
            async with self._client.stream(
                method,
                url,
                params=params,
                headers=headers,
                follow_redirects=False,
                timeout=self._policy.timeout_seconds,
            ) as response:
                status = response.status_code
                duration = self._clock() - start_time
                error_code = classify_http_status(status, accept_statuses)

                if error_code is None:
                    return await self._handle_accepted_response(
                        response, status, accepted_media_types, duration
                    )

                retry_after = parse_retry_after_header(response, self._utc_clock)
                msg = status_error_message(status, error_code)
                return HttpOutcome(
                    attempt_count=0,
                    retry_count=0,
                    final_status=status,
                    final_error_code=error_code,
                    final_error_message=msg,
                    duration_seconds=duration,
                    retry_after_seconds=retry_after,
                )

        except httpx.TimeoutException:
            return HttpOutcome(
                attempt_count=0,
                retry_count=0,
                final_status=None,
                final_error_code=ProviderErrorCode.TIMEOUT,
                final_error_message="request timed out",
                duration_seconds=self._clock() - start_time,
            )
        except httpx.TransportError:
            return HttpOutcome(
                attempt_count=0,
                retry_count=0,
                final_status=None,
                final_error_code=ProviderErrorCode.PROVIDER_UNAVAILABLE,
                final_error_message="provider transport unavailable",
                duration_seconds=self._clock() - start_time,
            )

    async def _handle_accepted_response(
        self,
        response: httpx.Response,
        status: int,
        accepted_media_types: tuple[str, ...],
        duration: float,
    ) -> HttpOutcome:
        """Validate content type, stream bounded body, and parse JSON."""
        content_type = response.headers.get("Content-Type")
        if not check_content_type(content_type, accepted_media_types):
            return HttpOutcome(
                attempt_count=0,
                retry_count=0,
                final_status=status,
                final_error_code=ProviderErrorCode.INVALID_RESPONSE,
                final_error_message="unsupported response content type",
                duration_seconds=duration,
            )

        try:
            body = await read_bounded_body(response, self._policy.max_response_bytes)
        except httpx.DecodingError:
            # HTTPX performs content decoding while streaming; a malformed
            # advertised encoding (e.g. ``Content-Encoding: gzip`` with a
            # non-gzip body) is a malformed successful response, not a
            # transport failure. It is non-retryable INVALID_RESPONSE with a
            # fixed safe message that never exposes decoder details, body,
            # URL, headers, or query values.
            return HttpOutcome(
                attempt_count=0,
                retry_count=0,
                final_status=status,
                final_error_code=ProviderErrorCode.INVALID_RESPONSE,
                final_error_message="invalid response content encoding",
                duration_seconds=duration,
            )
        except ValueError as exc:
            # Distinguish malformed size metadata from oversize bodies in the
            # safe internal message; both remain non-retryable INVALID_RESPONSE.
            return HttpOutcome(
                attempt_count=0,
                retry_count=0,
                final_status=status,
                final_error_code=ProviderErrorCode.INVALID_RESPONSE,
                final_error_message=str(exc) or "response too large",
                duration_seconds=duration,
            )

        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return HttpOutcome(
                attempt_count=0,
                retry_count=0,
                final_status=status,
                final_error_code=ProviderErrorCode.INVALID_RESPONSE,
                final_error_message="malformed JSON",
                duration_seconds=duration,
            )

        return HttpOutcome(
            attempt_count=0,
            retry_count=0,
            final_status=status,
            final_error_code=None,
            final_error_message=None,
            duration_seconds=duration,
            response_bytes=body,
            response_json=parsed,
        )
