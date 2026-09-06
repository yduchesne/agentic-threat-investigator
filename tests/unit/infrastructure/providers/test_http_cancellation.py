# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Cancellation, streaming, and status-boundary tests for the HTTP layer."""

from __future__ import annotations

import asyncio
import typing

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    HttpOutcome,
    ProviderHttpClient,
    ProviderHttpPolicy,
    RateLimiterSettings,
)

from .limiter_fakes import FakeRateClock, GatedSleep


class _RecordingSleep:  # pylint: disable=too-few-public-methods
    """Records sleep calls for assertion."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _zero_jitter() -> float:
    """Neutral jitter value (0.5 maps to zero offset)."""
    return 0.5


async def _request_outcome(
    client: httpx.AsyncClient,
    **http_kwargs: typing.Any,
) -> HttpOutcome:
    """Issue one deterministic request through a client built from kwargs."""
    http = ProviderHttpClient(client=client, **http_kwargs)
    return await http.request_json("GET", "https://test.example.com/api")


class _BlockingAsyncStream(httpx.AsyncByteStream):
    """A streamed response body with no Content-Length that can block mid-stream."""

    def __init__(
        self,
        chunks: list[bytes],
        *,
        blocked: asyncio.Event | None = None,
        blocker: asyncio.Event | None = None,
    ) -> None:
        self._chunks = chunks
        self._blocked = blocked
        self._blocker = blocker

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        for index, chunk in enumerate(self._chunks):
            if (
                index == len(self._chunks) - 1
                and self._blocked is not None
                and self._blocker is not None
            ):
                self._blocked.set()
                await self._blocker.wait()
            yield chunk


def _advance_loop(steps: int = 8) -> typing.Awaitable[None]:
    """Return an awaitable that yields control to the event loop several times."""

    async def _run() -> None:
        for _ in range(steps):
            await asyncio.sleep(0)

    return _run()


@pytest.mark.asyncio
class TestHttpClientCancellationAndStreaming:
    """Cancellation propagation, permit release, and streamed body bounds."""

    @staticmethod
    def _client_with_limiter(
        client: httpx.AsyncClient,
        **kwargs: typing.Any,
    ) -> tuple[ProviderHttpClient, BoundedLimiter]:
        """Build a ProviderHttpClient with a fresh attached limiter."""
        limiter = BoundedLimiter(RateLimiterSettings(max_concurrency=1))
        http = ProviderHttpClient(client=client, limiter=limiter, **kwargs)
        return http, limiter

    async def _assert_permit_available(self, limiter: BoundedLimiter) -> None:
        """Prove the limiter permit was released after cancellation."""
        acquired_within_budget = True
        try:
            await asyncio.wait_for(limiter.acquire(), timeout=0.1)
        except TimeoutError:
            acquired_within_budget = False
        assert acquired_within_budget, "limiter permit was leaked after cancellation"
        limiter.release()

    async def test_cancellation_while_waiting_for_semaphore(self) -> None:
        """Cancelling a request queued on the limiter propagates and frees no state."""
        io_issued = False

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal io_issued
            io_issued = True
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json={}
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http, limiter = self._client_with_limiter(client)
            await limiter.acquire()  # Hold the only permit

            task = asyncio.create_task(
                http.request_json("GET", "https://test.example.com/api")
            )
            await _advance_loop()
            assert io_issued is False  # Still waiting for the semaphore

            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            limiter.release()
            await self._assert_permit_available(limiter)

    async def test_cancellation_during_transport_io(self) -> None:
        """Cancelling mid-transport propagates unchanged and releases the permit."""
        request_started = asyncio.Event()
        release = asyncio.Event()

        async def _handler(_: httpx.Request) -> httpx.Response:
            request_started.set()
            await release.wait()
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json={}
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http, limiter = self._client_with_limiter(client)

            task = asyncio.create_task(
                http.request_json("GET", "https://test.example.com/api")
            )
            await request_started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            await self._assert_permit_available(limiter)

    async def test_cancellation_during_retry_sleep(self) -> None:
        """Cancelling during a retry sleep propagates and releases the permit."""
        attempts = 0
        sleep_started = asyncio.Event()
        blocker = asyncio.Event()

        async def _blocking_sleep(_: float) -> None:
            sleep_started.set()
            await blocker.wait()

        def _handler(_: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(503, json={})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http, limiter = self._client_with_limiter(
                client,
                max_retries=1,
                base_delay_seconds=0.01,
                sleep=_blocking_sleep,
                jitter_fn=_zero_jitter,
            )

            task = asyncio.create_task(
                http.request_json("GET", "https://test.example.com/api")
            )
            await sleep_started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            assert attempts == 1  # Cancelled before the second attempt
            await self._assert_permit_available(limiter)

    async def test_cancellation_during_streamed_iteration(self) -> None:
        """Cancelling while iterating a streamed body propagates and frees the permit."""
        stream_blocked = asyncio.Event()
        blocker = asyncio.Event()

        def _handler(_: httpx.Request) -> httpx.Response:
            stream = _BlockingAsyncStream(
                [b"partial", b"data"],
                blocked=stream_blocked,
                blocker=blocker,
            )
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, content=stream
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http, limiter = self._client_with_limiter(client)

            task = asyncio.create_task(
                http.request_json("GET", "https://test.example.com/api")
            )
            await stream_blocked.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            await self._assert_permit_available(limiter)

    async def test_streamed_overflow_without_content_length(self) -> None:
        """A streamed body exceeding the byte limit fails without Content-Length."""

        def _handler(_: httpx.Request) -> httpx.Response:
            async def _chunks() -> typing.AsyncIterator[bytes]:
                for _ in range(10):
                    yield b"x" * 100

            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, content=_chunks()
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            outcome = await _request_outcome(client, max_response_bytes=100)
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert outcome.final_error_message == "response too large"

    @pytest.mark.parametrize(
        "content_length", ["not-a-number", "-5"], ids=["malformed", "negative"]
    )
    async def test_bad_content_length_through_client_path(
        self, content_length: str
    ) -> None:
        """Malformed and negative Content-Length produce INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": content_length,
                },
                content=b"{}",
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            outcome = await _request_outcome(client)
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert outcome.final_error_message == "invalid response size metadata"

    async def test_missing_content_type_through_client_path(self) -> None:
        """A successful response with no Content-Type header is rejected."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"{}")

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            outcome = await _request_outcome(client)
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert "content type" in (outcome.final_error_message or "")

    async def test_permanent_400_through_client_path(self) -> None:
        """An HTTP 400 response returns INVALID_RESPONSE without retry."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"error": "bad request"})

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            outcome = await _request_outcome(client)
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert outcome.attempt_count == 1

    async def test_transport_error_then_success_and_exhaustion(self) -> None:
        """Network errors retry to success and exhaust to PROVIDER_UNAVAILABLE."""
        call_count = 0

        def _failing_then_ok(_: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.ConnectError("connection refused")
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json={}
            )

        transport = MockTransport(_failing_then_ok)
        async with httpx.AsyncClient(transport=transport) as client:
            outcome = await _request_outcome(
                client,
                max_retries=1,
                base_delay_seconds=0.01,
                sleep=_RecordingSleep(),
                jitter_fn=_zero_jitter,
            )
            assert outcome.final_error_code is None
            assert outcome.attempt_count == 2
            assert outcome.retry_count == 1

        def _always_failing(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        transport = MockTransport(_always_failing)
        async with httpx.AsyncClient(transport=transport) as client:
            outcome = await _request_outcome(
                client,
                max_retries=2,
                base_delay_seconds=0.01,
                sleep=_RecordingSleep(),
                jitter_fn=_zero_jitter,
            )
            assert outcome.final_error_code == ProviderErrorCode.PROVIDER_UNAVAILABLE
            assert outcome.attempt_count == 3

    async def test_mixed_policy_and_legacy_arguments_rejected(self) -> None:
        """Explicit policy plus nondefault legacy arguments raise ValueError."""
        with pytest.raises(ValueError, match="policy cannot be combined"):
            ProviderHttpClient(policy=ProviderHttpPolicy(), max_retries=3)
        with pytest.raises(ValueError, match="policy cannot be combined"):
            ProviderHttpClient(policy=ProviderHttpPolicy(), timeout_seconds=99.0)

    async def test_empty_accepted_status_set_rejects_all(self) -> None:
        """An empty accepted-status set classifies even a 200 as INVALID_RESPONSE."""

        def _handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json={}
            )

        transport = MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http = ProviderHttpClient(client=client)
            outcome = await http.request_json(
                "GET", "https://test.example.com/api", accept_statuses=set()
            )
            assert outcome.final_error_code == ProviderErrorCode.INVALID_RESPONSE
            assert "unexpected HTTP 200" in (outcome.final_error_message or "")


@pytest.mark.asyncio
class TestRateAdmissionCancellationRecovery:
    """Canceled rate waiters reclaim their slots; later requests are not delayed."""

    @staticmethod
    def _limiter(clock: FakeRateClock, sleep: GatedSleep) -> BoundedLimiter:
        """Build a one-request-per-second limiter on the injected fakes."""
        return BoundedLimiter(
            RateLimiterSettings(max_concurrency=5, requests_per_second=1.0),
            sleep=sleep,
            clock=clock,
        )

    async def test_canceled_head_waiter_leaves_next_real_slot_free(self) -> None:
        """A canceled first waiter delays the next request by one slot, not two."""
        clock = FakeRateClock()
        sleep = GatedSleep(clock)
        limiter = self._limiter(clock, sleep)

        # The first request is admitted immediately and consumes slot 0.0.
        await limiter.acquire()
        limiter.release()

        second = asyncio.create_task(limiter.acquire())
        await _advance_loop()
        assert sleep.calls == pytest.approx([1.0])

        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
        assert sleep.calls == pytest.approx([1.0])  # canceled before admission

        third = asyncio.create_task(limiter.acquire())
        await _advance_loop()
        # The next request waits for the next real slot (1.0), not the slot
        # after the canceled reservation (2.0).
        assert sleep.calls == pytest.approx([1.0, 1.0])
        sleep.gate(1).set()
        await asyncio.wait_for(third, timeout=1.0)
        limiter.release()

    async def test_canceled_waiter_burst_does_not_delay_later_requests(self) -> None:
        """Canceling every queued waiter leaves only one slot of delay behind."""
        clock = FakeRateClock()
        sleep = GatedSleep(clock)
        limiter = self._limiter(clock, sleep)

        await limiter.acquire()
        limiter.release()

        tasks = [asyncio.create_task(limiter.acquire()) for _ in range(3)]
        await _advance_loop()
        assert sleep.calls == pytest.approx([1.0, 2.0, 3.0])

        for task in tasks:
            task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        assert all(isinstance(r, asyncio.CancelledError) for r in results)
        assert sleep.calls == pytest.approx([1.0, 2.0, 3.0])

        # A later request is not delayed by the canceled reservations: it
        # waits one interval from the last real slot, not four.
        later = asyncio.create_task(limiter.acquire())
        await _advance_loop()
        assert sleep.calls == pytest.approx([1.0, 2.0, 3.0, 1.0])
        sleep.gate(3).set()
        await asyncio.wait_for(later, timeout=1.0)
        limiter.release()

        # No semaphore permit leaked: after advancing past the consumed slot,
        # another acquisition is admitted without any waiting.
        clock.advance(1.0)
        check = asyncio.create_task(limiter.acquire())
        await _advance_loop()
        assert check.done()
        limiter.release()

    async def test_canceled_middle_waiter_preserves_fifo_progress_and_spacing(
        self,
    ) -> None:
        """A non-head cancellation shifts later waiters earlier, keeping order."""
        clock = FakeRateClock()
        sleep = GatedSleep(clock)
        limiter = self._limiter(clock, sleep)

        await limiter.acquire()
        limiter.release()

        tasks = [asyncio.create_task(limiter.acquire()) for _ in range(3)]
        await _advance_loop()
        assert sleep.calls == pytest.approx([1.0, 2.0, 3.0])

        tasks[1].cancel()
        with pytest.raises(asyncio.CancelledError):
            await tasks[1]
        await _advance_loop()
        # The waiter behind the canceled one is woken and re-derives its wait
        # to the reclaimed slot (2.0): spacing and FIFO order are preserved.
        assert sleep.calls == pytest.approx([1.0, 2.0, 3.0, 2.0])

        sleep.gate(0).set()
        await asyncio.wait_for(tasks[0], timeout=1.0)
        limiter.release()
        assert clock.now == pytest.approx(1.0)

        sleep.gate(3).set()
        await asyncio.wait_for(tasks[2], timeout=1.0)
        limiter.release()
        assert clock.now == pytest.approx(3.0)

        # The schedule compacted: a new request is admitted immediately at
        # its due slot instead of being pushed to the next free slot.
        fourth = asyncio.create_task(limiter.acquire())
        await _advance_loop()
        assert fourth.done()
        assert sleep.calls == pytest.approx([1.0, 2.0, 3.0, 2.0])
        limiter.release()
