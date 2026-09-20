# SPDX-License-Identifier: AGPL-3.0-only
"""Provider HTTP boundary telemetry tests (PR 29B, H1..H7).

Proves the shared ``ProviderHttpClient`` aggregate telemetry: one logical
request duration histogram, actual attempt count, retry count, and failure
count, while URLs/paths/query/body/response content never become telemetry.
Retry/backoff behavior is unchanged; cancellation propagates.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from httpx import MockTransport
from opentelemetry.sdk.metrics.export import Metric

from agentic_threat_investigator.infrastructure.providers.http import (
    ProviderHttpClient,
    ProviderHttpPolicy,
)
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.otel import (
    counter_value,
    data_point_attributes,
    histogram_count,
    histogram_sum,
    metrics_by_name,
)
from tests.support.provider_http import no_op_sleep, zero_jitter


def _ok_json_handler(_: httpx.Request) -> httpx.Response:
    """Serve one valid JSON success response."""
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        json={"status": "ok"},
    )


def _retry_then_ok_handler() -> tuple[httpx.AsyncClient, list[int]]:
    """Build a transport that fails once with 503 then succeeds."""
    statuses: list[int] = []

    def handler(_: httpx.Request) -> httpx.Response:
        statuses.append(503)
        if len(statuses) == 1:
            return httpx.Response(
                503, headers={"Content-Type": "application/json"}, json={}
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"status": "ok"},
        )

    return httpx.AsyncClient(transport=MockTransport(handler)), statuses


async def _client_for(transport: httpx.AsyncClient) -> ProviderHttpClient:
    """Build one ProviderHttpClient over a deterministic transport."""
    return ProviderHttpClient(
        client=transport,
        sleep=no_op_sleep,
        jitter_fn=zero_jitter,
        policy=ProviderHttpPolicy(max_retries=2, base_delay_seconds=1.0),
    )


def _recorded(
    telemetry: SimpleNamespace,
) -> Mapping[str, Metric]:
    """Return metrics recorded by the in-memory reader."""
    return metrics_by_name(telemetry.reader)


class TestHttpAttemptTelemetry:
    """H1..H3: attempt/retry/failure accounting of one logical request."""

    @pytest.mark.asyncio
    async def test_h1_first_attempt_success(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """One logical request with one successful attempt (H1)."""
        async with httpx.AsyncClient(
            transport=MockTransport(_ok_json_handler)
        ) as client:
            http = await _client_for(client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
        assert outcome.final_error_code is None and outcome.attempt_count == 1
        recorded = _recorded(in_memory_persistence_telemetry)  # type: ignore[arg-type]
        assert counter_value(recorded[Metrics.PROVIDER_HTTP_ATTEMPTS]) == 1
        assert Metrics.PROVIDER_HTTP_RETRIES not in recorded
        assert Metrics.PROVIDER_HTTP_FAILURES not in recorded
        duration = recorded[DurationMetrics.PROVIDER_HTTP]
        assert histogram_count(duration) == 1
        assert histogram_sum(duration) >= 0.0
        assert data_point_attributes(duration)["ati.outcome"] == "success"

    @pytest.mark.asyncio
    async def test_h2_retry_then_success(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """Retry then success: 1 logical op, 2 attempts, 1 retry (H2)."""
        client, statuses = _retry_then_ok_handler()
        async with client:
            http = await _client_for(client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
        assert outcome.final_error_code is None
        assert outcome.attempt_count == 2 and outcome.retry_count == 1
        assert len(statuses) == 2
        recorded = _recorded(in_memory_persistence_telemetry)  # type: ignore[arg-type]
        assert counter_value(recorded[Metrics.PROVIDER_HTTP_ATTEMPTS]) == 2
        assert counter_value(recorded[Metrics.PROVIDER_HTTP_RETRIES]) == 1
        assert Metrics.PROVIDER_HTTP_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_h3_retries_exhausted(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """Exhausted retries keep the typed failure and count a failure (H3)."""

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                503, headers={"Content-Type": "application/json"}, json={}
            )

        async with httpx.AsyncClient(transport=MockTransport(handler)) as client:
            http = await _client_for(client)
            outcome = await http.request_json("GET", "https://test.example.com/api")
        assert outcome.final_error_code is not None
        assert outcome.attempt_count == 3 and outcome.retry_count == 2
        recorded = _recorded(in_memory_persistence_telemetry)  # type: ignore[arg-type]
        assert counter_value(recorded[Metrics.PROVIDER_HTTP_ATTEMPTS]) == 3
        assert counter_value(recorded[Metrics.PROVIDER_HTTP_RETRIES]) == 2
        assert counter_value(recorded[Metrics.PROVIDER_HTTP_FAILURES]) == 1
        duration = recorded[DurationMetrics.PROVIDER_HTTP]
        assert data_point_attributes(duration)["ati.outcome"] == "error"

    @pytest.mark.asyncio
    async def test_h6_no_url_or_path_attributes(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """No URL/path/query/header/body value appears in any attribute (H6/H7)."""
        async with httpx.AsyncClient(
            transport=MockTransport(_ok_json_handler)
        ) as client:
            http = await _client_for(client)
            await http.request_json(
                "GET",
                "https://test.example.com/api/v1/iocs/malicious-domain.test",
            )
        recorded = _recorded(in_memory_persistence_telemetry)  # type: ignore[arg-type]
        for metric in recorded.values():
            for point in metric.data.data_points:
                attributes: dict[str, Any] = dict(point.attributes or {})
                for key, value in attributes.items():
                    assert key.startswith("ati.")
                    assert "example.com" not in str(value)
                    assert "malicious-domain" not in str(value)
                    assert "api/v1" not in str(value)

    @pytest.mark.asyncio
    async def test_h4_retry_after_delay_semantics_unchanged(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """Retry-After still controls the retry delay with telemetry active (H4)."""
        sleeps: list[float] = []

        async def _recording_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        def _rate_limited_then_ok(_: httpx.Request) -> httpx.Response:
            if len(sleeps) == 0:
                return httpx.Response(
                    429,
                    headers={"Content-Type": "application/json", "Retry-After": "7"},
                    json={},
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"status": "ok"},
            )

        async with httpx.AsyncClient(
            transport=MockTransport(_rate_limited_then_ok)
        ) as client:
            http = ProviderHttpClient(
                client=client,
                sleep=_recording_sleep,
                jitter_fn=zero_jitter,
                policy=ProviderHttpPolicy(
                    max_retries=1, base_delay_seconds=1.0, max_delay_seconds=30.0
                ),
            )
            outcome = await http.request_json("GET", "https://test.example.com/api")
        assert outcome.final_error_code is None and outcome.attempt_count == 2
        # The provider-directed delay (>= Retry-After) is applied unchanged.
        assert sleeps and sleeps[0] >= 7.0
        recorded = _recorded(in_memory_persistence_telemetry)  # type: ignore[arg-type]
        assert counter_value(recorded[Metrics.PROVIDER_HTTP_ATTEMPTS]) == 2

    @pytest.mark.asyncio
    async def test_h5_cancellation_propagates_without_telemetry(
        self, in_memory_persistence_telemetry: object
    ) -> None:
        """Cancellation propagates unchanged and records nothing (H5)."""

        def _retryable(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                503, headers={"Content-Type": "application/json"}, json={}
            )

        async def _cancel(_: float) -> None:
            raise asyncio.CancelledError()

        async with httpx.AsyncClient(transport=MockTransport(_retryable)) as client:
            http = ProviderHttpClient(
                client=client,
                sleep=_cancel,
                jitter_fn=zero_jitter,
                policy=ProviderHttpPolicy(max_retries=2),
            )
            with pytest.raises(asyncio.CancelledError):
                await http.request_json("GET", "https://test.example.com/api")
        recorded = _recorded(in_memory_persistence_telemetry)  # type: ignore[arg-type]
        assert Metrics.PROVIDER_HTTP_ATTEMPTS not in recorded
        assert Metrics.PROVIDER_HTTP_FAILURES not in recorded
        assert DurationMetrics.PROVIDER_HTTP not in recorded
