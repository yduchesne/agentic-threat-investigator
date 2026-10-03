# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR L-1 deterministic concurrency tests for GooglePublicDnsProvider.

After the sequential A gate, AAAA/CNAME/MX/NS/TXT/SOA must execute
concurrently through the real ``ProviderHttpClient`` and its real
``BoundedLimiter`` while evidence/error aggregation stays deterministic in
canonical ``_DOMAIN_RR_TYPES`` order. Every scheduling claim here is proven
with ``asyncio.Event`` barriers, counters, and entry/completion order
captured at the synthetic transport boundary — never with wall-clock sleeps
or live DNS.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import pytest
from httpx import AsyncBaseTransport, Request, Response

from agentic_threat_investigator.app.providers import ProviderErrorCode, ProviderResult
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import ConvertedEvidence, EvidenceType
from agentic_threat_investigator.domain.legacy_evidence import LegacyEvidence
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    _DOMAIN_RR_TYPES,
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpClient,
    RateLimiterSettings,
)

_POST_A_RR_TYPES = tuple(_DOMAIN_RR_TYPES[1:])

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)

_RR_NUMBERS: dict[str, int] = {
    "A": 1,
    "AAAA": 28,
    "CNAME": 5,
    "MX": 15,
    "NS": 2,
    "TXT": 16,
    "SOA": 6,
    "PTR": 12,
}

_RR_DATA: dict[str, str] = {
    "A": "192.0.2.1",
    "AAAA": "2001:db8::1",
    "CNAME": "canonical.example.",
    "MX": "10 mail.example.com.",
    "NS": "ns1.example.com.",
    "TXT": "v=spf1 -all",
    "SOA": "ns1.example. admin.example. 20260101 7200 3600 1209600 300",
}


def _json_response(body: dict[str, Any]) -> Response:
    """Build one successful DNS JSON response."""
    return Response(200, headers={"Content-Type": "application/json"}, json=body)


def _record(name: str, rr_type: str, data: str) -> dict[str, Any]:
    """Build one strictly typed answer record."""
    return {"name": name, "type": _RR_NUMBERS[rr_type], "TTL": 300, "data": data}


def _valid_responses() -> dict[str, Response]:
    """One valid answer response per domain RR type, owned by example.com."""
    return {
        rr: _json_response(
            {"Status": 0, "Answer": [_record("example.com.", rr, _RR_DATA[rr])]}
        )
        for rr in _DOMAIN_RR_TYPES
    }


def _legacy(item: ConvertedEvidence | LegacyEvidence) -> LegacyEvidence:
    """Narrow one legacy-provider output item to its transitional shape."""
    assert isinstance(item, LegacyEvidence)
    return item


def _evidence_types(result: ProviderResult) -> list[str]:
    """Return the evidence query types in final result order."""
    return [_legacy(evidence).facts["query_type"] for evidence in result.evidence]


class _DnsProbeTransport(AsyncBaseTransport):
    """Synthetic in-process DNS transport with deterministic per-request hooks.

    Each request is classified by its ``type`` query parameter. ``entry``
    runs when a request reaches the transport and ``before_return`` runs
    after the response is built and before it is returned; both are awaited,
    so tests can prove overlap, limiter bounding, completion ordering,
    cancellation settling, and unexpected-exception behavior without any
    wall-clock timing. ``entries`` captures arrival order, ``completions``
    captures return order, and one ``completed`` event per RR type is set the
    moment its response is handed back.
    """

    def __init__(
        self,
        *,
        responses: Mapping[str, Response] | None = None,
        entry: Callable[[str], Awaitable[None]] | None = None,
        before_return: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._responses = dict(responses or {})
        self._entry = entry
        self._before_return = before_return
        self.entries: list[str] = []
        self.completions: list[str] = []
        self.completed: dict[str, asyncio.Event] = {}

    async def handle_async_request(self, request: Request) -> Response:
        """Record arrival, run entry hook, build response, gate, and return."""
        rr_type = request.url.params.get("type") or "UNKNOWN"
        self.entries.append(rr_type)
        if self._entry is not None:
            await self._entry(rr_type)
        response = self._responses.get(rr_type)
        if response is None:
            response = _json_response({"Status": 0})
        if self._before_return is not None:
            await self._before_return(rr_type)
        self.completions.append(rr_type)
        self.completed.setdefault(rr_type, asyncio.Event()).set()
        return response


def _build_provider_and_client(
    transport: AsyncBaseTransport, *, max_concurrency: int
) -> tuple[GooglePublicDnsProvider, httpx.AsyncClient]:
    """Build the real provider over the real limiter plus its caller-owned client."""
    client = httpx.AsyncClient(transport=transport)
    provider = GooglePublicDnsProvider(
        ProviderHttpClient(
            client=client,
            limiter=BoundedLimiter(
                RateLimiterSettings(
                    max_concurrency=max_concurrency, requests_per_second=None
                )
            ),
            max_retries=0,
        ),
        clock=lambda: _FIXED_TS,
    )
    return provider, client


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestGoogleDnsConcurrentScheduling:
    """L-1 scheduling: sequential A gate, then bounded concurrent post-A queries."""

    async def test_clean_a_nxdomain_issues_exactly_one_request(self) -> None:
        """L1-DNS01: a clean first-A NXDOMAIN makes exactly one request."""
        transport = _DnsProbeTransport(responses={"A": _json_response({"Status": 3})})
        provider, client = _build_provider_and_client(transport, max_concurrency=6)
        try:
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="nx.example.com")
            )
        finally:
            await client.aclose()

        assert transport.entries == ["A"]
        assert result.evidence == ()
        assert result.errors == ()

    async def test_post_a_queries_overlap_after_sequential_a_gate(self) -> None:
        """L1-DNS02: A completes first; two post-A requests are jointly admitted."""
        post_in_flight = 0
        peak_post = 0
        two_post_a_admitted = asyncio.Event()
        a_returned = asyncio.Event()
        release = asyncio.Event()

        async def entry(rr_type: str) -> None:
            nonlocal post_in_flight, peak_post
            if rr_type == "A":
                return
            post_in_flight += 1
            peak_post = max(peak_post, post_in_flight)
            if peak_post >= 2:
                two_post_a_admitted.set()

        async def before_return(rr_type: str) -> None:
            nonlocal post_in_flight
            if rr_type == "A":
                a_returned.set()
                return
            await release.wait()
            post_in_flight -= 1

        transport = _DnsProbeTransport(
            responses=_valid_responses(),
            entry=entry,
            before_return=before_return,
        )
        provider, client = _build_provider_and_client(transport, max_concurrency=6)
        try:
            task = asyncio.create_task(
                provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
                )
            )
            await asyncio.wait_for(two_post_a_admitted.wait(), timeout=2.0)
            # A's request preceded every post-A request and its handler had
            # already returned before two post-A requests were holding the
            # real limiter permits simultaneously.
            assert transport.entries[0] == "A"
            assert a_returned.is_set()
            assert "A" not in transport.entries[1:]
            release.set()
            result = await asyncio.wait_for(task, timeout=2.0)
        finally:
            await client.aclose()

        assert peak_post >= 2
        assert len(transport.entries) == 1 + len(_POST_A_RR_TYPES)
        assert set(transport.entries) == set(_DOMAIN_RR_TYPES)
        assert _evidence_types(result) == list(_DOMAIN_RR_TYPES)

    async def test_real_limiter_bounds_http_concurrency_to_two(self) -> None:
        """L1-DNS03: six tasks may be scheduled but the real limiter caps at 2."""
        in_flight = 0
        peak = 0
        peak_reached = asyncio.Event()
        release = asyncio.Event()

        async def entry(rr_type: str) -> None:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            if peak >= 2:
                peak_reached.set()

        async def before_return(rr_type: str) -> None:
            nonlocal in_flight
            if rr_type != "A":
                await release.wait()
            in_flight -= 1

        transport = _DnsProbeTransport(
            responses=_valid_responses(),
            entry=entry,
            before_return=before_return,
        )
        provider, client = _build_provider_and_client(transport, max_concurrency=2)
        try:
            task = asyncio.create_task(
                provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
                )
            )
            await asyncio.wait_for(peak_reached.wait(), timeout=2.0)
            assert peak == 2
            release.set()
            result = await asyncio.wait_for(task, timeout=2.0)
        finally:
            await client.aclose()

        assert peak == 2
        assert len(transport.entries) == 7
        assert set(transport.entries) == set(_DOMAIN_RR_TYPES)
        assert _evidence_types(result) == list(_DOMAIN_RR_TYPES)

    async def test_real_limiter_bounds_http_concurrency_to_one(self) -> None:
        """L1-DNS04: with bound 1 every RR query still executes, never overlapping."""
        in_flight = 0
        peak = 0

        async def entry(rr_type: str) -> None:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)

        async def before_return(rr_type: str) -> None:
            nonlocal in_flight
            in_flight -= 1

        transport = _DnsProbeTransport(
            responses=_valid_responses(),
            entry=entry,
            before_return=before_return,
        )
        provider, client = _build_provider_and_client(transport, max_concurrency=1)
        try:
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
            )
        finally:
            await client.aclose()

        assert peak == 1
        assert len(transport.entries) == 7
        assert transport.entries[0] == "A"
        assert set(transport.entries) == set(_DOMAIN_RR_TYPES)
        assert _evidence_types(result) == list(_DOMAIN_RR_TYPES)


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestGoogleDnsDeterministicAggregation:
    """L-1 aggregation: canonical RR order regardless of completion order."""

    async def test_reverse_completion_keeps_canonical_evidence_order(self) -> None:
        """L1-DNS05: strictly reverse completion still yields canonical order."""
        gates = {rr: asyncio.Event() for rr in _POST_A_RR_TYPES}
        entered: set[str] = set()
        all_entered = asyncio.Event()

        async def entry(rr_type: str) -> None:
            if rr_type == "A":
                return
            entered.add(rr_type)
            if entered == set(_POST_A_RR_TYPES):
                all_entered.set()

        async def before_return(rr_type: str) -> None:
            if rr_type != "A":
                await gates[rr_type].wait()

        transport = _DnsProbeTransport(
            responses=_valid_responses(),
            entry=entry,
            before_return=before_return,
        )
        provider, client = _build_provider_and_client(transport, max_concurrency=6)
        try:
            task = asyncio.create_task(
                provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
                )
            )
            await asyncio.wait_for(all_entered.wait(), timeout=2.0)
            assert len(transport.entries) == 7
            for rr_type in reversed(_POST_A_RR_TYPES):
                gates[rr_type].set()
                await asyncio.wait_for(
                    transport.completed.setdefault(rr_type, asyncio.Event()).wait(),
                    timeout=2.0,
                )
            result = await asyncio.wait_for(task, timeout=2.0)
        finally:
            await client.aclose()

        # The completion order was forced to be the exact reverse of the
        # canonical order, so scheduler luck cannot produce the evidence order.
        assert transport.completions[0] == "A"
        assert transport.completions[1:] == list(reversed(_POST_A_RR_TYPES))
        assert _evidence_types(result) == list(_DOMAIN_RR_TYPES)

    async def test_reverse_failure_completion_keeps_canonical_error_order(
        self,
    ) -> None:
        """L1-DNS06: reverse completion of failures keeps canonical error order."""
        responses = {"A": _valid_responses()["A"]}
        responses.update({rr: Response(500, json={}) for rr in _POST_A_RR_TYPES})
        gates = {rr: asyncio.Event() for rr in _POST_A_RR_TYPES}
        entered: set[str] = set()
        all_entered = asyncio.Event()

        async def entry(rr_type: str) -> None:
            if rr_type == "A":
                return
            entered.add(rr_type)
            if entered == set(_POST_A_RR_TYPES):
                all_entered.set()

        async def before_return(rr_type: str) -> None:
            if rr_type != "A":
                await gates[rr_type].wait()

        transport = _DnsProbeTransport(
            responses=responses,
            entry=entry,
            before_return=before_return,
        )
        provider, client = _build_provider_and_client(transport, max_concurrency=6)
        try:
            task = asyncio.create_task(
                provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
                )
            )
            await asyncio.wait_for(all_entered.wait(), timeout=2.0)
            for rr_type in reversed(_POST_A_RR_TYPES):
                gates[rr_type].set()
                await asyncio.wait_for(
                    transport.completed.setdefault(rr_type, asyncio.Event()).wait(),
                    timeout=2.0,
                )
            result = await asyncio.wait_for(task, timeout=2.0)
        finally:
            await client.aclose()

        assert transport.completions[1:] == list(reversed(_POST_A_RR_TYPES))
        assert _evidence_types(result) == ["A"]
        assert [error.code for error in result.errors] == [
            ProviderErrorCode.PROVIDER_UNAVAILABLE for _ in _POST_A_RR_TYPES
        ]

    async def test_mixed_success_and_typed_failure_keeps_siblings(self) -> None:
        """L1-DNS07: a typed AAAA failure does not cancel successful siblings."""
        responses = _valid_responses()
        responses["AAAA"] = Response(500, json={})
        gate_aaaa = asyncio.Event()
        others_done = asyncio.Event()
        others_completed = 0

        async def before_return(rr_type: str) -> None:
            nonlocal others_completed
            if rr_type == "AAAA":
                await gate_aaaa.wait()
                return
            if rr_type != "A":
                others_completed += 1
                if others_completed == len(_POST_A_RR_TYPES) - 1:
                    others_done.set()

        transport = _DnsProbeTransport(
            responses=responses,
            before_return=before_return,
        )
        provider, client = _build_provider_and_client(transport, max_concurrency=6)
        try:
            task = asyncio.create_task(
                provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
                )
            )
            # Wait until every sibling has completed, then let AAAA finish
            # last: the typed failure of a later query must neither cancel
            # siblings nor move its error ahead of earlier RR types.
            await asyncio.wait_for(others_done.wait(), timeout=2.0)
            gate_aaaa.set()
            result = await asyncio.wait_for(task, timeout=2.0)
        finally:
            await client.aclose()

        assert transport.completions[0] == "A"
        assert transport.completions[-1] == "AAAA"
        assert len(transport.completions) == 7
        assert _evidence_types(result) == ["A", "CNAME", "MX", "NS", "TXT", "SOA"]
        assert len(result.errors) == 1
        assert result.errors[0].code == ProviderErrorCode.PROVIDER_UNAVAILABLE


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestGoogleDnsConcurrencyLifecycle:
    """L-1 cancellation and unexpected-exception semantics."""

    async def test_parent_cancellation_settles_children_without_orphan_work(
        self,
    ) -> None:
        """L1-DNS09: CancelledError propagates and no orphan DNS request survives."""
        gates = {rr: asyncio.Event() for rr in _POST_A_RR_TYPES}
        first_post_a = asyncio.Event()

        async def entry(rr_type: str) -> None:
            if rr_type != "A":
                first_post_a.set()

        async def before_return(rr_type: str) -> None:
            if rr_type != "A":
                await gates[rr_type].wait()

        transport = _DnsProbeTransport(
            responses=_valid_responses(),
            entry=entry,
            before_return=before_return,
        )
        provider, client = _build_provider_and_client(transport, max_concurrency=6)
        try:
            task = asyncio.create_task(
                provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
                )
            )
            await asyncio.wait_for(first_post_a.wait(), timeout=2.0)
            assert transport.entries[0] == "A"

            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2.0)

            settled_entries = len(transport.entries)
            for _ in range(5):
                await asyncio.sleep(0)
            assert len(transport.entries) == settled_entries
        finally:
            await client.aclose()

    async def test_unexpected_child_exception_is_not_hidden(self) -> None:
        """L1-DNS10: an unexpected child exception fails the whole operation."""
        gates = {rr: asyncio.Event() for rr in _POST_A_RR_TYPES if rr != "TXT"}

        async def entry(rr_type: str) -> None:
            if rr_type == "TXT":
                raise RuntimeError("unexpected provider bug")

        async def before_return(rr_type: str) -> None:
            if rr_type in gates:
                await gates[rr_type].wait()

        transport = _DnsProbeTransport(
            responses=_valid_responses(),
            entry=entry,
            before_return=before_return,
        )
        provider, client = _build_provider_and_client(transport, max_concurrency=6)
        try:
            task = asyncio.create_task(
                provider.investigate(
                    _FIXED_UUID, Entity(type=EntityType.DOMAIN, value="example.com")
                )
            )
            with pytest.raises(RuntimeError, match="unexpected provider bug"):
                await asyncio.wait_for(task, timeout=2.0)

            settled_entries = len(transport.entries)
            for _ in range(5):
                await asyncio.sleep(0)
            assert len(transport.entries) == settled_entries
        finally:
            await client.aclose()

    async def test_ptr_investigation_issues_exactly_one_query(self) -> None:
        """L1-DNS11: an IP/PTR investigation never enters the domain path."""
        transport = _DnsProbeTransport(
            responses={
                "PTR": _json_response(
                    {
                        "Status": 0,
                        "Answer": [
                            _record(
                                "1.2.0.192.in-addr.arpa.",
                                "PTR",
                                "host.example.com.",
                            )
                        ],
                    }
                )
            }
        )
        provider, client = _build_provider_and_client(transport, max_concurrency=6)
        try:
            result = await provider.investigate(
                _FIXED_UUID, Entity(type=EntityType.IP_ADDRESS, value="192.0.2.1")
            )
        finally:
            await client.aclose()

        assert transport.entries == ["PTR"]
        assert len(result.evidence) == 1
        assert _legacy(result.evidence[0]).type == EvidenceType.DNS
        assert _legacy(result.evidence[0]).facts["query_type"] == "PTR"
