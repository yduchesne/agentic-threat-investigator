# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic TAXII 2.1 wire-boundary fixtures for tests.

Test-only support; no production package may import from it. Helpers build
TAXII 2.1 collection-object envelopes and HTTP responses with the real media
type and date-added headers, and a small recorded fake server that speaks the
actual TAXII 2.1 pagination contract (``more`` + opaque ``next``) so tests
exercise the real acquisition path against a deterministic external
boundary. Only the external TAXII server is faked — never ATI's parser,
converter, producer, broker, or database.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

TAXII_API_ROOT = "https://taxii.example.test/root"
TAXII_COLLECTION_ID = "collection-00000000-0000-4000-8000-000000000001"
TAXII_OBJECTS_URL = f"{TAXII_API_ROOT}/collections/{TAXII_COLLECTION_ID}/objects/"
TAXII_MEDIA_TYPE = "application/taxii+json"
TAXII_ACCEPT = "application/taxii+json;version=2.1"
BEARER_TOKEN = "fake-test-taxii-bearer-token"
DATE_ADDED_1 = "2026-07-01T00:00:00Z"
DATE_ADDED_2 = "2026-07-01T00:30:00Z"
DATE_ADDED_3 = "2026-07-01T01:00:00Z"
NEXT_1 = "opaque-token-page-1"
NEXT_2 = "opaque token/with+punctuation=.."

StixObject = dict[str, Any]
"""One raw decoded STIX 2.1 object member of a TAXII envelope."""


def taxii_envelope(
    *objects: StixObject,
    more: bool = False,
    next_token: str | None = None,
) -> dict[str, Any]:
    """Build one TAXII 2.1 collection-object envelope preserving member order."""
    payload: dict[str, Any] = {"objects": list(objects)}
    if more:
        payload["more"] = True
        if next_token is not None:
            payload["next"] = next_token
    return payload


def taxii_response(
    payload: object,
    *,
    status: int = 200,
    first: str | None = None,
    last: str | None = None,
    content_type: str = TAXII_MEDIA_TYPE,
    extra_headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build one deterministic TAXII HTTP response with bounded metadata."""
    headers: dict[str, str] = {"Content-Type": content_type}
    if first is not None:
        headers["X-TAXII-Date-Added-First"] = first
    if last is not None:
        headers["X-TAXII-Date-Added-Last"] = last
    if extra_headers:
        headers.update(extra_headers)
    return httpx.Response(
        status,
        content=json.dumps(payload).encode("utf-8"),
        headers=headers,
    )


def client_for(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    """Build a real ``httpx`` mock-transport client for the given handler."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@dataclass
class RecordedRequest:
    """One bounded record of a fake-TAXII request."""

    method: str
    url: str
    headers: dict[str, str]
    query: dict[str, str]


@dataclass
class RecordedTaxiiServer:
    """Deterministic fake TAXII 2.1 server recording every request.

    ``pages`` is a list of ``(response, is_continuation_of_next)`` tuples:
    the first entry answers the first page, and each following entry answers
    the page whose request carries the previous entry's ``next`` token. A
    request with an unexpected ``next`` value (or an unexpected added_after)
    fails the test with a clear assertion error.
    """

    pages: list[tuple[httpx.Response, str | None]]
    requests: list[RecordedRequest] = field(default_factory=list)

    def handler(self) -> Callable[[httpx.Request], httpx.Response]:
        """Return the MockTransport handler that serves and records pages."""

        def _handler(request: httpx.Request) -> httpx.Response:
            query: dict[str, str] = {}
            for key, value in request.url.params.multi_items():
                query.setdefault(key, value)
            self.requests.append(
                RecordedRequest(
                    method=request.method,
                    url=str(request.url),
                    headers=dict(request.headers),
                    query=query,
                )
            )
            index = len(self.requests) - 1
            if index >= len(self.pages):
                raise AssertionError(
                    f"fake TAXII server received an unexpected request #{index}"
                )
            response, expected_next = self.pages[index]
            if expected_next is not None:
                sent_next = query.get("next")
                assert sent_next == expected_next, (
                    f"page {index + 1} must carry next={expected_next!r}, "
                    f"got {sent_next!r}"
                )
            return response

        return _handler
