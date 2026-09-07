# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Typed HTTP transport and client helpers for deterministic provider tests.

Test-only support; no production package may import from it. The helpers
wrap ``httpx.MockTransport`` so provider test modules stay focused on
provider-specific payloads and assertions.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest


async def no_op_sleep(_: float) -> None:
    """Non-blocking async sleep replacement for deterministic tests."""


def zero_jitter() -> float:
    """Deterministic zero-offset jitter callable."""
    return 0.5


def static_client(response: httpx.Response) -> httpx.AsyncClient:
    """Build a client serving one fixed response for every request."""
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda _: response))


def handler_client(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.AsyncClient:
    """Build a client dispatching to the given handler."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def failing_io_client() -> httpx.AsyncClient:
    """Build a client that fails the test if any HTTP I/O is attempted."""
    return httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: pytest.fail("provider must not perform HTTP I/O")
        )
    )


def json_response(status: int, payload: Any) -> httpx.Response:
    """Build a JSON response with the given status and payload."""
    return httpx.Response(status, json=payload)
