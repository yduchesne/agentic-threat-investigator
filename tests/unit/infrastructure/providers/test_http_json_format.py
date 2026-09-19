# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Provider HTTP JSON-format contract tests (PR 28F-1 F1-J matrix).

Provider accepted-response bodies are parsed with ``orjson`` directly on the
bounded bytes (PR 28F-1). The observable contract is unchanged for valid
JSON and deliberately fail-closed (non-retryable
``INVALID_RESPONSE`` + ``SERIALIZATION`` + the fixed safe ``"malformed
JSON"`` message) for malformed syntax, invalid UTF-8, and the non-standard
``NaN``/``Infinity``/``-Infinity`` constants that permissive stdlib
``json.loads`` would accept. No raw decoder exception, body content, URL,
header, or decoder detail ever leaks into an outcome.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from httpx import MockTransport

from agentic_threat_investigator.app.datasource_semantics import DatasourceStage
from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.infrastructure.providers.http import (
    HttpOutcome,
    ProviderHttpClient,
)

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]

_UNICODE_TEXT = "威胁情报测试 — π ≈ 3.14159"


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    max_retries: int = 0,
) -> httpx.AsyncClient:
    """Build one deterministic mock-transport client; callers close it."""
    return httpx.AsyncClient(transport=MockTransport(handler), timeout=5)


def _json_response(body: bytes) -> httpx.Response:
    """Build a 200 JSON response whose exact bytes reach the parser."""
    return httpx.Response(
        200,
        content=body,
        headers={"Content-Type": "application/json"},
    )


def _bounded_failure(outcome: HttpOutcome) -> None:
    """Assert the exact bounded serialization-failure contract of PR 28F-1."""
    assert outcome.final_error_code is ProviderErrorCode.INVALID_RESPONSE
    assert outcome.final_error_code.retryable is False
    assert outcome.final_error_message == "malformed JSON"
    assert outcome.final_error_stage is DatasourceStage.SERIALIZATION
    assert outcome.response_json is None
    assert outcome.final_status == 200


@pytest.mark.asyncio
class TestProviderJsonFormat:
    """F1-J01..J15: valid JSON shapes parse; non-standard input fails closed."""

    async def test_f1j01_valid_object_success(self) -> None:
        """F1-J01: a valid object body succeeds with the same Python shape."""
        transport = _client(lambda _: _json_response(b'{"status": "ok", "n": 7}'))
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code is None
            assert outcome.response_json == {"status": "ok", "n": 7}
        finally:
            await transport.aclose()

    async def test_f1j02_top_level_array_success(self) -> None:
        """F1-J02: a top-level array body is a success at the HTTP boundary."""
        transport = _client(lambda _: _json_response(b'[{"a": 1}, 2, null]'))
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code is None
            assert outcome.response_json == [{"a": 1}, 2, None]
        finally:
            await transport.aclose()

    async def test_f1j03_nested_containers_and_scalars_preserved(self) -> None:
        """F1-J03: nested object/array/null/bool values are preserved exactly."""
        transport = _client(
            lambda _: _json_response(
                b'{"outer": {"inner": [{"k": ["v1", null, 2, 3.5, true]},'
                b' {"empty": [], "obj": {}}]}, "flag": false}'
            )
        )
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code is None
            assert outcome.response_json == {
                "outer": {
                    "inner": [
                        {"k": ["v1", None, 2, 3.5, True]},
                        {"empty": [], "obj": {}},
                    ]
                },
                "flag": False,
            }
        finally:
            await transport.aclose()

    async def test_f1j04_unicode_preserved(self) -> None:
        """F1-J04: non-ASCII UTF-8 text survives as a Python str."""
        body = f'{{"label": "{_UNICODE_TEXT}"}}'.encode("utf-8")
        transport = _client(lambda _: _json_response(body))
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code is None
            assert outcome.response_json == {"label": _UNICODE_TEXT}
        finally:
            await transport.aclose()

    async def test_f1j05_malformed_syntax_bounded_failure(self) -> None:
        """F1-J05: malformed syntax maps to the bounded serialization outcome."""
        transport = _client(lambda _: _json_response(b"{not json"))
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            _bounded_failure(outcome)
        finally:
            await transport.aclose()

    async def test_f1j06_invalid_utf8_bounded_failure(self) -> None:
        """F1-J06: invalid UTF-8 bytes fail closed without a str decode path."""
        transport = _client(lambda _: _json_response(b"\xff\xfe\x00"))
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            _bounded_failure(outcome)
        finally:
            await transport.aclose()

    @pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
    async def test_f1j07_j09_nonstandard_constants_rejected(
        self, constant: bytes
    ) -> None:
        """F1-J07..J09: NaN/Infinity/-Infinity are rejected, never accepted."""
        body = b'{"value": ' + constant + b"}"

        def handler(_: httpx.Request) -> httpx.Response:
            request_count[0] += 1
            return _json_response(body)

        request_count = [0]
        transport = _client(handler, max_retries=2)
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            _bounded_failure(outcome)
            assert outcome.attempt_count == 1
            assert request_count == [1]  # non-retryable, exactly one attempt
        finally:
            await transport.aclose()

    async def test_f1j10_empty_json_body_malformed(self) -> None:
        """F1-J10: an empty JSON body is malformed, not a null value."""
        transport = _client(lambda _: _json_response(b""))
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            _bounded_failure(outcome)
        finally:
            await transport.aclose()

    async def test_f1j11_oversize_body_parser_not_reached(self) -> None:
        """F1-J11: an oversize body still fails with the size outcome, not JSON."""
        transport = _client(
            lambda _: _json_response(b'{"pad": "' + b"x" * 1000 + b'"}')
        )
        try:
            http = ProviderHttpClient(client=transport, max_response_bytes=100)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code is ProviderErrorCode.INVALID_RESPONSE
            assert outcome.final_error_message == "response too large"
            assert outcome.final_error_stage is DatasourceStage.ACQUISITION
        finally:
            await transport.aclose()

    async def test_f1j14_server_error_still_prevents_parse(self) -> None:
        """F1-J14: a retryable 5xx status is classified before any JSON parse."""
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(503, json={})

        transport = _client(handler, max_retries=0)
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code is ProviderErrorCode.PROVIDER_UNAVAILABLE
            assert outcome.final_error_stage is DatasourceStage.ACQUISITION
            assert outcome.response_json is None
        finally:
            await transport.aclose()

    async def test_f1j15_finite_numeric_values_semantic_shapes(self) -> None:
        """F1-J15: finite integers/floats/bools/null keep their Python types.

        Semantic consumers rely on ``response_json`` values being plain
        Python ``int``/``float``/``bool``/``None``/``str``/``dict``/``list``
        with no decoder-specific wrappers.
        """
        body = (
            b'{"big": 18446744073709551615, "neg": -9223372036854775808,'
            b' "float": 3.5, "small": 1.2e-07, "zero": 0, "t": true,'
            b' "f": false, "n": null}'
        )
        transport = _client(lambda _: _json_response(body))
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            assert outcome.final_error_code is None
            parsed = outcome.response_json
            # Representative int64-range integers parse exactly as Python
            # ``int`` (uint64 max and int64 min), matching stdlib shapes.
            assert parsed["big"] == 18446744073709551615
            assert isinstance(parsed["big"], int)
            assert parsed["neg"] == -9223372036854775808
            assert isinstance(parsed["neg"], int)
            assert parsed["float"] == 3.5
            assert isinstance(parsed["float"], float)
            assert parsed["small"] == 1.2e-07
            assert parsed["zero"] == 0
            assert parsed["t"] is True
            assert parsed["f"] is False
            assert parsed["n"] is None
        finally:
            await transport.aclose()

    async def test_failure_never_leaks_decoder_or_body_detail(self) -> None:
        """No body content or decoder detail appears in the bounded message."""
        secret = "supersecret-provider-value-93281"
        body = f'{{"leak": "{secret}", }}'.encode("utf-8")  # trailing comma
        transport = _client(lambda _: _json_response(body))
        try:
            http = ProviderHttpClient(client=transport)
            outcome = await http.request_json("GET", "https://test.example.com/api")
            _bounded_failure(outcome)
            assert secret not in (outcome.final_error_message or "")
            assert "orjson" not in (outcome.final_error_message or "")
            assert "JSONDecodeError" not in (outcome.final_error_message or "")
        finally:
            await transport.aclose()
