# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded HTTP contact points for the PR 34 backend verifier.

Reuses the repository's existing ``httpx`` dependency (no new HTTP library).
Every helper performs one bounded HTTP request and raises
:class:`BackendError` on transport or protocol failure so the state machine
can classify the failing stage; no helper retries (bounded polling lives in
the state machine) and no helper ever logs credentials, Authorization
headers, or unbounded response bodies.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import httpx

_HTTP_TIMEOUT_SECONDS = 10.0
"""Per-request bounded timeout; convergence is harness-owned polling, never
a long request."""


class BackendError(RuntimeError):
    """One bounded backend probe failed (transport or protocol)."""


def get_json(
    url: str,
    *,
    params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    auth: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Perform one bounded HTTP GET and return the parsed JSON object."""
    payload = get_json_any(url, params=params, headers=headers, auth=auth)
    if not isinstance(payload, dict):
        raise BackendError(f"GET {url} returned a non-object JSON body")
    return payload


def get_json_any(
    url: str,
    *,
    params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    auth: tuple[str, str] | None = None,
) -> Any:
    """Perform one bounded HTTP GET and return the parsed JSON value.

    Unlike :func:`get_json`, the payload may be a JSON object or array
    (Grafana's ``/api/datasources`` returns an array on the pinned 13.2.2).
    """
    try:
        with httpx.Client(
            timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
            response = client.get(url, params=params, headers=headers, auth=auth)
    except httpx.HTTPError as exc:
        raise BackendError(f"GET {url} failed: {exc}") from exc
    if response.status_code != 200:
        raise BackendError(f"GET {url} returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise BackendError(f"GET {url} returned non-JSON body") from exc
    if not isinstance(payload, (dict, list)):
        raise BackendError(f"GET {url} returned a non-JSON-object/array body")
    return payload


def get_text(
    url: str,
    *,
    params: Mapping[str, str] | None = None,
) -> str:
    """Perform one bounded HTTP GET and return the body text."""
    try:
        with httpx.Client(
            timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
            response = client.get(url, params=params)
    except httpx.HTTPError as exc:
        raise BackendError(f"GET {url} failed: {exc}") from exc
    if response.status_code != 200:
        raise BackendError(f"GET {url} returned HTTP {response.status_code}")
    return response.text


def prometheus_query(
    base_url: str,
    query: str,
    *,
    timeout: str = "20s",
) -> Sequence[Mapping[str, Any]]:
    """Run one instant PromQL query and return the result vector.

    The pinned Prometheus 3.14 API returns ``{"status": "success", "data":
    {"resultType": "vector", "result": [...]}}``; any other shape is a
    bounded backend contract failure.
    """
    payload = get_json(
        f"{base_url}/api/v1/query",
        params={"query": query, "timeout": timeout},
    )
    if payload.get("status") != "success":
        raise BackendError(
            f"Prometheus query returned status {payload.get('status')!r}"
        )
    data = payload.get("data")
    if not isinstance(data, dict):
        raise BackendError("Prometheus query returned no data object")
    result = data.get("result")
    if data.get("resultType") != "vector" or not isinstance(result, list):
        raise BackendError(
            f"Prometheus query returned unexpected resultType {data.get('resultType')!r}"
        )
    return [entry for entry in result if isinstance(entry, dict)]


def _flatten_otlp_spans(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten Jaeger v3 OTLP-JSON ``result.resourceSpans`` into span dicts.

    Jaeger 2.x serves its v3 query API responses as OTLP ptrace proto JSON
    (``{"result": {"resourceSpans": [...]}}``) — verified against the
    pinned ``jaegertracing/jaeger:2.21.0`` image during PR 34 acceptance.
    """
    result = payload.get("result")
    if not isinstance(result, dict):
        return []
    spans: list[dict[str, Any]] = []
    resource_spans = result.get("resourceSpans")
    if not isinstance(resource_spans, list):
        return spans
    for resource_span in resource_spans:
        if not isinstance(resource_span, dict):
            continue
        scope_spans = resource_span.get("scopeSpans")
        if not isinstance(scope_spans, list):
            continue
        for scope_span in scope_spans:
            if not isinstance(scope_span, dict):
                continue
            spans_list = scope_span.get("spans")
            if not isinstance(spans_list, list):
                continue
            spans.extend(span for span in spans_list if isinstance(span, dict))
    return spans


def jaeger_search(
    base_url: str,
    *,
    service_name: str,
    start_rfc3339: str,
    end_rfc3339: str,
    attributes: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Search traces on the pinned Jaeger 2.x v3 API and return spans.

    Uses the verified v3 contract: ``GET /api/v3/traces`` with
    ``query.serviceName``, ``query.startTimeMin``/``query.startTimeMax``
    (RFC3339Nano) and an optional ``query.attributes`` JSON map. An empty
    result (HTTP 404 ``No traces found``) maps to ``[]`` so the state
    machine keeps polling; a genuinely malformed contract raises.
    """
    params: dict[str, str] = {
        "query.serviceName": service_name,
        "query.startTimeMin": start_rfc3339,
        "query.startTimeMax": end_rfc3339,
    }
    if attributes:
        import json

        params["query.attributes"] = json.dumps(attributes)
    try:
        payload = get_json(f"{base_url}/api/v3/traces", params=params)
    except BackendError as exc:
        if "HTTP 404" in str(exc):
            return []
        raise
    return _flatten_otlp_spans(payload)


def jaeger_trace(
    base_url: str,
    trace_id: str,
) -> list[dict[str, Any]]:
    """Fetch one trace by hex ID from the pinned Jaeger 2.x v3 API.

    Verified v3 contract: ``GET /api/v3/traces/{trace_id}`` returns the OTLP
    JSON trace; a missing trace (404) maps to ``[]``.
    """
    try:
        payload = get_json(f"{base_url}/api/v3/traces/{trace_id}")
    except BackendError as exc:
        if "HTTP 404" in str(exc):
            return []
        raise
    return _flatten_otlp_spans(payload)


def loki_query_range(
    base_url: str,
    query: str,
    *,
    start_ns: int,
    end_ns: int,
    limit: int = 100,
) -> list[tuple[str, str, Mapping[str, str]]]:
    """Run one Loki LogQL range query and return per-line triples.

    Loki 3.x returns the HTTP/JSON streaming query contract (``result:
    [{stream: {...}, values: [[ns, line], ...]}]``). The bounded surface is
    ``(timestamp, line, labels)``: the label map carries the indexed label
    set plus structured metadata (e.g. the exported ``trace_id``/``span_id``
    of OTLP log records) — never fabricated and never secrets.
    """
    payload = get_json(
        f"{base_url}/loki/api/v1/query_range",
        params={
            "query": query,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": str(limit),
            "direction": "BACKWARD",
        },
    )
    status = payload.get("status")
    if status not in ("success", 200):
        raise BackendError(f"Loki query returned status {status!r}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise BackendError("Loki query returned no data object")
    result = data.get("result")
    if not isinstance(result, list):
        raise BackendError("Loki query returned a non-list result")
    triples: list[tuple[str, str, Mapping[str, str]]] = []
    for stream in result:
        if not isinstance(stream, dict):
            continue
        stream_labels = stream.get("stream")
        labels = (
            {k: str(v) for k, v in stream_labels.items()}
            if isinstance(stream_labels, dict)
            else {}
        )
        values = stream.get("values")
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, list) or len(value) < 2:
                continue
            timestamp, line = value[0], value[1]
            if isinstance(timestamp, str) and isinstance(line, str):
                triples.append((timestamp, line, labels))
    return triples


def grafana_api(
    base_url: str,
    user: str,
    password: str,
    path: str,
    *,
    params: Mapping[str, str] | None = None,
) -> Any:
    """Call one Grafana HTTP API endpoint with harness admin credentials.

    Grafana 13.2.2 ``/api/datasources`` returns a JSON array, so the parsed
    JSON value (object or array) is returned.
    """
    return get_json_any(
        f"{base_url}{path}",
        params=params,
        auth=(user, password),
    )


__all__ = [
    "BackendError",
    "get_json",
    "get_json_any",
    "get_text",
    "grafana_api",
    "jaeger_search",
    "jaeger_trace",
    "loki_query_range",
    "prometheus_query",
]
