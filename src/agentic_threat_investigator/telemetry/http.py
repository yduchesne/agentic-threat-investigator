# SPDX-License-Identifier: AGPL-3.0-only
"""Framework-level FastAPI/ASGI inbound HTTP telemetry composition (PR 29B-1).

ATI's inbound HTTP boundary is instrumented at the ASGI/framework level with
the official OpenTelemetry FastAPI instrumentation, never with per-endpoint
decorators. This module owns only composition of that official
instrumentation over ATI's configured OTel providers plus the supported
privacy filter; it creates no ATI HTTP span names, no duplicate HTTP metrics,
and inspects no request/response bodies.

Ownership model:

- one inbound FastAPI request is one standard OTel HTTP server span whose
  operation identity is ``HTTP method + registered route template``;
- standard server metrics (``http.server.duration`` etc. as emitted by the
  resolved official instrumentation) carry the registered route template,
  never a concrete dynamic path;
- ATI application spans created during request processing inherit the server
  span's context naturally through OTel's current-context mechanism;
- a valid incoming W3C ``traceparent`` continues the upstream trace;
- disabled telemetry installs nothing here.

Privacy contract enforced at this boundary:

- standard route identity (``http.route`` / the bounded ``http.target`` of
  the standard server metrics) is always the registered route template;
- concrete request paths, full target URLs, and query strings are never
  retained in spans (the official instrumentation records them as standard
  span attributes; the server-request hook blanks the content-bearing keys);
- headers and bodies are never captured: the official instrumentation
  captures none by default and this module passes no header-capture option.

See ``docs/OBSERVABILITY.md`` for the deployment constraint that
``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_*`` and
``OTEL_SEMCONV_STABILITY_OPT_IN`` environment variables must not enable
header capture in the ATI API process.
"""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.trace import Span

from agentic_threat_investigator.telemetry.setup import TelemetryRuntime

URL_CONTENT_ATTRIBUTE_KEYS: tuple[str, ...] = (
    "http.url",
    "http.target",
    "url.full",
    "url.path",
    "url.query",
)
"""Standard OTel span attributes that carry concrete request target content.

The resolved official FastAPI/ASGI instrumentation records the full request
URL and the concrete (non-template) target as standard semantic-convention
span attributes. ATI's observability privacy policy does not retain concrete
paths, full URLs, or query strings even on spans; the server-request hook
blanks exactly these keys and leaves the bounded route identity untouched.
"""


def redact_http_content_attributes(span: Span, _scope: dict[str, Any]) -> None:
    """Blank concrete request-target content from the server span.

    Called by the official instrumentation as the supported server-request
    hook after the standard span attributes are set (the ASGI scope is not
    needed: only the already-set span carries the content to redact). The
    registered route template (``http.route`` / the framework span name) is
    untouched, so operation identity survives while concrete paths/URLs/query
    strings do not. The hook is fail-open from the framework's perspective:
    an exception here is recorded on the span and never changes request
    handling.
    """
    # The OTel trace ``Span`` ABC cannot read attributes; the SDK span the
    # hook actually receives can, so narrow the read-only view for the
    # presence check while mutating through the public ``set_attribute`` API.
    readable = cast(ReadableSpan, span)
    for key in URL_CONTENT_ATTRIBUTE_KEYS:
        if key in (readable.attributes or {}):
            span.set_attribute(key, "")


def instrument_fastapi_http(
    app: FastAPI,
    runtime: TelemetryRuntime,
) -> None:
    """Instrument ``app`` with official OTel FastAPI server telemetry.

    The providers come from :func:`configure_telemetry` (via ``runtime``);
    pass the exact ``TelemetryRuntime`` returned by that call so the API
    process never opens a second provider pipeline. When the runtime is
    disabled (``tracer_provider`` and ``meter_provider`` both ``None``) no
    HTTP telemetry pipeline is installed and the application is returned
    untouched.

    Installation is idempotent for one application instance: the official
    instrumentation guards against re-instrumenting an already-instrumented
    app, so repeated composition of the same app is a safe no-op. The
    ``receive``/``send`` internal event spans of the official middleware are
    excluded because PR 29B-1's trace contract is one HTTP server span and
    its ATI application descendants.
    """
    if runtime.tracer_provider is None or runtime.meter_provider is None:
        return
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=runtime.tracer_provider,
        meter_provider=runtime.meter_provider,
        server_request_hook=redact_http_content_attributes,
        exclude_spans=["receive", "send"],
    )


__all__ = [
    "URL_CONTENT_ATTRIBUTE_KEYS",
    "instrument_fastapi_http",
    "redact_http_content_attributes",
]
