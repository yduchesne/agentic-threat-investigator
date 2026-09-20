# SPDX-License-Identifier: AGPL-3.0-only
"""Decorator-first telemetry helpers (PR 29A).

``traced`` / ``timed`` / ``telemetry_operation`` are thin, backend-neutral
decorators built on the OpenTelemetry API for stable function/method
execution boundaries. They never capture function arguments or return values,
never serialize ``self``/requests/Evidence/prompts/provider payloads, and
never translate application exceptions or ``asyncio.CancelledError`` into
telemetry-specific failures. Static attributes are allowlist/bounded
validated at decoration time so a developer mistake fails fast before any
operation runs.

These decorators are not applied broadly in PR 29A; that is PR 29B.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import time
from collections.abc import Callable, Mapping
from typing import Any, TypeVar, cast

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from agentic_threat_investigator.telemetry.attributes import (
    AttributeKeys,
    validate_bounded_attributes,
)
from agentic_threat_investigator.telemetry.metrics import (
    DURATION_UNIT,
    DurationMetrics,
    Metrics,
    get_counter,
    get_histogram,
)
from agentic_threat_investigator.telemetry.tracing import SpanNames, get_tracer

F = TypeVar("F", bound=Callable[..., Any])

_ERROR_OUTCOME = "error"
_SUCCESS_OUTCOME = "success"

#: Registry of decorated PostgreSQL repository operations, keyed by
#: ``(repository class name, operation name)``. Filled at decoration time and
#: read by the structural coverage test so a newly added repository I/O
#: method without telemetry is difficult to introduce silently.
_REPOSITORY_OPERATION_REGISTRY: set[tuple[str, str]] = set()


def registered_postgres_repository_operations() -> frozenset[tuple[str, str]]:
    """Return the frozen set of instrumented PostgreSQL repository operations."""
    return frozenset(_REPOSITORY_OPERATION_REGISTRY)


def _validate_span_name(span_name: str) -> str:
    """Return a normalized non-blank span name or raise."""
    if not span_name.strip():
        raise ValueError("span_name must not be blank")
    return span_name.strip()


def _validate_duration_metric(metric: str) -> str:
    """Require the canonical ``.duration`` suffix contract."""
    if not metric.strip():
        raise ValueError("duration metric must not be blank")
    if not metric.endswith(".duration"):
        raise ValueError(
            "duration metric must use the canonical '<operation>.duration' suffix"
        )
    return metric.strip()


def _record_exception(span: trace.Span, exc: Exception) -> None:
    """Record an ordinary exception on a span using OTel standard behavior.

    The recorded exception event carries the exception message via OTel's
    standard semantics; ATI therefore uses these decorators only at boundaries
    whose exceptions are already safe and bounded (see ``docs/OBSERVABILITY.md``).
    """
    span.record_exception(exc)
    span.set_status(Status(StatusCode.ERROR))


def traced(
    *,
    span_name: str,
    attributes: Mapping[str, str] | None = None,
) -> Callable[[F], F]:
    """Decorate a sync/async callable to create one current child span.

    The wrapped return value, ordinary exceptions, and cancellation are
    preserved unchanged. Exception type is recorded on the span using
    standard OTel exception semantics; function arguments/results are never
    attached.
    """
    name = _validate_span_name(span_name)
    static_attributes = validate_bounded_attributes(attributes or {})

    def decorator(func: F) -> F:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                tracer = get_tracer()
                with tracer.start_as_current_span(
                    name, attributes=static_attributes
                ) as span:
                    try:
                        return await func(*args, **kwargs)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        _record_exception(span, exc)
                        raise

            return cast(F, async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            with tracer.start_as_current_span(
                name, attributes=static_attributes
            ) as span:
                try:
                    return func(*args, **kwargs)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    _record_exception(span, exc)
                    raise

        return cast(F, sync_wrapper)

    return decorator


def _duration_attrs(
    outcome: str,
    static_attributes: Mapping[str, str],
) -> dict[str, str]:
    """Merge the bounded outcome attribute with the static attributes."""
    merged = dict(static_attributes)
    merged["ati.outcome"] = outcome
    return merged


def timed(
    *,
    metric: str,
    attributes: Mapping[str, str] | None = None,
    on_error: Callable[[], None] | None = None,
) -> Callable[[F], F]:
    """Decorate a sync/async callable to record one duration histogram.

    Duration is measured with ``time.perf_counter()`` and recorded in seconds.
    Both successful and failing calls contribute duration (latency of failed
    external operations is operationally useful), tagged with a bounded
    ``ati.outcome`` attribute. Cancellation does not record a duration and
    always propagates unchanged. ``on_error``, when provided, is invoked after
    recording an ordinary failure duration and before re-raising; it is never
    invoked for cancellation. No measurement is emitted when the meter is
    unavailable/disabled (OTel no-op instruments).
    """
    duration_metric = _validate_duration_metric(metric)
    static_attributes = validate_bounded_attributes(attributes or {})

    def decorator(func: F) -> F:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                histogram = get_histogram(
                    duration_metric, unit=DURATION_UNIT, description=duration_metric
                )
                start = time.perf_counter()
                try:
                    result = await func(*args, **kwargs)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    histogram.record(
                        time.perf_counter() - start,
                        attributes=_duration_attrs(_ERROR_OUTCOME, static_attributes),
                    )
                    if on_error is not None:
                        on_error()
                    raise exc
                else:
                    histogram.record(
                        time.perf_counter() - start,
                        attributes=_duration_attrs(_SUCCESS_OUTCOME, static_attributes),
                    )
                    return result

            return cast(F, async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            histogram = get_histogram(
                duration_metric, unit=DURATION_UNIT, description=duration_metric
            )
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                histogram.record(
                    time.perf_counter() - start,
                    attributes=_duration_attrs(_ERROR_OUTCOME, static_attributes),
                )
                if on_error is not None:
                    on_error()
                raise exc
            else:
                histogram.record(
                    time.perf_counter() - start,
                    attributes=_duration_attrs(_SUCCESS_OUTCOME, static_attributes),
                )
                return result

        return cast(F, sync_wrapper)

    return decorator


def postgres_repository_operation(
    *,
    repository: str,
    operation: str,
) -> Callable[[F], F]:
    """Decorate one PostgreSQL repository I/O method (PR 29A-1).

    Composes the tested ``traced``/``timed`` primitives exactly once into one
    ``ati.postgres.repository`` span plus one ``ati.postgres.repository.duration``
    seconds histogram, both carrying the bounded static ``repository`` and
    ``operation`` attributes, and increments
    ``ati.postgres.repository.failures`` on ordinary errors. Cancellation and
    exception semantics are preserved unchanged; repository and operation
    names are static developer-controlled strings, never derived from method
    arguments.
    """
    repository_name = repository.strip()
    operation_name = operation.strip()
    if not repository_name or not operation_name:
        raise ValueError("repository and operation must not be blank")
    static_attributes = validate_bounded_attributes(
        {
            AttributeKeys.POSTGRES_REPOSITORY: repository_name,
            AttributeKeys.POSTGRES_OPERATION: operation_name,
        }
    )
    _REPOSITORY_OPERATION_REGISTRY.add((repository_name, operation_name))

    def decorator(func: F) -> F:
        def _record_failure() -> None:
            # get_counter resolves through the module seam at call time so
            # deterministic tests can inject an in-memory meter provider.
            get_counter(Metrics.POSTGRES_REPOSITORY_FAILURES).add(1, static_attributes)

        timed_decorator = timed(
            metric=DurationMetrics.POSTGRES_REPOSITORY,
            attributes=static_attributes,
            on_error=_record_failure,
        )
        traced_decorator = traced(
            span_name=SpanNames.POSTGRES_REPOSITORY,
            attributes=static_attributes,
        )
        return traced_decorator(timed_decorator(func))

    return decorator


def telemetry_operation(
    *,
    span_name: str,
    duration_metric: str,
    attributes: Mapping[str, str] | None = None,
) -> Callable[[F], F]:
    """Compose one span and one duration measurement for a stable boundary.

    A convenience that composes the two tested primitives exactly once: a
    single ``traced`` span surrounding a single ``timed`` duration histogram.
    It adds no new instrumentation logic beyond those primitives.
    """
    _validate_span_name(span_name)
    _validate_duration_metric(duration_metric)
    validate_bounded_attributes(attributes or {})

    def decorator(func: F) -> F:
        traced_decorator = traced(span_name=span_name, attributes=attributes)
        timed_decorator = timed(metric=duration_metric, attributes=attributes)
        return traced_decorator(timed_decorator(func))

    return decorator


__all__ = [
    "postgres_repository_operation",
    "registered_postgres_repository_operations",
    "telemetry_operation",
    "timed",
    "traced",
]
