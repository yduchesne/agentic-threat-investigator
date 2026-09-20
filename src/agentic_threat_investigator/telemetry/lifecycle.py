# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application-lifetime telemetry composition (PR 29B-2).

The ``ati-api`` production composition owns the whole telemetry lifecycle:
:func:`~agentic_threat_investigator.telemetry.setup.configure_telemetry`
starts the providers,
:func:`~agentic_threat_investigator.telemetry.http.instrument_fastapi_http`
installs the inbound HTTP telemetry, and
:func:`arrange_fastapi_telemetry_shutdown` composes the application lifespan
so the process shuts the providers down **after** the application services
have been disposed — and even when that disposal fails.

FastAPI/Starlette expose no second documented lifespan slot: the lifespan
handler registered through ``FastAPI(lifespan=...)`` is stored as the
application router's ``lifespan_context`` callable and drives the whole ASGI
lifespan protocol (:class:`starlette.routing.Router`). This module therefore
wraps exactly that existing supported composition point with a small
ATI-owned deferral wrapper built only from public APIs
(:data:`starlette.types.Lifespan` and :func:`contextlib.asynccontextmanager`).
The generic application factory
(:func:`~agentic_threat_investigator.api.app.create_app`) is never asked to
know about process telemetry, and ``shutdown_telemetry`` remains the single
teardown primitive: no provider ``.shutdown()`` call happens here.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.types import Lifespan


def arrange_fastapi_telemetry_shutdown(
    app: FastAPI,
    on_shutdown: Callable[[], None],
) -> None:
    """Arrange ``on_shutdown`` to run after the application lifespan exits.

    The existing lifespan on ``app`` (owned by ``create_app``, which composes
    and later disposes the API services) is wrapped so request serving and
    the original lifespan teardown run first and ``on_shutdown`` runs
    afterwards exactly once, with ``finally``-equivalent semantics: when the
    application teardown raises, ``on_shutdown`` still runs and the original
    exception remains authoritative. Disabled telemetry is unaffected: with
    no providers the shutdown callback stays a harmless no-op, and composing
    an application whose lifespan was never customized extends that default
    lifespan without changing it.
    """
    original_lifespan: Lifespan[FastAPI] = app.router.lifespan_context

    @asynccontextmanager
    async def _lifespan(application: FastAPI) -> AsyncIterator[None]:
        try:
            async with original_lifespan(application):
                yield
        finally:
            on_shutdown()

    app.router.lifespan_context = _lifespan


__all__ = ["arrange_fastapi_telemetry_shutdown"]
