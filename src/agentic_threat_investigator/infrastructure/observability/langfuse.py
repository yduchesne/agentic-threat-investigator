# SPDX-License-Identifier: AGPL-3.0-only
"""Langfuse v4 LLM-observability adapter (PR 29A foundation).

Uses only current Langfuse v4 (OpenTelemetry-native) APIs. The adapter gives
Langfuse its own dedicated OpenTelemetry ``TracerProvider`` so Langfuse
exports only the LLM/agent observations created through this adapter and
never becomes an accidental exporter of ATI's general infrastructure spans
(disconnected tracing). No prompt/model output content is captured; every
Langfuse interaction is fail-open relative to the application-facing
operation.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from langfuse import Langfuse
from opentelemetry.sdk.trace import TracerProvider

from agentic_threat_investigator.app.llm_observability import (
    LlmObservability,
    LlmObservation,
    validate_llm_observation,
)

logger = logging.getLogger(__name__)

_ERROR_STATUS_MESSAGE = "llm observation failed"


def _safe_metadata(observation: LlmObservation) -> dict[str, str]:
    """Project the portable observation onto content-free Langfuse metadata."""
    metadata: dict[str, str] = {"operation": observation.operation_name}
    for field in (
        "model_provider",
        "model_name",
        "model_profile",
        "prompt_version",
        "investigation_id",
    ):
        value = getattr(observation, field)
        if value is not None and value != "":
            metadata[field] = value
    return metadata


class LangfuseLlmObservability(LlmObservability):
    """Record LLM/agent observations through a Langfuse v4 client.

    ``client`` may be injected for deterministic tests; when absent a client
    is built lazily from the resolved keys with a dedicated
    :class:`TracerProvider` (never the global OTel provider), keeping Langfuse
    export isolated from ATI's general OpenTelemetry span stream. A backend
    setup/export failure never fails or alters the application-facing
    operation, and cancellation always propagates unchanged.
    """

    def __init__(
        self,
        *,
        public_key: str,
        secret_key: str,
        base_url: str | None = None,
        client: Any | None = None,
    ) -> None:
        """Bind the resolved Langfuse credentials or an injected client."""
        self._public_key = public_key
        self._secret_key = secret_key
        self._base_url = base_url
        self._client = client
        self._built: Any | None = None

    def _get_client(self) -> Any:
        """Return an injected client or build one lazily with a dedicated provider."""
        if self._client is not None:
            return self._client
        if self._built is None:
            provider = TracerProvider()
            self._built = Langfuse(
                public_key=self._public_key,
                secret_key=self._secret_key,
                base_url=self._base_url,
                tracer_provider=provider,
            )
        return self._built

    @contextmanager
    def observe(self, observation: LlmObservation) -> Iterator[None]:
        """Open a Langfuse span for ``observation``, fail-open."""
        validate_llm_observation(observation)
        try:
            client = self._get_client()
            span_cm = client.start_as_current_observation(
                name=observation.operation_name,
                as_type="span",
                input=None,
                output=None,
                metadata=_safe_metadata(observation),
            )
        except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary; a backend failure must never break the operation
            logger.debug("Langfuse observability could not start observation")
            yield
            return
        with span_cm as span:
            try:
                yield
            except asyncio.CancelledError:
                raise
            except Exception:
                try:
                    span.update(level="ERROR", status_message=_ERROR_STATUS_MESSAGE)
                except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary; marking failure must never break the operation
                    logger.debug("Langfuse observability could not mark failure")
                raise
            else:
                try:
                    span.update(output={"outcome": "success"})
                except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary; marking success must never break the operation
                    logger.debug("Langfuse observability could not mark success")


__all__ = ["LangfuseLlmObservability"]
