# SPDX-License-Identifier: AGPL-3.0-only
"""LangSmith LLM-observability adapter (PR 29A foundation).

Translates portable ATI LLM observations onto the installed langsmith run
lifecycle, injecting only safe, content-free metadata and tags. The run
client is injected for deterministic tests; when absent it is created lazily
from the standard LangSmith environment on first use. Langsmith exports are
fail-open relative to the application-facing operation, and cancellation
always propagates unchanged.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from agentic_threat_investigator.app.llm_observability import (
    LlmObservability,
    LlmObservation,
    validate_llm_observation,
)

logger = logging.getLogger(__name__)


def _safe_metadata(observation: LlmObservation) -> dict[str, str]:
    """Project the portable observation onto content-free LangSmith metadata."""
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


class LangSmithLlmObservability(LlmObservability):
    """Record LLM/agent observations through a langsmith RunTree lifecycle.

    ``client`` may be injected for deterministic tests (a duck-typed object
    with ``create_run``/``update_run``); when absent a ``langsmith.Client`` is
    created lazily from the standard LangSmith environment on first use. The
    adapter never passes prompts or model output, and any langsmith failure is
    swallowed safely so observability never fails the application operation.
    """

    def __init__(self, client: Any | None = None) -> None:
        """Bind an optional injected langsmith-compatible client."""
        self._client = client

    @contextmanager
    def observe(self, observation: LlmObservation) -> Iterator[None]:
        """Open a LangSmith run scope for ``observation``, fail-open."""
        validate_llm_observation(observation)
        run = self._start_run(observation)
        try:
            yield
        except asyncio.CancelledError:
            raise
        except Exception:
            self._finish_run(run, outcome="error")
            raise
        else:
            self._finish_run(run, outcome="success")

    def _start_run(self, observation: LlmObservation) -> Any:
        """Create the langsmith run tree, or ``None`` on backend failure."""
        try:
            return _build_run_tree(self._client, observation)
        except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary; start failure must never break the operation
            logger.debug("LangSmith observability could not start run")
            return None

    def _finish_run(self, run: Any, *, outcome: str) -> None:
        """Post the run outcome, swallowing any langsmith export failure."""
        if run is None:
            return
        try:
            run.add_tags([f"ati.outcome:{outcome}"])
            run.post(exclude_child_runs=True)
        except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary; export failure must never break the operation
            logger.debug("LangSmith observability export failed")


def _build_run_tree(client: Any, observation: LlmObservation) -> Any:
    """Build a langsmith RunTree with safe metadata only."""
    from langsmith.run_trees import RunTree

    effective_client = client if client is not None else _build_client()
    run = RunTree(
        name=observation.operation_name,
        ls_client=effective_client,
        run_type="chain",
    )
    run.add_metadata(_safe_metadata(observation))
    return run


def _build_client() -> Any:
    """Create a default ``langsmith.Client`` from the standard environment."""
    from langsmith import Client

    return Client()


__all__ = ["LangSmithLlmObservability"]
