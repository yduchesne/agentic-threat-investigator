# SPDX-License-Identifier: AGPL-3.0-only
"""Default NoOp LLM-observability backend tests (PR 29A)."""

from __future__ import annotations

import pytest

from agentic_threat_investigator.app.llm_observability import LlmObservation
from agentic_threat_investigator.infrastructure.observability.noop import (
    NoOpLlmObservability,
)


class TestNoOpLlmObservability:
    """The NoOp backend performs no work and preserves context-manager semantics."""

    def test_observe_is_a_noop_context_manager(self) -> None:
        """A NoOp observe scope does nothing and has no side effects."""
        noop = NoOpLlmObservability()
        with noop.observe(
            LlmObservation(operation_name="urn:ati:llm:evidence_analysis")
        ):
            pass

    @pytest.mark.asyncio
    async def test_observe_supports_async_usage(self) -> None:
        """The returned context manager can be used in an async context."""
        noop = NoOpLlmObservability()
        with noop.observe(LlmObservation(operation_name="op")):
            await _async_work()

    def test_observe_never_rejects_or_raises(self) -> None:
        """Even a content-shaped observation cannot raise from the NoOp backend."""
        noop = NoOpLlmObservability()
        with noop.observe(LlmObservation(operation_name="op\nuser prompt here")):
            pass


async def _async_work() -> None:
    """Minimal async helper to exercise async context use."""
    return
