# SPDX-License-Identifier: AGPL-3.0-only
"""The default NoOp LLM-observability backend (PR 29A).

Used for ``none`` selection and whenever the master observability switch is
disabled. Guaranteed zero side effects: no allocation-heavy behavior per
event, no network, no logging, no exceptions, and preserved context-manager
semantics. It deliberately performs no validation so it can never reject an
application-facing observation.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from agentic_threat_investigator.app.llm_observability import (
    LlmObservability,
    LlmObservation,
)


class NoOpLlmObservability(LlmObservability):
    """An LLM-observability backend that performs no work at all."""

    @contextmanager
    def observe(self, observation: LlmObservation) -> Iterator[None]:
        """Return a no-op scope; ``observation`` is intentionally ignored."""
        del observation
        yield


__all__ = ["NoOpLlmObservability"]
