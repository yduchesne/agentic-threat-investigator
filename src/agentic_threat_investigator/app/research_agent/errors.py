# SPDX-License-Identifier: AGPL-3.0-only
"""Typed application errors for the Research Agent workflow (PR 22B)."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID


class ResearchAgentCitationError(RuntimeError):
    """A model claim cites citation IDs outside the supplied context.

    The output is schema-valid but refers to stable ``citation_id`` values
    that were not among the exact retrieved chunks supplied to this model
    invocation; a citation that merely exists elsewhere in the corpus is
    rejected identically. The message carries only the safe stable IDs and
    never source text or model output.
    """

    def __init__(self, citation_ids: Sequence[UUID]) -> None:
        """Record the unsupported citation identities."""
        self.citation_ids = tuple(citation_ids)
        rendered = ", ".join(str(citation_id) for citation_id in self.citation_ids)
        super().__init__(f"research claim cites unsupported citation IDs: {rendered}")
