# SPDX-License-Identifier: AGPL-3.0-only
"""Typed application errors for the Evidence Analyst workflow."""


class EvidenceAnalystInputBoundsError(ValueError):
    """An analyst input exceeded an explicit context bound.

    Oversized input fails with this typed error before any model call;
    evidence is never silently truncated, because silent truncation would
    make Assessment provenance misleading.
    """

    def __init__(self, bound: str, limit: int, actual: int) -> None:
        """Record the bound name, the configured limit, and the actual size."""
        super().__init__(
            f"evidence analyst input {bound} size {actual} exceeds limit {limit}"
        )
        self.bound = bound
        self.limit = limit
        self.actual = actual
