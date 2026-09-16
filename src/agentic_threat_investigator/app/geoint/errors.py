# SPDX-License-Identifier: AGPL-3.0-only
"""Typed application errors for the bounded GEOINT analysis context (PR 26F).

The GEOINT analysis facade and context policy fail closed: an oversize or
incoherent geographic context raises a typed error before any model call,
so the Evidence Analyst never reasons over silently truncated geography.
"""


class GeointAnalysisError(ValueError):
    """Base class for bounded GEOINT analysis-context failures."""


class GeointAnalysisInputBoundsError(GeointAnalysisError):
    """A GEOINT analysis context exceeded an explicit aggregate bound.

    The deterministic policy (never the model) chooses the context; an
    oversize context fails with this typed error rather than silently
    dropping items, matching the Evidence Analyst's established input-bound
    convention.
    """

    def __init__(self, bound: str, limit: int, actual: int) -> None:
        """Record the bound name, the configured limit, and the actual size."""
        super().__init__(
            f"geoint analysis context {bound} size {actual} exceeds limit {limit}"
        )
        self.bound = bound
        self.limit = limit
        self.actual = actual


class GeointObservationEvidenceError(GeointAnalysisError):
    """A supplied observation's Evidence is missing from the analyst input.

    Every observation shown to the model must be supportable by the exact
    Evidence already supplied to that invocation; an observation whose
    Evidence is outside the bounded analyst input would make the mapped
    Assessment support invalid, so the analysis fails closed before any LLM
    call.
    """

    def __init__(self, observation_id: object, evidence_id: object) -> None:
        """Record the exact observation and missing Evidence identities."""
        super().__init__(
            "geoint observation "
            f"{observation_id} references evidence {evidence_id} that is "
            "not part of the Evidence Analyst input"
        )
        self.observation_id = observation_id
        self.evidence_id = evidence_id
