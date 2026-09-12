# SPDX-License-Identifier: AGPL-3.0-only
"""Typed application errors for the Report Writer workflow (PR 23B)."""


class ReportWriterError(ValueError):
    """Base class for typed Report Writer workflow failures."""


class ReportWriterInputError(ReportWriterError):
    """The authoritative input snapshot cannot be assembled.

    Raised before any model invocation: no current Assessment, missing
    provenance, or an inconsistent persisted snapshot. These failures consume
    no LLM budget.
    """


class ReportWriterNoCurrentAssessmentError(ReportWriterInputError):
    """The Investigation has no current Assessment.

    A report is an analytical presentation of an Assessment; report
    generation without a durable current ``assessment_id`` pointer fails with
    this typed error and never reaches the LLM boundary.
    """

    def __init__(self, investigation_id: object) -> None:
        """Record the Investigation without a current Assessment."""
        super().__init__(f"investigation has no current assessment: {investigation_id}")
        self.investigation_id = investigation_id


class ReportWriterInputLimitError(ReportWriterInputError):
    """A report input collection exceeded an explicit context bound.

    Oversized input fails with this typed error before any model call;
    material is never silently truncated, because silent truncation would
    make report provenance misleading. Only the collection name, count, and
    limit are reported — never source text.
    """

    def __init__(self, bound: str, limit: int, actual: int) -> None:
        """Record the bound name, the configured limit, and the actual size."""
        super().__init__(
            f"report writer input {bound} size {actual} exceeds limit {limit}"
        )
        self.bound = bound
        self.limit = limit
        self.actual = actual


class ReportWriterInputConsistencyError(ReportWriterInputError):
    """The persisted input snapshot is internally inconsistent.

    Raised when an authoritative reference cannot resolve (missing analyzed
    Evidence, missing RelationshipObservation support, missing canonical
    Entity/Relationship required for presentation, or a cross-Investigation
    reference). The loader never "repairs" missing provenance by dropping
    items; it fails closed.
    """


class ReportProvenanceError(ReportWriterError):
    """Deterministic provenance/citation-closure validation failed.

    Raised before persistence by the ReportProvenanceValidator for unknown or
    cross-Investigation references, Assessment authority violations, caveat
    changes, snapshot drift, or source-set closure failures. The message is
    safe for logs: it never contains raw model output or hidden reasoning.
    """
