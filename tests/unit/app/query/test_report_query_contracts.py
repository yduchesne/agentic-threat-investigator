# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the report query contract (PR 23B extension of PR 23A)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    CursorFilterMismatchError,
    CursorQueryMismatchError,
    InvalidCursorError,
    QueryKind,
    encode_cursor,
    require_cursor_for_query,
)
from agentic_threat_investigator.app.query.reports import (
    ReportListQuery,
    parse_report_cursor,
    report_sort_values,
)


def test_report_list_query_fingerprint_stable() -> None:
    """The report list query fingerprint is canonical and stable."""
    investigation_id = uuid4()
    query = ReportListQuery(investigation_id=investigation_id, limit=10)
    assert query.fingerprint() == query.fingerprint()
    other = ReportListQuery(investigation_id=investigation_id, limit=50)
    assert query.fingerprint() == other.fingerprint()


def test_report_cursor_round_trip() -> None:
    """Report cursors encode version+id and decode strictly."""
    investigation_id = uuid4()
    query = ReportListQuery(investigation_id=investigation_id, limit=10)
    cursor = encode_cursor(
        CursorEnvelope(
            query_kind=QueryKind.REPORTS,
            filter_fingerprint=query.fingerprint(),
            sort_values=report_sort_values(3, uuid4()),
        )
    )
    envelope = require_cursor_for_query(
        cursor,
        query_kind=QueryKind.REPORTS,
        filter_fingerprint=query.fingerprint(),
    )
    assert envelope is not None
    version, report_id = parse_report_cursor(envelope)
    assert version == 3
    assert isinstance(report_id, uuid4().__class__)


def test_report_cursor_bound_to_query_kind() -> None:
    """A cursor from another collection fails closed."""
    investigation_id = uuid4()
    query = ReportListQuery(investigation_id=investigation_id, limit=10)
    cursor = encode_cursor(
        CursorEnvelope(
            query_kind=QueryKind.ASSESSMENTS,
            filter_fingerprint=query.fingerprint(),
            sort_values=("1", str(uuid4())),
        )
    )
    with pytest.raises(CursorQueryMismatchError):
        require_cursor_for_query(
            cursor,
            query_kind=QueryKind.REPORTS,
            filter_fingerprint=query.fingerprint(),
        )


def test_report_cursor_bound_to_filters() -> None:
    """A cursor from another Investigation scope fails closed."""
    query = ReportListQuery(investigation_id=uuid4(), limit=10)
    cursor = encode_cursor(
        CursorEnvelope(
            query_kind=QueryKind.REPORTS,
            filter_fingerprint=query.fingerprint(),
            sort_values=("1", str(uuid4())),
        )
    )
    other = ReportListQuery(investigation_id=uuid4(), limit=10)
    with pytest.raises(CursorFilterMismatchError):
        require_cursor_for_query(
            cursor,
            query_kind=QueryKind.REPORTS,
            filter_fingerprint=other.fingerprint(),
        )


def test_report_cursor_malformed_rejected() -> None:
    """A malformed cursor is rejected with the typed error."""
    with pytest.raises(InvalidCursorError):
        require_cursor_for_query(
            "not-a-cursor",
            query_kind=QueryKind.REPORTS,
            filter_fingerprint="fingerprint",
        )


def test_query_kind_enum_has_reports() -> None:
    """The cursor query-kind enum carries the reports collection."""
    assert QueryKind.REPORTS.value == "reports"
