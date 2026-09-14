# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""History route allowlist tests (PR 24C).

The generic History list surfaces only backend-public allowlisted object
types. Non-allowlisted rows (for example the immutable ``evidence`` audit
rows appended by the stored functions) never fail the list with a 500:
they stay persisted for audit/ordering but are omitted from the public
projection. Explicitly requested non-allowlisted types still fail closed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from agentic_threat_investigator.app.query.history import (
    DomainObjectHistoryRecord,
    HistoryOperation,
)
from agentic_threat_investigator.app.query.models import QueryPage

from .conftest import FakeQueryBundle, build_test_app, login_client

INVESTIGATION = UUID("11111111-1111-1111-1111-111111111111")
OBJECT_ID = UUID("22222222-2222-2222-2222-222222222222")


def _record(object_type: str, version: int = 1) -> DomainObjectHistoryRecord:
    """Build one immutable history row fixture."""
    return DomainObjectHistoryRecord(
        id=UUID("33333333-3333-4333-8333-333333333333"),
        object_type=object_type,
        object_id=OBJECT_ID,
        version=version,
        operation=HistoryOperation.CREATE,
        state={"id": str(OBJECT_ID), "version": version},
        diff={},
        actor_id=None,
        request_id=None,
        investigation_id=INVESTIGATION,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_history_list_omits_non_allowlisted_rows_without_failing() -> None:
    """Rows like immutable ``evidence`` audit entries never break the list."""
    bundle = FakeQueryBundle()
    bundle.domain_history.page = QueryPage(
        items=(_record("investigation"), _record("evidence")),
        next_cursor=None,
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/history")
    assert response.status_code == 200
    payload = response.json()
    assert [item["object_type"] for item in payload["items"]] == ["investigation"]


def test_history_list_preserves_bounded_cursor_paging() -> None:
    """Omitting audit rows preserves the next-cursor contract."""
    bundle = FakeQueryBundle()
    bundle.domain_history.page = QueryPage(
        items=(_record("entity"),), next_cursor="cursor-1"
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/history")
    assert response.status_code == 200
    payload = response.json()
    assert payload["next_cursor"] == "cursor-1"
    assert len(payload["items"]) == 1


def test_history_list_rejects_explicit_non_allowlisted_type_filter() -> None:
    """A requested non-allowlisted object type fails closed with 400."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/history",
            params={"object_type": "evidence"},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_history_object_list_rejects_non_allowlisted_type() -> None:
    """Object-scoped browsing of a non-allowlisted type fails closed."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/history/evidence/{OBJECT_ID}"
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
