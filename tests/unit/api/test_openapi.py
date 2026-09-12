# SPDX-License-Identifier: AGPL-3.0-only
"""OpenAPI contract snapshot test (PR 23C Part 19).

FastAPI-generated OpenAPI is a supported artifact with explicit stable
operation IDs, tags, public DTOs, and an accurate cookie-session security
scheme. The normalized schema is pinned to ``tests/fixtures/openapi_v1.json``
so every deliberate change to the /api/v1 surface is reviewed.

Regenerate the fixture after an intentional contract change with:

    uv run python -c \\
      "import json; from agentic_threat_investigator.api.app import create_app; \\
       from agentic_threat_investigator.config import Settings; \\
       s=create_app(Settings(public_base_url='http://testserver')).openapi(); \\
       open('tests/fixtures/openapi_v1.json','w').write(json.dumps(s,sort_keys=True,indent=2)+chr(10))"
"""

from __future__ import annotations

import json
from pathlib import Path

from agentic_threat_investigator.api.app import create_app
from agentic_threat_investigator.config import Settings

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "openapi_v1.json"


def _normalized_schema() -> dict[str, object]:
    """Generate the deterministic OpenAPI schema for the fixture app."""
    application = create_app(Settings(public_base_url="http://testserver"))
    normalized = json.loads(json.dumps(application.openapi(), sort_keys=True))
    assert isinstance(normalized, dict)
    return normalized


def test_openapi_snapshot_is_pinned() -> None:
    """The generated schema exactly matches the reviewed snapshot."""
    expected = json.loads(FIXTURE.read_text())
    assert _normalized_schema() == expected


def test_openapi_declares_cookie_session_scheme_accurately() -> None:
    """OpenAPI documents the cookie apiKey scheme, never JWT/Bearer."""
    schema = create_app(Settings()).openapi()
    schemes = schema["components"]["securitySchemes"]
    assert schemes["cookieSession"] == {
        "type": "apiKey",
        "in": "cookie",
        "name": "ati_session",
    }
    assert "bearer" not in json.dumps(schemes).lower()


def test_openapi_protects_analytical_operations() -> None:
    """Every non-public operation requires the cookie session."""
    schema = create_app(Settings()).openapi()
    public = {
        ("/health/live", "get"),
        ("/health/ready", "get"),
        ("/api/v1/auth/login", "post"),
    }
    protected = 0
    for path, path_item in schema["paths"].items():
        for method, operation in path_item.items():
            if not isinstance(operation, dict):
                continue
            if (path, method) in public:
                assert "security" not in operation
            else:
                assert operation["security"] == [{"cookieSession": []}]
                protected += 1
    assert protected >= 20


def test_openapi_operation_ids_are_explicit() -> None:
    """Every /api/v1 operation carries an explicit stable operation_id."""
    schema = create_app(Settings()).openapi()
    operation_ids: set[str] = set()
    for path, path_item in schema["paths"].items():
        if not path.startswith("/api/v1"):
            continue
        for _method, operation in path_item.items():
            if not isinstance(operation, dict):
                continue
            operation_id = operation["operationId"]
            assert operation_id
            assert operation_id not in operation_ids
            operation_ids.add(operation_id)
            assert operation["tags"]
    assert operation_ids == {
        "auth_login",
        "auth_logout",
        "auth_me",
        "create_investigation",
        "list_investigations",
        "get_investigation",
        "list_evidence",
        "get_evidence",
        "list_relationships",
        "get_relationship",
        "list_relationship_observations",
        "list_research_results",
        "get_research_result",
        "list_assessments",
        "get_current_assessment",
        "get_assessment",
        "list_reports",
        "get_current_report",
        "get_report",
        "get_report_markdown",
        "list_timeline_events",
        "list_investigation_history",
        "list_object_history",
        "get_object_history_version",
    }


def test_openapi_error_responses_use_stable_envelope() -> None:
    """Public operations document 401/404/422 with the ATI envelope shape."""
    schema = create_app(Settings()).openapi()
    investigation_path = schema["paths"]["/api/v1/investigations/{investigation_id}"]
    responses = investigation_path["get"]["responses"]
    assert "401" in responses
    assert "404" in responses
    error_schema = responses["404"]["content"]["application/json"]["schema"]
    ref = error_schema["$ref"]
    assert ref.endswith("/ErrorResponse")


def test_openapi_public_dtos_only() -> None:
    """No internal domain or persistence schema leaks into OpenAPI."""
    schema = create_app(Settings()).openapi()
    schemas = set(schema["components"]["schemas"])
    forbidden = {
        "InvestigationState",
        "Evidence",
        "Assessment",
        "InvestigationReport",
        "ResearchResult",
        "User",
        "Session",
        "Credential",
        "DomainObjectHistoryRecord",
    }
    assert not (schemas & forbidden)
