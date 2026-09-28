# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31F-2 deterministic fatal-diagnostic vertical slice.

Runs the production coordinator graph through a controlled nested failure at
the analysis boundary over real PostgreSQL and the packaged fake world:

```text
controlled nested exception (with secret-like text)
  -> analyze node fatal boundary
  -> root cause selected
  -> ErrorMessageSanitizer redaction
  -> InvestigationError persisted on the FAILED Investigation
  -> INVESTIGATION_STOPPED(fatal_error, stable code, sanitized message)
  -> Timeline API exposes the safe message
```

Only the analysis executor (the nondeterministic/external LLM boundary) is
faked to raise; Timeline persistence, the fatal-stop architecture, the
coordinator graph, the runner, and the provider executor are the real
production implementations. The test proves a secret sentinel never survives
into persistence or the API response.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.app.error_messages import ErrorMessageSanitizer
from agentic_threat_investigator.app.orchestration.coordinator import (
    AnalysisExecutor,
    AnalysisOutcome,
)
from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.config import OperatingMode
from agentic_threat_investigator.domain.investigation import (
    InvestigationStatus,
    StopReason,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeWorldCatalog,
)
from agentic_threat_investigator.infrastructure.intelligence_composition import (
    build_fake_intelligence_sources,
)
from tests.integration.api_helpers import (
    api_client,
    api_settings,
    csrf_headers,
    seed_user,
)
from tests.integration.fake_runtime_helpers import FIXED_TS

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

SENTINEL = "SENTINEL_FATAL_SLICE_A41"
F02_ROOT_DOMAIN = "update-package.test"


def _nested_failure() -> RuntimeError:
    """Build the controlled nested exception containing the sentinel."""
    try:
        raise ValueError(
            f"analysis backend refused with api_key={SENTINEL} and port 443"
        )
    except ValueError as error:
        try:
            raise RuntimeError("evidence analysis could not complete") from error
        except RuntimeError as outer:
            return outer


class _FailingAnalysisExecutor(AnalysisExecutor):
    """Raise a controlled nested exception containing secret-like text."""

    def __init__(self, *, bound_investigation_id: UUID | None = None) -> None:
        self._bound = bound_investigation_id

    @property
    def bound_investigation_id(self) -> UUID | None:
        return self._bound

    async def analyze(self, investigation_id: UUID) -> AnalysisOutcome:
        del investigation_id
        raise _nested_failure()


def _fake_api_settings() -> Any:
    """Return API settings with the fake operating mode selected."""
    return api_settings().model_copy(update={"operating_mode": OperatingMode.FAKE})


def _fatal_slice_runner(uow_factory: Callable[[], Any]) -> LocalInvestigationRunner:
    """Compose the production runner with the controlled failing analyst."""
    sources = build_fake_intelligence_sources(
        _fake_api_settings(),
        catalog=FakeWorldCatalog.load_packaged(),
        clock=lambda: FIXED_TS,
    )
    return LocalInvestigationRunner(
        uow_factory=uow_factory,
        provider_registry=sources.provider_registry,
        analysis_executor_factory=lambda bound: _FailingAnalysisExecutor(
            bound_investigation_id=bound
        ),
        clock=lambda: FIXED_TS,
        recursion_limit=120,
    )


async def _move_to_running(
    uow_factory: Callable[[], Any], investigation_id: UUID
) -> None:
    """Advance the PENDING Investigation to RUNNING (confirmed lifecycle)."""
    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(investigation_id)
        assert durable is not None
        assert durable.version is not None
        await uow.investigations.update_status(
            investigation_id,
            InvestigationStatus.RUNNING,
            expected_version=durable.version,
        )


async def test_fatal_diagnostic_vertical_slice(
    session_factory: Any, uow_factory: Callable[[], Any]
) -> None:
    """A nested failure becomes a safe persisted analyst-visible diagnostic."""
    await seed_user(session_factory)

    with api_client(_fake_api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        response = client.post(
            "/api/v1/investigations",
            json={
                "indicators": [{"type": "domain", "value": F02_ROOT_DOMAIN}],
                "objective": "assess the update-package delivery domain",
            },
            headers={"Idempotency-Key": "f02-fatal-slice-1", **csrf_headers(client)},
        )
        assert response.status_code == 202
        investigation_id = UUID(response.json()["id"])

    await _move_to_running(uow_factory, investigation_id)

    runner = _fatal_slice_runner(uow_factory)
    terminal = await runner.run(investigation_id)

    # Terminal FAILED state with the stable stop reason.
    assert terminal.status is InvestigationStatus.FAILED
    assert terminal.stop_reason == StopReason.FATAL_ERROR.value
    assert terminal.errors
    fatal_error = terminal.errors[-1]
    assert fatal_error.code == "analysis_execution_error"
    assert SENTINEL not in fatal_error.message

    # The final Timeline stop event carries the stable code + sanitized
    # diagnostic through the real Timeline repository path.
    async with uow_factory() as uow:
        events = await uow.timeline_events.list_by_investigation(investigation_id)
    stopped = [
        event
        for event in events
        if event.type is InvestigationTimelineEventType.INVESTIGATION_STOPPED
    ]
    assert stopped, "a fatal stop Timeline event must be persisted"
    stop_event = stopped[-1]
    assert stop_event.reason_code == StopReason.FATAL_ERROR.value
    assert stop_event.error_code == "analysis_execution_error"
    assert stop_event.error_message is not None
    assert SENTINEL not in stop_event.error_message
    assert "api_key " + "<redacted>" in stop_event.error_message
    assert "analysis backend refused" in stop_event.error_message
    # Root-cause text survived; the outer wrapper text is not the diagnostic.
    assert "evidence analysis could not complete" not in stop_event.error_message

    # The Timeline API exposes the safe nullable message, never the sentinel.
    with api_client(_fake_api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "correct horse battery staple"},
        )
        timeline = client.get(
            f"/api/v1/investigations/{investigation_id}/timeline",
            params={"limit": 200},
        )
        detail = client.get(f"/api/v1/investigations/{investigation_id}")
    assert timeline.status_code == 200
    items = timeline.json()["items"]
    api_stream = str(items)
    assert SENTINEL not in api_stream
    assert any(item.get("error_message") == stop_event.error_message for item in items)
    assert detail.status_code == 200
    assert detail.json()["status"] == "failed"
    # The persisted Investigation state also never carries the sentinel.
    assert SENTINEL not in str(detail.json())


async def test_sanitizer_redacts_sentinel_from_nested_root(
    session_factory: Any, uow_factory: Callable[[], Any]
) -> None:
    """The injectable sanitizer redacts a known secret from the root cause.

    Standalone composition check: an ``ErrorMessageSanitizer`` constructed
    with an already-resolved secret value redacts that value before any
    persistence boundary.
    """
    del session_factory, uow_factory
    sanitizer = ErrorMessageSanitizer(known_secrets=(SENTINEL,))
    redacted = sanitizer.from_exception(_nested_failure())
    assert SENTINEL not in redacted
    assert "analysis backend refused" in redacted
    assert "evidence analysis could not complete" not in redacted
