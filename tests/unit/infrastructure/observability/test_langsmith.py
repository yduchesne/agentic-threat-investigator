# SPDX-License-Identifier: AGPL-3.0-only
"""LangSmith LLM-observability adapter tests (PR 29A foundation)."""

from __future__ import annotations

import pytest

from agentic_threat_investigator.app.llm_observability import LlmObservation
from agentic_threat_investigator.infrastructure.observability.langsmith import (
    LangSmithLlmObservability,
)


class _RecordingClient:
    """A duck-typed langsmith client that records posted runs in memory."""

    def __init__(self, *, fail_export: bool = False) -> None:
        """Initialize the recording list and optional export failure flag."""
        self.runs: list[dict[str, object]] = []
        self.fail_export = fail_export

    def create_run(self, **kwargs: object) -> str:
        """Record the posted run; optionally raise to simulate export failure."""
        if self.fail_export:
            raise RuntimeError("langsmith unavailable")
        self.runs.append(dict(kwargs))
        return "run-1"

    def update_run(self, **kwargs: object) -> None:
        """Record an update (no-op for this adapter)."""
        del kwargs

    def upload_attachment(self, **kwargs: object) -> None:
        """Duck-typed attachment upload (not used by the adapter)."""
        del kwargs


def _safe_observation() -> LlmObservation:
    """Return a valid bounded observation."""
    return LlmObservation(
        operation_name="urn:ati:llm:evidence_analysis",
        model_provider="openai",
        model_name="gpt-4o-mini",
        prompt_version="v1",
        investigation_id="inv-123",
    )


class TestLangSmithLlmObservability:
    """The adapter posts only safe metadata through a recording seam."""

    def test_success_posts_only_safe_metadata(self) -> None:
        """A successful observation posts empty inputs and bounded metadata only."""
        client = _RecordingClient()
        observability = LangSmithLlmObservability(client=client)
        with observability.observe(_safe_observation()):
            pass
        assert len(client.runs) == 1
        post = client.runs[0]
        # No prompt/model output content is ever captured.
        assert post["inputs"] == {}
        assert not post["outputs"]
        assert "user prompt content" not in str(post)
        assert "system prompt" not in str(post)
        metadata = post["extra"]["metadata"]  # type: ignore[index]
        assert metadata["operation"] == "urn:ati:llm:evidence_analysis"
        assert metadata["model_name"] == "gpt-4o-mini"
        assert metadata["investigation_id"] == "inv-123"
        assert "evidence facts" not in str(post)
        assert "ati.outcome:success" in post["tags"]  # type: ignore[operator]

    def test_failure_posts_error_outcome_without_content(self) -> None:
        """A failed observation posts a bounded error outcome, not exception text."""
        client = _RecordingClient()
        observability = LangSmithLlmObservability(client=client)
        with (
            pytest.raises(RuntimeError, match="boom"),
            observability.observe(_safe_observation()),
        ):
            raise RuntimeError("boom with api key sk-leak")
        assert len(client.runs) == 1
        post = client.runs[0]
        assert "ati.outcome:error" in post["tags"]  # type: ignore[operator]
        assert "sk-leak" not in str(post)

    def test_content_bearing_observation_rejected(self) -> None:
        """A content-bearing observation is rejected before any export."""
        client = _RecordingClient()
        observability = LangSmithLlmObservability(client=client)
        with (
            pytest.raises(ValueError, match="control|operation_name"),
            observability.observe(
                LlmObservation(operation_name="op\nuser prompt content")
            ),
        ):
            pass
        assert client.runs == []

    def test_export_failure_is_fail_open(self) -> None:
        """A backend export failure never fails the application operation."""
        client = _RecordingClient(fail_export=True)
        observability = LangSmithLlmObservability(client=client)
        with observability.observe(_safe_observation()):
            assert True
