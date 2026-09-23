# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Manual evaluation workflow static tests (LS-W01..W13).

Parses the committed ``.github/workflows/evaluation.yml`` and ``ci.yml`` with
PyYAML and proves the PR 30B security/trigger contract: workflow_dispatch
only, read-only contents permission, the LangSmith secret only (no
model-provider secret), locked dependency sync, local validation before the
remote operation, and ordinary CI staying uncredentialed and offline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]  # PyYAML ships no type stubs; test-only workflow parser

ROOT = Path(__file__).resolve().parents[4]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "evaluation.yml"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"


def _load(path: Path) -> dict[Any, Any]:
    """Parse one workflow YAML document."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _triggers(workflow: dict[Any, Any]) -> dict[Any, Any]:
    """Return the trigger mapping, normalizing the YAML boolean ``on`` key."""
    on = workflow.get("on")
    if isinstance(on, dict):
        return on
    if isinstance(on, str):
        return {on: None}
    boolean_key = workflow.get(True)
    if isinstance(boolean_key, dict):
        return boolean_key
    if isinstance(boolean_key, str):
        return {boolean_key: None}
    return {}


def _steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the ordered step dictionaries of the evaluation job."""
    job = workflow["jobs"]["evaluation"]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)
    return list(steps)


class TestWorkflowTriggersAndPermissions:
    """LS-W01..W06 trigger and permission contract."""

    def test_w01_workflow_exists(self) -> None:
        """W01 the evaluation workflow file exists and parses."""
        assert WORKFLOW_PATH.is_file()
        workflow = _load(WORKFLOW_PATH)
        assert workflow["name"] == "Evaluation (manual)"

    def test_w02_only_workflow_dispatch(self) -> None:
        """W02 the workflow is triggered only by workflow_dispatch."""
        workflow = _load(WORKFLOW_PATH)
        assert set(_triggers(workflow).keys()) == {"workflow_dispatch"}

    def test_w03_contents_read_permission(self) -> None:
        """W03 the workflow requests only the read contents permission."""
        workflow = _load(WORKFLOW_PATH)
        assert workflow["permissions"] == {"contents": "read"}

    def test_w04_no_pr_trigger(self) -> None:
        """W04 no pull_request trigger exists."""
        workflow = _load(WORKFLOW_PATH)
        assert "pull_request" not in _triggers(workflow)

    def test_w05_no_push_trigger(self) -> None:
        """W05 no push trigger exists."""
        workflow = _load(WORKFLOW_PATH)
        assert "push" not in _triggers(workflow)

    def test_w06_no_schedule_trigger(self) -> None:
        """W06 no schedule trigger exists."""
        workflow = _load(WORKFLOW_PATH)
        assert "schedule" not in _triggers(workflow)


class TestWorkflowSecretsAndSteps:
    """LS-W07..W12 secrets and step contract."""

    def test_w07_references_langsmith_api_key(self) -> None:
        """W07 the workflow references the LANGSMITH_API_KEY secret."""
        workflow = _load(WORKFLOW_PATH)
        rendered = yaml.safe_dump(workflow)
        assert "LANGSMITH_API_KEY" in rendered

    def test_w08_no_model_provider_secret_yet(self) -> None:
        """W08 no model-provider secret is referenced yet (PR 30B runs no real target)."""
        workflow = _load(WORKFLOW_PATH)
        rendered = yaml.safe_dump(workflow)
        for forbidden in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "ATI_LLM_API_KEY",
            "LLM_API_KEY",
        ):
            assert forbidden not in rendered

    def test_w09_python_314(self) -> None:
        """W09 the workflow runs Python 3.14 like ordinary CI."""
        workflow = _load(WORKFLOW_PATH)
        rendered = yaml.safe_dump(workflow)
        assert "3.14" in rendered

    def test_w10_locked_dependency_sync(self) -> None:
        """W10 the workflow installs dependencies with the locked lockfile."""
        workflow = _load(WORKFLOW_PATH)
        assert any(
            "uv sync --locked" in (step.get("run") or "") for step in _steps(workflow)
        )

    def test_w11_local_validation_before_remote_operation(self) -> None:
        """W11 local dataset validation runs before any LangSmith operation."""
        workflow = _load(WORKFLOW_PATH)
        steps = _steps(workflow)
        runs = [(index, step.get("run") or "") for index, step in enumerate(steps)]
        validate_index = next(
            index for index, run in runs if "ati-eval validate" in run
        )
        langsmith_index = next(
            index for index, run in runs if "ati-eval langsmith" in run
        )
        assert validate_index < langsmith_index

    def test_w12_invokes_ati_eval_langsmith(self) -> None:
        """W12 the workflow invokes ati-eval langsmith with the operator inputs."""
        workflow = _load(WORKFLOW_PATH)
        assert any(
            "ati-eval langsmith" in (step.get("run") or "") for step in _steps(workflow)
        )


class TestOrdinaryCiUncredentialed:
    """LS-W13 ordinary CI remains uncredentialed and offline."""

    def test_w13_ci_yml_has_no_secrets(self) -> None:
        """W13 ci.yml carries no external credential and stays offline.

        The only secret reference in ordinary CI is the built-in
        ``GITHUB_TOKEN`` used by the gitleaks action (a repository-owned
        default token, not an operator credential); no LangSmith key and no
        model-provider secret may appear.
        """
        assert CI_PATH.is_file()
        text = CI_PATH.read_text(encoding="utf-8")
        assert "LANGSMITH_API_KEY" not in text
        for credential in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "ATI_LLM_API_KEY",
            "LLM_API_KEY",
        ):
            assert credential not in text
        secret_references = [
            line.strip()
            for line in text.splitlines()
            if "secrets." in line and "GITHUB_TOKEN" not in line
        ]
        assert secret_references == []
        ci = _load(CI_PATH)
        assert set(_triggers(ci).keys()) == {"pull_request"}
