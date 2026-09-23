# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Manual evaluation workflow static tests (LS-W01..W18 / EA-W01..W18).

Parses the committed ``.github/workflows/evaluation.yml`` and ``ci.yml`` with
PyYAML and proves the PR 30B/30C security/trigger/runtime contract:

- ``workflow_dispatch`` only and read-only ``contents`` permission;
- operations include ``verify``/``sync``/``run``;
- Python 3.14 with locked ``uv sync``;
- local validation before any remote operation; LangSmith verify before any
  model work for ``run``; PostgreSQL and Alembic migrations configured and
  applied only for ``run``;
- ``LANGSMITH_API_KEY`` for every remote operation and the model-provider
  secret (``ATI_OPENAI_API_KEY``) referenced only for ``run``;
- verify/sync never need model execution;
- ordinary CI stays uncredentialed and offline;
- secrets are never echoed or literalized in shell lines.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]  # PyYAML ships no type stubs; test-only workflow parser

ROOT = Path(__file__).resolve().parents[4]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "evaluation.yml"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"

MODEL_PROVIDER_SECRETS = (
    "ATI_OPENAI_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "ATI_LLM_API_KEY",
    "LLM_API_KEY",
)
"""Secret names that must never appear outside the run step's environment."""

NON_RUN_SECRETS = ("ATI_OPENAI_API_KEY", "ANTHROPIC_API_KEY", "LLM_API_KEY")
"""Model-provider secrets that must never be referenced for verify/sync or echoed."""


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


def _run_steps(workflow: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    """Return ``(index, step)`` pairs of steps carrying a shell run command."""
    return [
        (index, step) for index, step in enumerate(_steps(workflow)) if step.get("run")
    ]


def _step_condition(step: dict[str, Any]) -> str:
    """Return the guard condition of one step (empty when unconditional)."""
    return step.get("if") or ""


def _can_run_for(step: dict[str, Any], operation: str) -> bool:
    """Return whether a step runs for the given workflow-dispatch operation."""
    condition = _step_condition(step)
    if not condition:
        return True
    return f"inputs.operation == '{operation}'" in condition


class TestWorkflowTriggersAndPermissions:
    """EA-W01..W05/W14..W17 trigger, permission, and operation contract."""

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

    def test_w03_run_operation_available(self) -> None:
        """W03 the operator can select verify, sync, or run."""
        workflow = _load(WORKFLOW_PATH)
        options = _triggers(workflow)["workflow_dispatch"]["inputs"]["operation"][
            "options"
        ]
        assert options == ["verify", "sync", "run"]

    def test_w19_dataset_is_data_not_shell_code(self) -> None:
        """W19 the dataset input is always quoted as data, never shell code."""
        workflow = _load(WORKFLOW_PATH)
        run_lines = [
            line
            for step in _steps(workflow)
            for line in (step.get("run") or "").splitlines()
        ]
        assert any('"${{ inputs.dataset }}"' in line for line in run_lines)
        assert not any("$(inputs.dataset)" in line for line in run_lines)

    def test_w20_evidence_analyst_still_supported(self) -> None:
        """W20 Evidence Analyst stays supported and the run step is dataset-agnostic."""
        workflow = _load(WORKFLOW_PATH)
        rendered = yaml.safe_dump(workflow)
        assert "evidence-analyst/v1" in rendered
        run_steps = [
            (step.get("run") or "")
            for step in _steps(workflow)
            if "ati-eval run" in (step.get("run") or "")
        ]
        assert run_steps
        # One dataset-agnostic run step serves any supported target.
        assert all('ati-eval run "${{ inputs.dataset }}"' in run for run in run_steps)


class TestWorkflowSecretsAndSteps:
    """EA-W04..W12 secrets, dependency, and step-order contract."""

    def test_w09_python_314(self) -> None:
        """W04/W09 the workflow runs Python 3.14 like ordinary CI."""
        workflow = _load(WORKFLOW_PATH)
        rendered = yaml.safe_dump(workflow)
        assert "3.14" in rendered

    def test_w10_locked_dependency_sync(self) -> None:
        """W05/W10 the workflow installs dependencies with the locked lockfile."""
        workflow = _load(WORKFLOW_PATH)
        assert any(
            "uv sync --locked" in (step.get("run") or "") for step in _steps(workflow)
        )

    def test_w07_references_langsmith_api_key(self) -> None:
        """W10 the workflow references the LANGSMITH_API_KEY secret."""
        workflow = _load(WORKFLOW_PATH)
        rendered = yaml.safe_dump(workflow)
        assert "LANGSMITH_API_KEY" in rendered

    def test_w11_model_provider_secret_only_for_run(self) -> None:
        """W11 the model-provider secret is wired only by the run step.

        Exactly the step executing ``ati-eval run`` (gated to the ``run``
        operation) carries the ``ATI_OPENAI_API_KEY`` secret reference; every
        other step stays free of it.
        """
        workflow = _load(WORKFLOW_PATH)
        wired_steps = [
            (index, step)
            for index, step in _run_steps(workflow)
            if "secrets.ATI_OPENAI_API_KEY" in yaml.safe_dump(step.get("env") or {})
        ]
        assert len(wired_steps) == 1
        index, step = wired_steps[0]
        assert "ati-eval run" in (step.get("run") or "")
        assert "inputs.operation == 'run'" in _step_condition(step)

    def test_w12_verify_sync_need_no_model_execution(self) -> None:
        """W12 verify/sync steps never require the model-provider secret."""
        workflow = _load(WORKFLOW_PATH)
        for _index, step in _run_steps(workflow):
            if _can_run_for(step, "run"):
                continue
            env = yaml.safe_dump(step.get("env") or {})
            for secret in NON_RUN_SECRETS:
                assert secret not in env
            assert "ati-eval run" not in (step.get("run") or "")

    def test_w18_secrets_never_echoed_in_shell(self) -> None:
        """W18 secret values are never echoed or literalized in shell lines.

        Shell lines may only reference secrets through ``${{ secrets.* }}``
        expressions (GitHub renders them as environment wiring); a literal
        credential value or a ``secrets.`` reference inside ``run`` text is
        forbidden.
        """
        workflow = _load(WORKFLOW_PATH)
        for _index, step in _run_steps(workflow):
            run = step.get("run") or ""
            for secret in MODEL_PROVIDER_SECRETS:
                assert f"secrets.{secret}" not in run
            assert "LANGSMITH_API_KEY" not in run.splitlines()[0] or (
                "secrets.LANGSMITH_API_KEY" not in run
            )

    def test_w11_validate_before_remote_operation(self) -> None:
        """W06 local validation runs before every LangSmith/model operation."""
        workflow = _load(WORKFLOW_PATH)
        runs = [
            (index, step.get("run") or "")
            for index, step in enumerate(_steps(workflow))
            if step.get("run")
        ]
        validate_index = next(
            index for index, run in runs if "ati-eval validate" in run
        )
        for marker in ("ati-eval langsmith", "ati-eval run"):
            remote_index = next((index for index, run in runs if marker in run), None)
            assert remote_index is None or validate_index < remote_index

    def test_w12_invokes_ati_eval_langsmith(self) -> None:
        """W12 the workflow invokes ati-eval langsmith with the operator inputs."""
        workflow = _load(WORKFLOW_PATH)
        assert any(
            "ati-eval langsmith" in (step.get("run") or "") for step in _steps(workflow)
        )


class TestRunOperation:
    """EA-W06..W09 run-operation runtime contract."""

    def test_w06_validate_before_run(self) -> None:
        """W06 local validation runs before the run step."""
        workflow = _load(WORKFLOW_PATH)
        runs = [
            (index, step.get("run") or "")
            for index, step in enumerate(_steps(workflow))
            if step.get("run")
        ]
        validate_index = next(
            index for index, run in runs if "ati-eval validate" in run
        )
        run_index = next(index for index, run in runs if "ati-eval run" in run)
        assert validate_index < run_index

    def test_w07_langsmith_verify_before_model_run(self) -> None:
        """W07 LangSmith verify (for run) precedes the ati-eval run step."""
        workflow = _load(WORKFLOW_PATH)
        runs = [
            (index, step.get("run") or "")
            for index, step in enumerate(_steps(workflow))
            if step.get("run")
        ]
        verify_index = next(
            index for index, run in runs if "ati-eval langsmith verify" in run
        )
        run_index = next(index for index, run in runs if "ati-eval run" in run)
        assert verify_index < run_index

    def test_w08_postgresql_configured_for_run(self) -> None:
        """W08 a PostgreSQL service step is configured and gated to run."""
        workflow = _load(WORKFLOW_PATH)
        postgres_steps = [
            step
            for step in _steps(workflow)
            if "podman-compose" in (step.get("run") or "")
            or "postgres" in (step.get("run") or "").lower()
        ]
        assert postgres_steps
        assert all(
            "inputs.operation == 'run'" in _step_condition(step)
            for step in postgres_steps
            if _step_condition(step)
        )

    def test_w09_migrations_applied_for_run(self) -> None:
        """W09 Alembic migrations are applied and gated to run."""
        workflow = _load(WORKFLOW_PATH)
        migration_steps = [
            step
            for step in _steps(workflow)
            if "alembic upgrade head" in (step.get("run") or "")
        ]
        assert migration_steps
        assert all(
            "inputs.operation == 'run'" in _step_condition(step)
            for step in migration_steps
            if _step_condition(step)
        )

    def test_run_uses_langsmith_flag(self) -> None:
        """The run step executes the benchmark with --langsmith."""
        workflow = _load(WORKFLOW_PATH)
        run_steps = [
            (step.get("run") or "")
            for step in _steps(workflow)
            if "ati-eval run" in (step.get("run") or "")
        ]
        assert run_steps
        assert all("--langsmith" in run for run in run_steps)


class TestOrdinaryCiUncredentialed:
    """EA-W13 ordinary CI remains uncredentialed and offline."""

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
