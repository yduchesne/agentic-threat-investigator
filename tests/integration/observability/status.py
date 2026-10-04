#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 34 observability-harness readiness/convergence status CLI.

The CLI is the bounded command the harness (and operators) run to answer
machine-readably: *is this specific run's telemetry fully visible in the real
backends yet?* It polls with a bounded interval and hard timeout, prints a
concise current stage, returns exit 0 only once the requested stage (or
later) is reached, is independently runnable after a failed run for
diagnosis, and never prints credentials, Authorization headers, secret-
bearing responses, or unbounded bodies.

Usage (all modes):

  status.py --run-id <id> --state-dir <dir> --wait --until-stage <stage> \
      --timeout-seconds <n> [--interval-seconds <n>]
  status.py --run-id <id> --state-dir <dir> --status
  status.py --run-id <id> --state-dir <dir> --diagnose

Environment (set only by ``scripts/observability-integration.sh``):

  ATI_OBS_RUN_ID                  unique diagnostic run UUID
  ATI_OBS_COLLECTOR_HEALTH_URL    Collector health-check host URL
  ATI_OBS_PROMETHEUS_URL          Prometheus API host URL
  ATI_OBS_JAEGER_URL              Jaeger query API host URL
  ATI_OBS_LOKI_URL                Loki API host URL
  ATI_OBS_GRAFANA_URL             Grafana API host URL
  ATI_OBS_GRAFANA_ADMIN_USER      synthetic per-run admin user
  ATI_OBS_GRAFANA_ADMIN_PASSWORD  synthetic per-run admin password
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from tests.integration.observability._statemachine import (
    STAGE_ORDER,
    ObservabilityStage,
    StageResult,
    evaluate,
    wait_for_stage,
)
from tests.integration.observability.topology import ObsTopology
from tests.integration.observability.verifier import (
    collect_summaries,
    probe,
    topology_ready,
)


def _stage_index(stage: ObservabilityStage | None) -> int:
    """Return the ordinal of a stage (or -1 for ``None``)."""
    if stage is None:
        return -1
    return STAGE_ORDER.index(stage)


def _stage_line(result: StageResult) -> str:
    """Render one concise machine-readable stage line."""
    if result.failed:
        return f"STAGE={result.stage.value} TERMINAL={result.terminal_stage} FAILURE={result.terminal_failure}"
    return f"STAGE={result.stage.value}"


def _load_state(state_dir: Path) -> dict[str, Any]:
    """Load the bounded run-state artifact (required)."""
    state_path = state_dir / "run-state.json"
    if not state_path.exists():
        print(f"MISSING_RUN_STATE: {state_path}")
        raise SystemExit(2)
    try:
        loaded = json.loads(state_path.read_text())
    except json.JSONDecodeError:
        print(f"MALFORMED_RUN_STATE: {state_path}")
        raise SystemExit(2) from None
    if not isinstance(loaded, dict):
        print(f"MALFORMED_RUN_STATE: {state_path}")
        raise SystemExit(2)
    return dict(loaded)


def _signals_emitted(state: dict[str, Any]) -> bool:
    """Read the recorded generator outcome from the run-state artifact."""
    return bool(state.get("signals_emitted"))


def _write_state(state_dir: Path, **updates: Any) -> None:
    """Merge bounded updates into the run-state artifact."""
    state_path = state_dir / "run-state.json"
    state = json.loads(state_path.read_text())
    for key, value in updates.items():
        state[key] = value
    state_path.write_text(json.dumps(state, indent=2))


def _topology() -> ObsTopology:
    """Build the topology from the harness environment (or exit)."""
    return ObsTopology.from_environment()


def _container_rows() -> list[dict[str, str]]:
    """List the harness-owned Compose containers (bounded diagnostics)."""
    try:
        result = subprocess.run(
            [
                "podman",
                "ps",
                "-a",
                "--filter",
                f"label=io.podman.compose.project={os.environ.get('COMPOSE_PROJECT_NAME', '')}",
                "--format",
                "{{.Names}}|{{.Status}}",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception:  # noqa: BLE001 - container probing must never crash the diagnostic CLI
        return []
    rows = []
    for line in result.stdout.splitlines():
        if "|" in line:
            name, status = line.split("|", 1)
            rows.append({"name": name, "status": status})
    return rows


def _diagnose(args: argparse.Namespace) -> int:
    """Collect the bounded diagnostic bundle and print its path."""
    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    topology = _topology()
    ready_ok, checks = topology_ready(topology)
    bundle: dict[str, Any] = {
        "run_id": args.run_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ati_git_sha": _load_state(state_dir).get("ati_git_sha"),
        "stage": _stage_line(evaluate(probe(topology, signals_emitted=False))),
        "topology_ready": ready_ok,
        "per_service_ready": checks,
        "containers": _container_rows(),
    }
    bundle_path = state_dir / "diagnostics.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))
    print(bundle_path)
    return 0


def _main_argv(argv: list[str] | None = None) -> int:
    """Run the status CLI with the given argv (test seam)."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--state-dir", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--wait", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--diagnose", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=1200.0)
    parser.add_argument("--interval-seconds", type=float, default=3.0)
    parser.add_argument(
        "--until-stage",
        default=None,
        help="Wait only until this stage (or a later one) is reached.",
    )
    args = parser.parse_args(argv)

    state_dir = Path(args.state_dir)
    _load_state(state_dir)
    topology = _topology()

    if args.diagnose:
        return _diagnose(args)

    if args.status:
        result = evaluate(
            probe(topology, signals_emitted=_signals_emitted(_load_state(state_dir)))
        )
        _write_state(state_dir, stage=result.stage.value)
        print(_stage_line(result))
        print(f"STAGE_IS_READY={1 if result.ready else 0}")
        return 0 if result.ready else 1

    target = ObservabilityStage[args.until_stage] if args.until_stage else None

    def _snapshot() -> Any:
        """Build the live probe using the recorded generator outcome."""
        return probe(topology, signals_emitted=_signals_emitted(_load_state(state_dir)))

    if target is None:
        target = ObservabilityStage.READY_FOR_ASSERTIONS
    result = wait_for_stage(
        _snapshot,
        until=target,
        timeout_seconds=args.timeout_seconds,
        interval_seconds=args.interval_seconds,
    )
    print(_stage_line(result))
    _write_state(state_dir, stage=result.stage.value)
    if result.failed:
        print(f"NOT_READY terminal={result.terminal_stage!r}")
        return 1
    if _stage_index(result.stage) >= _stage_index(target):
        if target is ObservabilityStage.READY_FOR_ASSERTIONS and result.ready:
            _write_state(state_dir, **collect_summaries(topology))
        print("READY_FOR_ASSERTIONS" if result.ready else f"REACHED_{target.value}")
        return 0
    print(f"NOT_READY latest={result.stage.value}")
    return 1


if __name__ == "__main__":
    sys.exit(_main_argv())
