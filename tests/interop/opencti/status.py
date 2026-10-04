#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""OpenCTI interoperability readiness status/diagnose CLI (PR 33E section 10.7-10.8).

The CLI is the bounded command the harness (and operators) run to answer
machine-readably: *is this specific seeded interoperability run fully visible
in ATI yet?* It polls with a bounded interval and hard timeout, prints a
concise current stage, returns exit code 0 only for READY_FOR_ASSERTIONS, is
independently runnable after a failed run for diagnosis, and never prints
credentials, Authorization headers, raw secret-bearing responses, or
unbounded source payloads. PostgreSQL-persisted ATI domain state is the
authoritative final readiness condition; OpenCTI feed convergence and broker
state are corroborating gates only.

Usage (all modes):

  status.py --run-id <id> --state-dir <dir> [--manifest <path>] --wait \
      --timeout-seconds <n> [--interval-seconds <n>]
  status.py --run-id <id> --state-dir <dir> [--manifest <path>] --status
  status.py --run-id <id> --state-dir <dir> [--manifest <path>] --diagnose

Environment:

  DATABASE_URL          ATI PostgreSQL URL (integration-style, guarded)
  OPENCTI_TAXII_URL     TAXII 2.1 collection objects URL of real OpenCTI
  OPENCTI_TAXII_TOKEN   optional bearer token for the collection
  OPENCTI_ROOT_URL      OpenCTI API root (diagnostics, optional)
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from tests.interop.opencti._statemachine import (
    FAILURE_STAGE_BOOTSTRAP,
    FAILURE_STAGE_READINESS_TIMEOUT,
    InteropStage,
    ProbeSnapshot,
    StageResult,
    evaluate,
    wait_for_ready,
)

_TAXII_ACCEPT = "application/taxii+json;version=2.1"
_TAXII_MEDIA_TYPE = "application/taxii+json"


def _require(env: str) -> str:
    value = os.environ.get(env, "")
    if not value:
        raise SystemExit(f"{env} is required")
    return value


def _pg() -> Any:
    """Open one psycopg connection bound to the isolation/search path contract."""
    import psycopg

    url = _require("DATABASE_URL")
    if "ati-test" not in url and "ati-interop" not in url and "ati_interop" not in url:
        raise SystemExit("refusing interop status against a non-isolated database URL")
    sync_url = url.replace("postgresql+psycopg://", "postgresql://").replace(
        "postgresql+psycopg_async://", "postgresql://"
    )
    separator = "&" if "?" in sync_url else "?"
    if "search_path" not in sync_url:
        # psycopg's strict URI parser rejects an unescaped ``=`` inside the
        # options value; percent-encode it exactly like libpq requires.
        sync_url = f"{sync_url}{separator}options=-csearch_path%3Dati,public"
    return psycopg.connect(sync_url, connect_timeout=10)


def _taxii_feed_ids() -> list[str]:
    """Return the object IDs currently visible through the real TAXII endpoint.

    The harness TLS terminator presents a self-signed certificate generated
    per run; the same CA injected into the ATI driver is honored here so the
    probe verifies the real TLS boundary (never ``ssl._create_unverified``).
    """
    url = _require("OPENCTI_TAXII_URL")
    headers = {"Accept": _TAXII_ACCEPT, "User-Agent": "ati-interop-status/0.1"}
    token = os.environ.get("OPENCTI_TAXII_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    ca_file = os.environ.get("ATI_OPENCTI_CA_CERT")
    context = (
        ssl.create_default_context(cafile=ca_file)
        if ca_file
        else ssl.create_default_context()
    )
    request = urllib.request.Request(f"{url}?limit=500", headers=headers)
    with urllib.request.urlopen(request, timeout=30, context=context) as response:
        content_type = response.headers.get("Content-Type", "")
        if _TAXII_MEDIA_TYPE not in content_type:
            return []
        payload = json.loads(response.read().decode("utf-8"))
    objects = payload.get("objects", [])
    ids = [obj.get("id") for obj in objects if isinstance(obj, dict)]
    return [str(item) for item in ids if isinstance(item, str)]


class PostgresProbe:
    """PG-backed run-scoped probe snapshot builder."""

    def __init__(self, *, state: dict[str, Any], manifest: dict[str, Any]) -> None:
        self._state = state
        self._manifest = manifest

    def snapshot(self) -> ProbeSnapshot:
        """Derive one run-scoped snapshot purely from durable state."""
        raw_execution_id = self._state.get("execution_id")
        execution_id = raw_execution_id if isinstance(raw_execution_id, str) else None
        executed = bool(execution_id)
        with _pg() as connection, connection.cursor() as cursor:
            lifecycle = (
                self._lifecycle(cursor, cast(str, execution_id)) if executed else []
            )
            terminal = (
                self._terminal(cursor, cast(str, execution_id)) if executed else None
            )
            if terminal is not None:
                failure, stage = terminal
                return ProbeSnapshot(
                    seed_accepted=True,
                    feed_converged=True,
                    terminal_failure=failure,
                    terminal_stage=stage,
                )
            completed = executed and "completed" in lifecycle
            published = self._publish_converged(cursor)
            expected = self._expected_state(cursor)
            checkpoint = self._checkpoint_ok(cursor)
        feed_ok = False
        try:
            expected_ids = self._manifest.get("stix_ids")
            stix_ids = expected_ids if isinstance(expected_ids, list) else []
            feed_ok = set(_taxii_feed_ids()) >= set(stix_ids)
        except Exception:  # noqa: BLE001 - a feed probe failure means "not yet converged", never a crash
            feed_ok = False
        return ProbeSnapshot(
            seed_accepted=bool(self._state.get("seed_accepted")),
            feed_converged=feed_ok,
            execution_completed=completed,
            published=published,
            expected_state_matches=expected,
            checkpoint_matches=checkpoint,
        )

    @staticmethod
    def _lifecycle(cursor: Any, execution_id: str) -> list[str]:
        cursor.execute(
            "SELECT event_type FROM ati.datasource_log WHERE execution_id = %s "
            "ORDER BY id ASC",
            (execution_id,),
        )
        return [row[0] for row in cursor.fetchall()]

    @staticmethod
    def _terminal(cursor: Any, execution_id: str) -> tuple[str, str] | None:
        cursor.execute(
            "SELECT event_type, error_code FROM ati.datasource_log "
            "WHERE execution_id = %s AND event_type IN "
            "('failed', 'cancelled') ORDER BY id ASC LIMIT 1",
            (execution_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        event_type, error_code = row
        return (
            f"datasource execution {event_type} (code={error_code})",
            FAILURE_STAGE_BOOTSTRAP,
        )

    def _publish_converged(self, cursor: Any) -> bool:
        ids = self._manifest.get("expected_evidence_ids", [])
        if not ids:
            return False
        cursor.execute(
            "SELECT count(*) FROM ati.evidence_message_receipt r "
            "JOIN ati.evidence e ON e.id = r.evidence_id "
            "WHERE e.source_record_id = ANY(%s) "
            "AND e.source = %s",
            (list(ids), self._manifest.get("source_id")),
        )
        return int(cursor.fetchone()[0]) == len(ids)

    def _expected_state(self, cursor: Any) -> bool:
        if not self._publish_converged(cursor):
            return False
        ids = self._manifest.get("expected_evidence_ids", [])
        cursor.execute(
            "SELECT count(*) FROM ati.evidence WHERE source_record_id = ANY(%s) "
            "AND source = %s",
            (ids, self._manifest.get("source_id")),
        )
        if int(cursor.fetchone()[0]) != len(ids):
            return False
        for entity_type, values in (
            self._manifest.get("expected_entities") or {}
        ).items():
            cursor.execute(
                "SELECT count(*) FROM ati.entity WHERE entity_type = %s "
                "AND canonical_value = ANY(%s)",
                (entity_type, values),
            )
            if int(cursor.fetchone()[0]) != len(values):
                return False
        for rel in self._manifest.get("expected_relationships") or []:
            cursor.execute(
                "SELECT count(*) FROM ati.relationship r "
                "JOIN ati.entity s ON s.id = r.source_entity_id "
                "JOIN ati.entity t ON t.id = r.target_entity_id "
                "WHERE r.relationship_type = %s AND s.canonical_value = %s "
                "AND t.canonical_value = %s",
                (rel["type"], rel["source"], rel["target"]),
            )
            if int(cursor.fetchone()[0]) != 1:
                return False
        return True

    def _checkpoint_ok(self, cursor: Any) -> bool:
        expectation = self._manifest.get("checkpoint") or {}
        if not expectation.get("advance"):
            return True
        cursor.execute(
            "SELECT checkpoint_value FROM ati.datasource_checkpoint "
            "WHERE datasource_id = %s AND checkpoint_kind = %s",
            (expectation.get("datasource_id"), expectation.get("kind")),
        )
        return cursor.fetchone() is not None


def _stage_line(result: StageResult) -> str:
    """Print one concise human-readable status line."""
    if result.failed:
        return f"TERMINAL({result.terminal_stage}): {result.terminal_failure}"
    return str(result.stage)


def _stage_index(stage: InteropStage) -> int:
    """Return the deterministic stage order index (seed-first)."""
    return tuple(InteropStage).index(stage)


def wait_for_stage(
    probe_callable: Callable[[], ProbeSnapshot],
    target: InteropStage,
    *,
    timeout_seconds: float,
    interval_seconds: float = 2.0,
) -> StageResult:
    """Poll until the run passes the requested stage, READY, or a failure/timeout.

    Used by the orchestrator to wait for the OpenCTI feed convergence before
    starting ATI acquisition: readiness is then re-awaited with
    :func:`wait_for_ready` after the acquisition driver ran. Bounded like
    every harness wait; on timeout the caller diagnoses instead of asserting.
    """
    started = time.monotonic()
    result = evaluate(probe_callable())
    # ``evaluate`` returns the earliest NOT-yet-satisfied gate (READY once
    # every gate holds), so the target feed gate is passed exactly when the
    # derived stage moved PAST it. Loop while the stage names the target
    # gate (or an earlier one) still pending.
    while (
        not result.ready
        and not result.failed
        and _stage_index(result.stage) <= _stage_index(target)
    ):
        if time.monotonic() - started >= timeout_seconds:
            return StageResult(
                stage=result.stage,
                terminal_failure="stage wait timeout expired",
                terminal_stage=FAILURE_STAGE_READINESS_TIMEOUT,
            )
        time.sleep(interval_seconds)
        result = evaluate(probe_callable())
    return result


def _main_argv(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--manifest", default=None)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--wait", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--diagnose", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=1800.0)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument(
        "--until-stage",
        default=None,
        help="Wait only until this stage (or a later one) is reached; used by "
        "the orchestrator to wait for the OpenCTI feed before acquisition.",
    )
    args = parser.parse_args(argv)

    state_dir = Path(args.state_dir)
    state_path = state_dir / "run-state.json"
    if not state_path.exists():
        print(f"MISSING_RUN_STATE: {state_path}")
        return 2
    state = json.loads(state_path.read_text())
    manifest_path = Path(args.manifest) if args.manifest else state.get("manifest")
    if not manifest_path or not Path(manifest_path).exists():
        print("MISSING_MANIFEST")
        return 2
    manifest = json.loads(Path(manifest_path).read_text())
    probe = PostgresProbe(state=state, manifest=manifest)

    if args.diagnose:
        return _diagnose(args, state, manifest, probe)

    if args.status:
        result = evaluate(probe.snapshot())
        print(_stage_line(result))
        print(f"STAGE_IS_READY={1 if result.ready else 0}")
        return 0 if result.ready else 1

    if args.until_stage:
        target = InteropStage[args.until_stage]
        result = wait_for_stage(
            probe.snapshot,
            target,
            timeout_seconds=args.timeout_seconds,
            interval_seconds=args.interval_seconds,
        )
        print(_stage_line(result))
        return (
            0
            if result.stage is InteropStage.READY_FOR_ASSERTIONS
            or (_stage_index(result.stage) > _stage_index(target))
            else 1
        )

    result = wait_for_ready(
        probe.snapshot,
        timeout_seconds=args.timeout_seconds,
        interval_seconds=args.interval_seconds,
    )
    print(_stage_line(result))
    if result.ready:
        print("READY_FOR_ASSERTIONS")
        return 0
    print(f"NOT_READY terminal={result.terminal_stage!r}")
    return 1


def _diagnose(
    args: argparse.Namespace,
    state: dict[str, Any],
    manifest: dict[str, Any],
    probe: PostgresProbe,
) -> int:
    """Collect the bounded diagnostic bundle (section 10.8) and print its path."""
    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    bundle: dict[str, Any] = {
        "run_id": args.run_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pinned_images": dict((state.get("pinned_images") or {}).items()),
        "ati_git_sha": state.get("ati_git_sha"),
        "execution_id": state.get("execution_id"),
        "stage": _stage_line(evaluate(probe.snapshot())),
        "manifest_expectations": {
            "fixture": manifest.get("fixture"),
            "evidence": len(manifest.get("expected_evidence_ids", [])),
            "entities": {
                k: len(v) for k, v in (manifest.get("expected_entities") or {}).items()
            },
            "relationships": len(manifest.get("expected_relationships", [])),
            "unsupported": len(manifest.get("unsupported_stix_ids", [])),
            "checkpoint": manifest.get("checkpoint"),
        },
        "current_stage_probe": _probe_dict(probe.snapshot()),
        "container_health": _container_health(args.run_id),
    }
    execution_id = state.get("execution_id")
    if execution_id:
        with _pg() as connection, connection.cursor() as cursor:
            bundle["lifecycle"] = PostgresProbe._lifecycle(cursor, execution_id)
            cursor.execute(
                "SELECT checkpoint_value, version, updated_at "
                "FROM ati.datasource_checkpoint WHERE datasource_id = 'opencti-collection' "
                "AND checkpoint_kind = 'taxii_added_after'"
            )
            bundle["checkpoint"] = cursor.fetchone()
            cursor.execute(
                "SELECT count(*) FROM ati.evidence_message_receipt r JOIN ati.evidence e "
                "ON e.id = r.evidence_id WHERE e.source_id = 'urn:ati:source:opencti'"
            )
            bundle["receipt_count"] = int(cursor.fetchone()[0])
    bundle_path = state_dir / "diagnose-bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, default=str))
    print(f"DIAGNOSE_BUNDLE={bundle_path}")
    return 0


def _probe_dict(probe: ProbeSnapshot) -> dict[str, bool | str | None]:
    """Render a probe snapshot as a bounded dict (no secrets)."""
    return {
        "seed_accepted": probe.seed_accepted,
        "feed_converged": probe.feed_converged,
        "execution_completed": probe.execution_completed,
        "published": probe.published,
        "expected_state_matches": probe.expected_state_matches,
        "checkpoint_matches": probe.checkpoint_matches,
        "terminal_failure": probe.terminal_failure,
        "terminal_stage": probe.terminal_stage,
    }


def _container_health(run_id: str) -> list[dict[str, str]]:
    """Return bounded container health for the harness-owned Compose project."""
    try:
        result = subprocess.run(
            [
                "podman",
                "ps",
                "-a",
                "--filter",
                f"label=io.podman.compose.project={run_id}",
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


if __name__ == "__main__":
    sys.exit(_main_argv())
