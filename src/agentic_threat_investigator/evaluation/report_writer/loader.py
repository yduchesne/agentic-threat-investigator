# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned Report Writer scenario loading (PR 23B).

Scenarios live as JSON files under ``evals/scenarios/report_writer/``.
Loading is strict: unknown fields, malformed values, duplicate JSON object
keys at any nesting depth, and duplicate ``(id, version)`` identities all
fail closed with a typed error. Discovery order is deterministic (sorted by
file name), so a scenario directory always yields the same ordered tuple.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentic_threat_investigator.evaluation.report_writer.models import (
    ReportWriterScenario,
)


class ReportWriterScenarioLoadError(ValueError):
    """A report-writer scenario file or directory cannot be loaded.

    ``path`` is absent when the failure was not tied to one file (for
    example duplicate scenario identities across a directory).
    """

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        """Record the message and optional offending file path."""
        suffix = f" ({path})" if path is not None else ""
        super().__init__(f"report-writer scenario load failed{suffix}: {message}")
        self.message = message
        self.path = path


class DuplicateJsonKeyError(ValueError):
    """A JSON object repeats one key at any nesting depth."""

    def __init__(self, key: str) -> None:
        """Record the duplicated key name."""
        super().__init__(f"duplicate JSON object key: {key!r}")
        self.key = key


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    """Build a dict from JSON object pairs, rejecting any repeated key."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(key)
        result[key] = value
    return result


def load_report_writer_scenarios_directory(
    directory: Path | str,
) -> tuple[ReportWriterScenario, ...]:
    """Load every report-writer scenario in sorted-by-filename order.

    Corpus identity is the exact ``(scenario.id, scenario.version)`` pair:
    two files may carry the same stable id at different positive versions,
    but a repeated identity is rejected.
    """
    root = Path(directory)
    if not root.is_dir():
        raise ReportWriterScenarioLoadError(
            "report-writer scenario directory does not exist", path=root
        )
    ordered_paths = sorted(root.glob("*.json"), key=lambda item: item.name)
    if not ordered_paths:
        raise ReportWriterScenarioLoadError(
            "report-writer scenario directory contains no JSON files", path=root
        )
    scenarios: list[ReportWriterScenario] = []
    for path in ordered_paths:
        try:
            text = path.read_bytes().decode("utf-8")
            raw: dict[str, Any] = json.loads(
                text, object_pairs_hook=_reject_duplicate_keys
            )
            scenarios.append(ReportWriterScenario.model_validate(raw))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ReportWriterScenarioLoadError(str(exc), path=path) from exc
    seen: set[tuple[str, int]] = set()
    duplicates: set[str] = set()
    for scenario in scenarios:
        identity = (scenario.id, scenario.version)
        rendered = f"{scenario.id}@{scenario.version}"
        if identity in seen:
            duplicates.add(rendered)
        seen.add(identity)
    if duplicates:
        raise ReportWriterScenarioLoadError(
            "duplicate scenario identities: " + ", ".join(sorted(duplicates))
        )
    return tuple(scenarios)
