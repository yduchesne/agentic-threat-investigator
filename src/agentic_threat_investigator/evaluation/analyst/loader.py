# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned scenario loading (PR 20C).

Scenarios live as JSON files under ``evals/scenarios/analyst/``. Loading is
strict: unknown fields, malformed values, unresolved expectation labels, and
duplicate scenario identities all fail closed with a typed error. Discovery
order is deterministic (sorted by file name), so a corpus directory always
yields the same scenario tuple.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentic_threat_investigator.evaluation.analyst.models import AnalystScenario


class AnalystScenarioLoadError(ValueError):
    """A scenario file or corpus directory cannot be loaded.

    ``path`` is absent when the failure was not tied to one file (for
    example duplicate scenario identities across a directory).
    """

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        """Record the message and optional offending file path."""
        suffix = f" ({path})" if path is not None else ""
        super().__init__(f"analyst scenario load failed{suffix}: {message}")
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
    """Build a dict from JSON object pairs, rejecting any repeated key.

    ``json.loads`` applies this hook at every nesting depth automatically, so
    a duplicated key anywhere in the document fails closed.
    """
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(key)
        result[key] = value
    return result


def load_scenario_file(path: Path) -> AnalystScenario:
    """Load and validate exactly one scenario JSON file.

    JSON decoding and every Pydantic validation constraint apply; a malformed
    file raises :class:`AnalystScenarioLoadError` and never yields a partial
    scenario. Duplicate JSON object keys and invalid UTF-8 text fail through
    the same bounded error seam.
    """
    try:
        text = path.read_bytes().decode("utf-8")
        raw: dict[str, Any] = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AnalystScenarioLoadError(str(exc), path=path) from exc
    try:
        return AnalystScenario.model_validate(raw)
    except (ValueError, TypeError) as exc:
        raise AnalystScenarioLoadError(str(exc), path=path) from exc


def load_scenarios_directory(directory: Path) -> tuple[AnalystScenario, ...]:
    """Load every ``*.json`` scenario in sorted-by-filename order.

    Corpus identity is the exact ``(scenario.id, scenario.version)`` pair:
    two files may carry the same stable id at different positive versions,
    but a repeated id at the same version is rejected.
    """
    ordered_paths = sorted(directory.glob("*.json"), key=lambda item: item.name)
    scenarios = tuple(load_scenario_file(path) for path in ordered_paths)
    seen: set[tuple[str, int]] = set()
    duplicates: set[str] = set()
    for scenario in scenarios:
        identity = (scenario.id, scenario.version)
        rendered = f"{scenario.id}@{scenario.version}"
        if identity in seen:
            duplicates.add(rendered)
        seen.add(identity)
    if duplicates:
        raise AnalystScenarioLoadError(
            "duplicate scenario identities: " + ", ".join(sorted(duplicates))
        )
    return scenarios
