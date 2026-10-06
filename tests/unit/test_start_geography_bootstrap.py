# SPDX-License-Identifier: AGPL-3.0-only
"""PR 35-3: start.sh canonical-geography bootstrap invariants.

There is no repository shell-test framework, so these tests statically lock
in the bootstrap contract that normal local startup loads canonical
reference geography through the production importer, after migrations and
before the final success summary, bounded and fail-closed. The importer's
own idempotency/transactional behavior is covered by the reference-ingestion
integration tests; these tests only guard the orchestration wiring.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
START_SH = REPO_ROOT / "start.sh"


def _script() -> str:
    """Return the current start.sh contents."""
    return START_SH.read_text(encoding="utf-8")


def _shell_function(script: str, name: str) -> str:
    """Return the body of one top-level ``name() { ... }`` shell function."""
    marker = f"{name}() {{"
    start = script.index(marker)
    end = script.index("\n}\n", start)
    return script[start : end + 3]


def test_start_imports_reference_geography_via_production_importer() -> None:
    """The bootstrap uses the installed production importer, not a reimplementation."""
    body = _shell_function(_script(), "ensure_canonical_geography")
    assert "ati-geography-import" in body
    # No geography parsing/SQL duplication and no upstream build/download.
    for forbidden in ("ati-geography-build", "INSERT INTO", "COPY ", "SELECT "):
        assert forbidden not in body


def test_start_geography_import_is_bounded_and_fail_closed() -> None:
    """The importer runs under the existing timeout and failure exits the script."""
    body = _shell_function(_script(), "ensure_canonical_geography")
    assert "run_with_timeout" in body
    assert "GEOGRAPHY_IMPORT_TIMEOUT" in body
    assert "return 1" in body

    main = _script()
    assert "if ! ensure_canonical_geography; then" in main
    # The failure branch must exit before the success summary.
    failure = main.index("if ! ensure_canonical_geography; then")
    assert main.index("exit 1", failure) < main.index("print_summary || exit 1")


def test_start_geography_import_follows_migration_and_precedes_summary() -> None:
    """Import happens after migrations and before final success output."""
    main = _script()
    migrate = main.index("health_check_one_shot migrate")
    geography = main.index("if ! ensure_canonical_geography; then")
    summary = main.index("print_summary || exit 1")
    assert migrate < geography < summary


def test_start_geography_bootstrap_is_mode_agnostic_and_not_a_count_check() -> None:
    """Fake/production share one path; readiness is importer success, not row counts."""
    main = _script()
    body = _shell_function(main, "ensure_canonical_geography")
    assert "ATI_OPERATING_MODE" not in body
    assert not re.search(r"count\(\*\)\s*FROM\s+ati\.location", main, re.IGNORECASE)
    assert "location_count" not in main


def test_start_geography_corpus_is_configurable_with_a_tracked_default() -> None:
    """A tracked synthetic corpus is the default; ATI_GEOGRAPHY_CORPUS overrides it."""
    main = _script()
    assert "ATI_GEOGRAPHY_CORPUS" in main
    assert "tests/fixtures/geoint/corpus_small.jsonl" in main
    # Relative overrides resolve against the repository root.
    assert 'GEOGRAPHY_CORPUS="${ROOT_DIR}/${GEOGRAPHY_CORPUS}"' in main
