# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Source-contract guard for EntityLocation version allocation (PR 26A-2).

The behavioral proof lives in the real-PostgreSQL G26A2 matrix
(``tests/integration/test_geoint_persistence.py``). This narrow unit guard
pins the newest shipped GEOINT SQL API to the sequence-allocation invariant,
so a regression can never silently re-introduce arithmetic
``target.version + 1`` allocation inside
``ati.append_entity_location_observation`` without the integration matrix
catching it first. The scan is restricted to the function definition body
(comment lines excluded) so historical prose about the superseded behavior
is not flagged.
"""

import re
from pathlib import Path

_SQL_ROOT = Path(__file__).resolve().parents[2] / "migrations" / "sql" / "ati"
_FUNCTION_MARKER = "CREATE OR REPLACE FUNCTION ati.append_entity_location_observation"
_SEQUENCE_ALLOCATION = "nextval('ati.entity_location_version_seq')"
_ARITHMETIC_VERSION = re.compile(r"target\.version\s*\+\s*1")


def _latest_geoint_sql() -> Path:
    """Return the newest shipped version of the GEOINT persistence API."""
    versions = sorted(
        _SQL_ROOT.glob("v*/geoint_persistence.sql"),
        key=lambda path: int(path.parent.name[1:]),
    )
    assert versions, "no geoint persistence SQL version is shipped"
    return versions[-1]


def _active_append_function_sql() -> str:
    """Return the code (without comment lines) of the newest append function."""
    sql = _latest_geoint_sql().read_text()
    body = sql[sql.index(_FUNCTION_MARKER) :]
    return "\n".join(
        line for line in body.splitlines() if not line.strip().startswith("--")
    )


def test_active_geoint_api_allocates_entity_location_versions_from_sequence() -> None:
    """The active GEOINT API allocates EntityLocation versions from the sequence."""
    function_sql = _active_append_function_sql()
    # The corrected function must reference the dedicated sequence.
    assert _SEQUENCE_ALLOCATION in function_sql
    # ...and must never fall back to row-local arithmetic allocation.
    assert not _ARITHMETIC_VERSION.search(function_sql)
