# SPDX-License-Identifier: AGPL-3.0-only
"""Typed error mapping for custom persistence SQLSTATEs.

Versioned stored functions raise typed conflicts with dedicated SQLSTATEs so
repositories can surface application errors without parsing error text.
"""

SQLSTATE_INVESTIGATION_NOT_FOUND = "U18A1"
SQLSTATE_VERSION_CONFLICT = "U18A2"
SQLSTATE_EVIDENCE_DUPLICATE = "U18A3"
SQLSTATE_INVESTIGATION_DUPLICATE = "U18A4"
SQLSTATE_INVALID_TRANSITION = "U18A5"


def sqlstate(error: BaseException) -> str | None:
    """Return the SQLSTATE carried by a DBAPI error, if any."""
    orig = getattr(error, "orig", None)
    state = getattr(orig, "sqlstate", None)
    return state if isinstance(state, str) else None
