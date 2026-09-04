# SPDX-License-Identifier: AGPL-3.0-only
"""Contract pin between ``BatchOutcome`` and the batch SQL function.

The repository deserializes the database function's outcome strings directly
into ``BatchOutcome``. These tests scan the newest shipped SQL version so a
drift between the enum and the function can never pass silently.
"""

import re
from pathlib import Path

import pytest

from agentic_threat_investigator.app.persistence.repositories import BatchOutcome

_SQL_ROOT = Path(__file__).resolve().parents[2] / "migrations" / "sql" / "ati"
_CLASSIFICATION_LITERAL = re.compile(r"(?:THEN|ELSE) '([A-Z_]+)'")


def _latest_entity_batch_sql() -> Path:
    """Return the newest shipped version of the entity batch function."""
    versions = sorted(
        _SQL_ROOT.glob("v*/entity_batch.sql"),
        key=lambda path: int(path.parent.name[1:]),
    )
    assert versions, "no entity batch SQL version is shipped"
    return versions[-1]


def test_classification_literals_match_batch_outcome_enum() -> None:
    """The newest SQL classifies with exactly the deserializable outcomes."""
    sql = _latest_entity_batch_sql().read_text()
    literals = set(_CLASSIFICATION_LITERAL.findall(sql))
    assert literals, "no classification literals found in the batch SQL"
    assert literals == {outcome.value for outcome in BatchOutcome}


@pytest.mark.parametrize("outcome", list(BatchOutcome))
def test_outcome_values_round_trip(outcome: BatchOutcome) -> None:
    """Every database outcome string deserializes into the enum."""
    assert BatchOutcome(outcome.value) is outcome


@pytest.mark.parametrize("value", ["INSERT", "UPDATE"])
def test_legacy_v0002_outcome_values_are_rejected(value: str) -> None:
    """The superseded v0002 outcome strings must fail deserialization."""
    with pytest.raises(ValueError):
        BatchOutcome(value)
