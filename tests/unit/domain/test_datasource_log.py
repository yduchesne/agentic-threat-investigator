# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27B datasource-log event contract tests.

Stable matrix IDs D27B-U03..U06 pin the immutable bounded operational event
model: timezone-aware UTC timestamps, non-negative stage-local counts,
bounded canonical error codes bound to FAILED only, and the absence of any
payload/exception/metadata field.
"""

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.datasource import (
    TERMINAL_DATASOURCE_EXECUTION_EVENT_TYPES,
    DatasourceExecutionEventType,
    DatasourceId,
    DatasourceLogEvent,
    validate_datasource_error_code,
)

_EXECUTION_ID = UUID("11111111-1111-1111-1111-111111111111")
_DATASOURCE_ID = DatasourceId("threatfox-live")
_OCCURRED_AT = datetime(2026, 2, 1, 12, 30, 0, tzinfo=UTC)


def _event(
    *,
    execution_id: UUID = _EXECUTION_ID,
    datasource_id: DatasourceId = _DATASOURCE_ID,
    event_type: DatasourceExecutionEventType = DatasourceExecutionEventType.STARTED,
    occurred_at: datetime = _OCCURRED_AT,
    **overrides: object,
) -> DatasourceLogEvent:
    """Build a valid default STARTED event with optional overrides."""
    base: dict[str, object] = {
        "execution_id": execution_id,
        "datasource_id": datasource_id,
        "event_type": event_type,
        "occurred_at": occurred_at,
    }
    base.update(overrides)
    return DatasourceLogEvent(**base)  # type: ignore[arg-type]


def test_d27b_u03_aware_timestamps_normalize_to_utc() -> None:
    """D27B-U03: aware timestamps normalize to UTC; naive timestamps fail closed."""
    offset = datetime(2026, 2, 1, 17, 30, 0, tzinfo=timezone(timedelta(hours=5)))
    event = _event(occurred_at=offset)
    assert event.occurred_at == _OCCURRED_AT
    assert event.occurred_at.tzinfo is UTC
    with pytest.raises(ValidationError):
        _event(occurred_at=datetime(2026, 2, 1, 12, 30, 0))


@pytest.mark.parametrize("field", ["item_count", "byte_count"])
def test_d27b_u04_safe_counts(field: str) -> None:
    """D27B-U04: zero accepted; positive accepted; negative counts rejected."""
    assert getattr(_event(**{field: 0}), field) == 0  # type: ignore[arg-type]
    assert getattr(_event(**{field: 7}), field) == 7  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        _event(**{field: -1})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid",
    ["", "   ", " padded ", "Upper", "has space", "a" * 65, "has-dash"],
)
def test_d27b_u05_safe_error_codes(invalid: str) -> None:
    """D27B-U05: blank/whitespace/over-bound/malformed codes are rejected."""
    with pytest.raises((ValueError, ValidationError)):
        validate_datasource_error_code(invalid)
    with pytest.raises(ValidationError):
        _event(event_type=DatasourceExecutionEventType.FAILED, error_code=invalid)


def test_d27b_u05b_valid_error_code_accepted_and_bounded() -> None:
    """A canonical snake-case code round-trips on the FAILED event."""
    event = _event(
        event_type=DatasourceExecutionEventType.FAILED, error_code="acquisition_failed"
    )
    assert event.error_code == "acquisition_failed"
    assert len("a" * 64) == 64
    assert (
        _event(
            event_type=DatasourceExecutionEventType.FAILED, error_code="a" * 64
        ).error_code
        == "a" * 64
    )


def test_d27b_u05c_error_code_allowed_only_for_failed() -> None:
    """error_code is required for FAILED and forbidden on every other event."""
    with pytest.raises(ValidationError):
        _event(event_type=DatasourceExecutionEventType.FAILED, error_code=None)
    for event_type in DatasourceExecutionEventType:
        if event_type is DatasourceExecutionEventType.FAILED:
            continue
        with pytest.raises(ValidationError):
            _event(event_type=event_type, error_code="unexpected_error")


def test_d27b_u06_no_payload_field() -> None:
    """D27B-U06: the model forbids unknown fields, including payload/exception fields."""
    with pytest.raises(ValidationError):
        _event(payload={"raw": "body"})
    with pytest.raises(ValidationError):
        _event(exception="Traceback...")
    with pytest.raises(ValidationError):
        _event(metadata={"anything": "goes"})
    with pytest.raises(ValidationError):
        _event(headers={"Authorization": "Bearer secret"})
    with pytest.raises(ValidationError):
        _event(credentials={"token": "secret"})


def test_d27b_u06b_model_is_immutable() -> None:
    """The event is frozen: no attribute can be mutated after construction."""
    event = _event()
    with pytest.raises(ValidationError):
        event.item_count = 5


def test_terminal_event_vocabulary_is_exact() -> None:
    """Terminal vocabulary is exactly COMPLETED/FAILED/CANCELLED."""
    assert (
        frozenset(
            {
                DatasourceExecutionEventType.COMPLETED,
                DatasourceExecutionEventType.FAILED,
                DatasourceExecutionEventType.CANCELLED,
            }
        )
        == TERMINAL_DATASOURCE_EXECUTION_EVENT_TYPES
    )
    assert {member.value for member in DatasourceExecutionEventType} == {
        "started",
        "acquired",
        "decoded",
        "converted",
        "completed",
        "failed",
        "cancelled",
    }


def test_d27b_u13_no_inference_from_datasource_definition() -> None:
    """D27B-U13: lifecycle vocabulary never changes classification dimensions."""
    from agentic_threat_investigator.domain.datasource import (
        REPRESENTATIVE_DATASOURCE_DEFINITIONS,
        DatasourceProtocol,
        SerializationFormat,
    )
    from agentic_threat_investigator.domain.identifiers import SemanticFormatId

    definitions = REPRESENTATIVE_DATASOURCE_DEFINITIONS
    assert all(
        definition.protocol in DatasourceProtocol
        and definition.serialization_format is SerializationFormat.JSON
        and definition.semantic_format
        in (SemanticFormatId.STIX_21, SemanticFormatId.THREATFOX)
        for definition in definitions
    )
    # Event construction derives nothing from the definition's dimensions:
    # the same execution identity vocabulary is reused for any datasource.
    for definition in definitions:
        event = _event(datasource_id=definition.datasource_id)
        assert event.datasource_id is not None
        assert event.execution_id == _EXECUTION_ID
