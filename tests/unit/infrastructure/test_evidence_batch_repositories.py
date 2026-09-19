# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 28E batch persistence adapter serialization.

The PostgreSQL round trip lives in the integration suite; this module pins
the pure adapter surface the unit gate covers: the deterministic JSONB
serialization of one prepared record (thawed facts, canonical entity order,
sorted assertions) and the bounded identity detail parser.
"""

from __future__ import annotations

import pytest

from agentic_threat_investigator.app.evidence_consumer import (
    prepare_evidence_batch,
)
from agentic_threat_investigator.app.evidence_message import EvidenceMessage
from agentic_threat_investigator.infrastructure.persistence.postgresql.evidence_batch_repositories import (
    _detail_uuid,
    _serialize_record,
)
from tests.support.evidence_batch_fixtures import message_batch, threatfox_message

pytestmark = pytest.mark.unit


def _one_record() -> tuple[EvidenceMessage, object]:
    """Build (message, converted) of one canonical ThreatFox message."""
    return threatfox_message(
        ioc="malicious-domain.test",
        ioc_type="domain",
        source_record_id="rec-serial",
        sequence=0,
    )


def test_serialized_wire_shape_is_bounded_and_ordered() -> None:
    """The JSONB record carries only the validated persistence inputs."""
    message, _ = _one_record()
    prepared = prepare_evidence_batch(message_batch((message,)))
    wire = _serialize_record(prepared.records[0])
    assert wire["message_id"] == str(message.message_id)
    assert wire["observation_candidate_id"] == str(message.observation_candidate_id)
    assert wire["evidence"]["id"] == str(message.evidence_id)
    assert wire["evidence"]["source"] == "urn:ati:source:threatfox"
    assert wire["observation"]["facts"]["matches"][0]["ioc"] == "malicious-domain.test"
    assert wire["observation"]["observed_at"] is None
    assert wire["observation"]["raw_payload"] is None
    assert "position" not in wire
    assert "investigation_id" not in wire
    # Entities: invocation subject + extracted malware, identity-sorted.
    identities = [(entity["type"], entity["value"]) for entity in wire["entities"]]
    assert identities == [
        ("domain", "malicious-domain.test"),
        ("malware", "win.asyncrat"),
    ]
    assert wire["relationships"] == [
        {
            "source_type": "domain",
            "source_value": "malicious-domain.test",
            "type": "urn:ati:relationship:threat:associated_with",
            "target_type": "malware",
            "target_value": "win.asyncrat",
        }
    ]


def test_serialized_timestamps_are_canonical_utc() -> None:
    """Retrieved-at serializes as pinned Z suffix ISO-8601."""
    message, _ = _one_record()
    prepared = prepare_evidence_batch(message_batch((message,)))
    wire = _serialize_record(prepared.records[0])
    assert wire["observation"]["retrieved_at"].endswith("Z")
    assert "T" in wire["observation"]["retrieved_at"]


def test_detail_uuid_parses_only_bounded_identities() -> None:
    """The DETAIL helper accepts UUIDs and rejects everything else."""
    from uuid import uuid4

    value = uuid4()
    assert _detail_uuid(str(value)) == value
    assert _detail_uuid(None) is None
    assert _detail_uuid("not-a-uuid") is None
    assert _detail_uuid("") is None
