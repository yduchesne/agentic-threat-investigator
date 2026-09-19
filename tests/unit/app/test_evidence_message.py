# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 28C EvidenceMessage wire-contract unit tests (E28C matrix).

Matrix IDs:

- E28C-I01..I10: deterministic message/observation-candidate identities
  (UUIDv5, replay-stable per producer execution slot, tuple-reactive,
  timestamp/broker-independent, schema-version-independent, negative
  sequence rejected).
- E28C-B01..B12: pure builder from ``ConvertedEvidence`` +
  ``SemanticSourceContext`` + execution ID + sequence (exact V1 mapping,
  fail-closed cross-binding, deterministic flattened sequences, nullable
  fields, naive-timestamp rejection).
- E28C-R01..R06: message/ConvertedEvidence round trips and exact nested
  JSON/Unicode/microsecond/non-UTC canonical preservation.
- E28C-S01..S09: canonical byte-deterministic encoding (stable bytes,
  insertion-order independence, canonical UUID/URN/null representations,
  NaN/Infinity/arbitrary-object rejection).
- E28C-D01..D16: strict decode fail-closed behavior (UTF-8/JSON, version,
  extra fields, malformed values, identity mismatch, no payload echo).
- E28C-P01..P08: contract boundary (no Investigation/subject/graph/broker/
  metadata state; no candidate version/diff; material-state semantics).
- E28C-V01..V03: production ThreatFox vertical slice (converter -> builder
  -> codec -> reconstruction; replay; later unchanged acquisition).

All tests are deterministic, offline, and involve no database, network,
broker, or UnitOfWork.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    EvidenceConversionContext,
)
from agentic_threat_investigator.app.evidence_message import (
    EVIDENCE_MESSAGE_SCHEMA_VERSION,
    EvidenceMessage,
    EvidenceMessageDecodeError,
    EvidenceMessageError,
    EvidenceMessageValidationError,
    UnsupportedEvidenceMessageVersionError,
    converted_evidence_from_message,
    decode_evidence_message,
    encode_evidence_message,
    evidence_message_from_converted,
    evidence_message_id,
    evidence_observation_candidate_id,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceMaterialState,
    EvidenceObservationCandidate,
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.infrastructure.datasources.threatfox_evidence import (
    ThreatFoxToEvidenceConverter,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
)
from tests.support.threatfox_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    asyncrat_domain_record,
)

pytestmark = pytest.mark.unit

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_LATER_TS = datetime(2026, 6, 2, 9, 30, 15, 123456, tzinfo=UTC)
_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)


def _context(
    *,
    retrieved_at: datetime = _FIXED_TS,
    source_reference: str | None = _ENDPOINT,
    datasource_id: DatasourceId | None = None,
    source_id: SourceId = SourceId.THREATFOX,
    semantic_format: SemanticFormatId = SemanticFormatId.THREATFOX,
) -> SemanticSourceContext:
    """Build one deterministic semantic provenance context."""
    return SemanticSourceContext(
        datasource_id=datasource_id or _DEFINITION.datasource_id,
        source_id=source_id,
        semantic_format=semantic_format,
        retrieved_at=retrieved_at,
        source_reference=source_reference,
    )


def _converted(
    context: SemanticSourceContext,
    *,
    source_record_id: str = "record-1",
    facts: dict[str, Any] | None = None,
    observed_at: datetime | None = None,
    raw_payload: dict[str, Any] | None = None,
    source_url: str | None = None,
    evidence_id: UUID | None = None,
    evidence_type: EvidenceType = EvidenceType.THREAT_INTELLIGENCE,
) -> ConvertedEvidence:
    """Build one deterministic ConvertedEvidence consistent with a context.

    ``source_url=None`` means "use the context's credential-free reference".
    """
    if evidence_id is None:
        evidence_id = evidence_id_for_source_record(
            context.semantic_format, context.source_id, source_record_id
        )
    effective_source_url: str | None = (
        context.source_reference if source_url is None else source_url
    )
    return ConvertedEvidence(
        evidence=Evidence(
            id=evidence_id,
            type=evidence_type,
            source=context.source_id.value,
            source_record_id=source_record_id,
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=evidence_id,
            source_url=effective_source_url,
            observed_at=observed_at,
            retrieved_at=context.retrieved_at,
            facts={} if facts is None else facts,
            raw_payload=raw_payload,
        ),
    )


def _message(
    converted: ConvertedEvidence | None = None,
    *,
    context: SemanticSourceContext | None = None,
    execution_id: UUID | None = None,
    sequence: int = 0,
) -> EvidenceMessage:
    """Build one deterministic V1 message through the public builder."""
    if context is None:
        context = _context()
    if converted is None:
        converted = _converted(context)
    return evidence_message_from_converted(
        converted,
        datasource_execution_id=execution_id or uuid4(),
        semantic_source=context,
        sequence=sequence,
    )


def _message_kwargs(message: EvidenceMessage) -> dict[str, Any]:
    """Return construction kwargs reproducing one message (for overrides)."""
    return {
        "schema_version": message.schema_version,
        "message_id": message.message_id,
        "observation_candidate_id": message.observation_candidate_id,
        "datasource_execution_id": message.datasource_execution_id,
        "datasource_id": message.datasource_id,
        "source_id": message.source_id,
        "semantic_format": message.semantic_format,
        "sequence": message.sequence,
        "evidence_id": message.evidence_id,
        "evidence_type": message.evidence_type,
        "source_record_id": message.source_record_id,
        "retrieved_at": message.retrieved_at,
        "observed_at": message.observed_at,
        "source_url": message.source_url,
        "facts": message.facts,
        "raw_payload": message.raw_payload,
    }


def _override(message: EvidenceMessage, **changes: Any) -> dict[str, Any]:
    """Merge construction kwargs with overrides for direct construction."""
    merged: dict[str, Any] = dict(_message_kwargs(message))
    merged.update(changes)
    return merged


def _decode_wire(message: EvidenceMessage) -> dict[str, Any]:
    """Decode one message's canonical bytes back to its plain wire dict."""
    data: dict[str, Any] = json.loads(encode_evidence_message(message).decode("utf-8"))
    return data


class TestMessageIdentity:
    """E28C-I01..I10: deterministic UUIDv5 message/candidate identities."""

    def test_i01_same_slot_same_message_id(self) -> None:
        """E28C-I01: same execution + sequence + Evidence -> identical message ID."""
        execution_id = uuid4()
        first = _message(execution_id=execution_id, sequence=3)
        second = _message(execution_id=execution_id, sequence=3)
        assert first.message_id == second.message_id
        assert first.message_id.version == 5

    def test_i02_different_execution_different_message_id(self) -> None:
        """E28C-I02: a different execution changes the message ID."""
        assert (
            _message(execution_id=uuid4(), sequence=0).message_id
            != _message(execution_id=uuid4(), sequence=0).message_id
        )

    def test_i03_different_sequence_different_message_id(self) -> None:
        """E28C-I03: a different flat sequence changes the message ID."""
        execution_id = uuid4()
        assert (
            _message(execution_id=execution_id, sequence=0).message_id
            != _message(execution_id=execution_id, sequence=1).message_id
        )

    def test_i04_different_evidence_different_message_id(self) -> None:
        """E28C-I04: a different Evidence identity changes the message ID."""
        execution_id = uuid4()
        context = _context()
        first = _message(execution_id=execution_id, sequence=0)
        other = _message(
            _converted(context, source_record_id="record-2"),
            execution_id=execution_id,
            sequence=0,
        )
        assert first.evidence_id != other.evidence_id
        assert first.message_id != other.message_id

    def test_i05_same_message_same_candidate_id(self) -> None:
        """E28C-I05: the same message yields the identical candidate UUIDv5."""
        message = _message()
        assert message.observation_candidate_id == evidence_observation_candidate_id(
            message.message_id
        )
        assert message.observation_candidate_id.version == 5

    def test_i06_different_message_different_candidate_id(self) -> None:
        """E28C-I06: a different message yields a different candidate ID."""
        first = _message(sequence=0)
        second = _message(sequence=1)
        assert first.observation_candidate_id != second.observation_candidate_id

    def test_i07_retrieval_time_not_in_identity(self) -> None:
        """E28C-I07: only retrieval time changing keeps the message ID stable."""
        execution_id = uuid4()
        early = _message(
            _converted(_context(retrieved_at=_FIXED_TS)),
            context=_context(retrieved_at=_FIXED_TS),
            execution_id=execution_id,
            sequence=0,
        )
        late = _message(
            _converted(_context(retrieved_at=_LATER_TS)),
            context=_context(retrieved_at=_LATER_TS),
            execution_id=execution_id,
            sequence=0,
        )
        assert early.retrieved_at != late.retrieved_at
        assert early.message_id == late.message_id

    def test_i08_no_broker_metadata_identity_computes(self) -> None:
        """E28C-I08: identity computes with no broker metadata present."""
        message = _message()
        assert isinstance(
            evidence_message_id(
                message.datasource_execution_id, message.sequence, message.evidence_id
            ),
            UUID,
        )
        assert message.message_id == evidence_message_id(
            message.datasource_execution_id, message.sequence, message.evidence_id
        )

    def test_i09_schema_representation_not_in_evidence_identity(self) -> None:
        """E28C-I09: Evidence identity ignores message representation/slot.

        Two messages for the same source record but different producer slots
        and schema handling share the exact deterministic Evidence ID,
        proving schema representation never contaminates Evidence identity.
        """
        context = _context()
        converted = _converted(context)
        zero = _message(converted, execution_id=uuid4(), sequence=0)
        seven = _message(converted, execution_id=uuid4(), sequence=7)
        assert zero.evidence_id == seven.evidence_id
        assert zero.evidence_id == evidence_id_for_source_record(
            context.semantic_format, context.source_id, "record-1"
        )
        assert zero.evidence_id not in (
            zero.message_id,
            zero.observation_candidate_id,
        )

    def test_i10_negative_sequence_rejected(self) -> None:
        """E28C-I10: a negative flattening sequence fails closed."""
        with pytest.raises(EvidenceMessageValidationError):
            _message(sequence=-1)


class TestBuilderBinding:
    """E28C-B01..B12: pure builder mapping and fail-closed cross-binding."""

    def test_b01_valid_converted_evidence_exact_v1_message(self) -> None:
        """E28C-B01: a valid ConvertedEvidence maps to the exact V1 message."""
        context = _context()
        converted = _converted(
            context, facts={"matches": [{"ioc": CANONICAL_ASYNCRAT_DOMAIN}]}
        )
        message = _message(converted, context=context, sequence=0)
        assert message.schema_version == EVIDENCE_MESSAGE_SCHEMA_VERSION
        assert message.datasource_id == context.datasource_id
        assert message.source_id == context.source_id
        assert message.semantic_format == context.semantic_format
        assert message.sequence == 0
        assert message.evidence_id == converted.evidence.id
        assert message.evidence_type == converted.evidence.type
        assert message.source_record_id == converted.evidence.source_record_id
        assert message.source_url == converted.observation.source_url
        assert message.observed_at == converted.observation.observed_at
        assert message.retrieved_at == converted.observation.retrieved_at
        assert message.facts == converted.observation.facts
        assert message.raw_payload == converted.observation.raw_payload

    def test_b02_wrong_semantic_evidence_id_rejected(self) -> None:
        """E28C-B02: an Evidence ID outside its semantic identity fails closed."""
        context = _context()
        converted = _converted(context, evidence_id=uuid4())
        with pytest.raises(EvidenceMessageValidationError):
            _message(converted, context=context)

    def test_b03_candidate_evidence_mismatch_rejected(self) -> None:
        """E28C-B03: candidate.evidence_id != Evidence.id fails closed."""
        context = _context()
        converted = _converted(context)
        converted = ConvertedEvidence(
            evidence=converted.evidence,
            observation=EvidenceObservationCandidate(
                evidence_id=uuid4(),
                source_url=converted.observation.source_url,
                retrieved_at=context.retrieved_at,
                facts=converted.observation.facts,
            ),
        )
        with pytest.raises(EvidenceMessageValidationError):
            _message(converted, context=context)

    def test_b04_evidence_source_context_mismatch_rejected(self) -> None:
        """E28C-B04: Evidence.source != context source fails closed."""
        context = _context()
        converted = ConvertedEvidence(
            evidence=Evidence(
                id=evidence_id_for_source_record(
                    context.semantic_format, SourceId.URLHAUS, "record-1"
                ),
                type=EvidenceType.THREAT_INTELLIGENCE,
                source=SourceId.URLHAUS.value,
                source_record_id="record-1",
            ),
            observation=EvidenceObservationCandidate(
                evidence_id=evidence_id_for_source_record(
                    context.semantic_format, SourceId.URLHAUS, "record-1"
                ),
                source_url=context.source_reference,
                retrieved_at=context.retrieved_at,
            ),
        )
        with pytest.raises(EvidenceMessageValidationError):
            _message(converted, context=context)

    def test_b05_empty_source_record_id_rejected(self) -> None:
        """E28C-B05: an empty upstream record identity fails closed."""
        context = _context()
        converted = _converted(context, source_record_id="")
        with pytest.raises(EvidenceMessageValidationError):
            _message(converted, context=context)

    def test_b06_sequence_zero_accepted(self) -> None:
        """E28C-B06: the flattening sequence may be zero."""
        message = _message(sequence=0)
        assert message.sequence == 0
        decoded = decode_evidence_message(encode_evidence_message(message))
        assert decoded.sequence == 0

    def test_b07_flattened_items_distinct_deterministic_ids(self) -> None:
        """E28C-B07: flattened items 0..N-1 get distinct deterministic IDs."""
        context = _context()
        execution_id = uuid4()
        messages = [
            _message(
                _converted(context, source_record_id=f"record-{index}"),
                context=context,
                execution_id=execution_id,
                sequence=index,
            )
            for index in range(3)
        ]
        assert {message.sequence for message in messages} == {0, 1, 2}
        assert len({message.message_id for message in messages}) == 3
        assert len({message.observation_candidate_id for message in messages}) == 3
        repeated = [
            _message(
                _converted(context, source_record_id=f"record-{index}"),
                context=context,
                execution_id=execution_id,
                sequence=index,
            )
            for index in range(3)
        ]
        assert [message.message_id for message in messages] == [
            message.message_id for message in repeated
        ]

    def test_b08_observed_at_null_accepted(self) -> None:
        """E28C-B08: a null observed_at is accepted and preserved."""
        message = _message(_converted(_context(), observed_at=None))
        assert message.observed_at is None

    def test_b09_raw_payload_null_accepted(self) -> None:
        """E28C-B09: a null raw_payload is accepted and preserved."""
        message = _message(_converted(_context(), raw_payload=None))
        assert message.raw_payload is None

    def test_b10_empty_facts_accepted(self) -> None:
        """E28C-B10: an empty facts object is accepted and preserved."""
        message = _message(_converted(_context(), facts={}))
        assert message.facts == {}

    def test_b11_naive_retrieved_at_rejected(self) -> None:
        """E28C-B11: a naive retrieved_at fails closed at the message seam."""
        message = _message()
        with pytest.raises(EvidenceMessageValidationError):
            EvidenceMessage(
                **_override(message, retrieved_at=datetime(2026, 6, 1, 12, 0, 0))
            )

    def test_b12_naive_observed_at_rejected(self) -> None:
        """E28C-B12: a naive observed_at fails closed at the message seam."""
        message = _message()
        with pytest.raises(EvidenceMessageValidationError):
            EvidenceMessage(
                **_override(message, observed_at=datetime(2026, 6, 1, 12, 0, 0))
            )

    def test_b13_candidate_source_url_context_mismatch_rejected(self) -> None:
        """E28C-B13: a candidate source_url conflicting with the context fails.

        The production ThreatFox converter maps the credential-free context
        reference onto the candidate ``source_url`` verbatim; the builder
        validates that identity rather than silently choosing a value.
        """
        context = _context()
        converted = _converted(context, source_url="https://other.test/feed")
        with pytest.raises(EvidenceMessageValidationError):
            _message(converted, context=context)

    def test_b14_candidate_retrieved_at_context_mismatch_rejected(self) -> None:
        """E28C-B14: a candidate retrieval time conflicting with the context fails."""
        context = _context()
        converted = _converted(context)
        converted = ConvertedEvidence(
            evidence=converted.evidence,
            observation=EvidenceObservationCandidate(
                evidence_id=converted.evidence.id,
                source_url=context.source_reference,
                retrieved_at=_LATER_TS,
                facts=converted.observation.facts,
            ),
        )
        with pytest.raises(EvidenceMessageValidationError):
            _message(converted, context=context)

    def test_b15_empty_source_url_rejected(self) -> None:
        """E28C-B15: an empty source_url fails closed on the message seam."""
        message = _message()
        with pytest.raises(EvidenceMessageValidationError):
            EvidenceMessage(**_override(message, source_url=""))

    def test_b16_boolean_schema_version_rejected(self) -> None:
        """E28C-B16: a boolean schema_version never masquerades as version 1."""
        message = _message()
        with pytest.raises(EvidenceMessageValidationError):
            EvidenceMessage(**_override(message, schema_version=True))


class TestRoundTrip:
    """E28C-R01..R06: message and ConvertedEvidence round trips."""

    def test_r01_message_bytes_message_equality(self) -> None:
        """E28C-R01: message -> bytes -> message yields an equal message."""
        message = _message()
        assert decode_evidence_message(encode_evidence_message(message)) == message

    def test_r02_converted_message_converted_equality(self) -> None:
        """E28C-R02: ConvertedEvidence -> message -> ConvertedEvidence equality."""
        context = _context()
        converted = _converted(
            context,
            facts={"match": {"tags": ["a", "b"], "ioc": "203.0.113.42"}},
            observed_at=_FIXED_TS,
            raw_payload={"extra": {"n": 3}},
        )
        message = _message(converted, context=context)
        assert converted_evidence_from_message(message) == converted

    def test_r03_nested_json_exact_preservation(self) -> None:
        """E28C-R03: deeply nested JSON survives the codec exactly."""
        message = _message(
            _converted(
                _context(),
                facts={
                    "outer": {
                        "inner": [
                            {"k": ["v1", None, 2, 3.5, True]},
                            {"empty_list": [], "empty_obj": {}},
                        ]
                    }
                },
            )
        )
        decoded = decode_evidence_message(encode_evidence_message(message))
        assert thaw_json(decoded.facts) == {
            "outer": {
                "inner": [
                    {"k": ["v1", None, 2, 3.5, True]},
                    {"empty_list": [], "empty_obj": {}},
                ]
            }
        }

    def test_r04_unicode_utf8_round_trip(self) -> None:
        """E28C-R04: non-ASCII Unicode survives as UTF-8 exactly."""
        text = "威胁情报测试 — π ≈ 3.14159"
        message = _message(_converted(_context(), facts={"label": text}))
        payload = encode_evidence_message(message)
        assert text.encode("utf-8") in payload
        assert decode_evidence_message(payload).facts["label"] == text

    def test_r05_microseconds_exact_instant(self) -> None:
        """E28C-R05: microsecond precision is preserved exactly."""
        message = _message(
            _converted(_context(retrieved_at=_LATER_TS)),
            context=_context(retrieved_at=_LATER_TS),
        )
        decoded = decode_evidence_message(encode_evidence_message(message))
        assert decoded.retrieved_at == _LATER_TS
        assert decoded.retrieved_at.microsecond == 123456
        assert ".123456Z" in encode_evidence_message(message).decode("utf-8")

    def test_r06_non_utc_aware_input_canonical_utc(self) -> None:
        """E28C-R06: non-UTC aware timestamps are canonicalized to UTC."""
        message = _message()
        offset = datetime(
            2026, 6, 1, 17, 30, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))
        )
        shifted = EvidenceMessage(**_override(message, retrieved_at=offset))
        assert shifted.retrieved_at == _FIXED_TS
        assert shifted.retrieved_at.utcoffset() == timedelta(0)
        assert (
            "2026-06-01T12:00:00.000000Z" in encode_evidence_message(shifted).decode()
        )


class TestCanonicalEncoding:
    """E28C-S01..S09: canonical byte-deterministic encoding."""

    def test_s01_encode_twice_byte_identical(self) -> None:
        """E28C-S01: encoding the same message twice yields identical bytes."""
        message = _message()
        assert encode_evidence_message(message) == encode_evidence_message(message)

    def test_s02_facts_insertion_order_identical_bytes(self) -> None:
        """E28C-S02: facts insertion order never changes the bytes."""
        context = _context()
        execution_id = uuid4()
        first = _message(
            _converted(context, facts={"a": 1, "b": 2}),
            context=context,
            execution_id=execution_id,
        )
        second = _message(
            _converted(context, facts={"b": 2, "a": 1}),
            context=context,
            execution_id=execution_id,
        )
        assert encode_evidence_message(first) == encode_evidence_message(second)

    def test_s03_raw_payload_insertion_order_identical_bytes(self) -> None:
        """E28C-S03: raw payload insertion order never changes the bytes."""
        context = _context()
        execution_id = uuid4()
        first = _message(
            _converted(context, raw_payload={"a": {"z": 1}, "b": [2, {"y": None}]}),
            context=context,
            execution_id=execution_id,
        )
        second = _message(
            _converted(context, raw_payload={"b": [2, {"y": None}], "a": {"z": 1}}),
            context=context,
            execution_id=execution_id,
        )
        assert encode_evidence_message(first) == encode_evidence_message(second)

    def test_s04_uuids_canonical_lowercase_strings(self) -> None:
        """E28C-S04: wire UUIDs are canonical lowercase strings."""
        message = _message()
        wire = _decode_wire(message)
        for field in (
            "message_id",
            "observation_candidate_id",
            "datasource_execution_id",
            "evidence_id",
        ):
            assert wire[field] == str(message.__getattribute__(field))
            assert wire[field] == wire[field].lower()

    def test_s05_enums_urn_stable_values(self) -> None:
        """E28C-S05: enums/semantic identifiers use stable wire values."""
        message = _message()
        wire = _decode_wire(message)
        assert wire["datasource_id"] == message.datasource_id.value
        assert wire["source_id"] == SourceId.THREATFOX.value
        assert wire["semantic_format"] == SemanticFormatId.THREATFOX.value
        assert wire["evidence_type"] == EvidenceType.THREAT_INTELLIGENCE.value
        assert wire["source_id"] == "urn:ati:source:threatfox"
        assert wire["evidence_type"] == "urn:ati:evidence:threat_intelligence"

    def test_s06_nullable_optionals_pinned_null(self) -> None:
        """E28C-S06: nullable optionals encode the pinned JSON null."""
        message = _message()
        assert message.observed_at is None
        assert message.raw_payload is None
        wire = _decode_wire(message)
        assert wire["observed_at"] is None
        assert wire["raw_payload"] is None

    def test_s07_nan_rejected(self) -> None:
        """E28C-S07: NaN in JSON values fails closed, never stringified."""
        message = _message()
        with pytest.raises(EvidenceMessageValidationError):
            EvidenceMessage(**_override(message, facts={"x": float("nan")}))

    def test_s08_infinity_rejected(self) -> None:
        """E28C-S08: Infinity in JSON values fails closed, never stringified."""
        message = _message()
        with pytest.raises(EvidenceMessageValidationError):
            EvidenceMessage(**_override(message, facts={"x": float("inf")}))
        with pytest.raises(EvidenceMessageValidationError):
            EvidenceMessage(**_override(message, raw_payload={"x": float("-inf")}))

    def test_s09_arbitrary_object_rejected(self) -> None:
        """E28C-S09: an unsupported object fails closed, never str()-ed."""
        message = _message()
        with pytest.raises(EvidenceMessageValidationError):
            EvidenceMessage(**_override(message, facts={"x": object()}))


class TestDecodeFailClosed:
    """E28C-D01..D16: strict decode with typed bounded failures."""

    def test_d01_malformed_json_decode_error(self) -> None:
        """E28C-D01: malformed JSON raises the decode error."""
        with pytest.raises(EvidenceMessageDecodeError):
            decode_evidence_message(b'{"schema_version": 1, ')

    def test_d02_invalid_utf8_decode_error(self) -> None:
        """E28C-D02: invalid UTF-8 raises the decode error."""
        with pytest.raises(EvidenceMessageDecodeError):
            decode_evidence_message(b"\xff\xfe\x00")

    def test_d03_top_level_array_validation_error(self) -> None:
        """E28C-D03: a top-level array is a structure violation."""
        with pytest.raises(EvidenceMessageValidationError):
            decode_evidence_message(b"[1, 2, 3]")

    def test_d04_missing_schema_version_validation_error(self) -> None:
        """E28C-D04: a missing schema_version fails closed."""
        message = _message()
        wire = _decode_wire(message)
        del wire["schema_version"]
        with pytest.raises(EvidenceMessageValidationError) as caught:
            decode_evidence_message(json.dumps(wire, sort_keys=True).encode("utf-8"))
        assert isinstance(caught.value, EvidenceMessageError)

    def test_d05_invalid_old_zero_version_fails_closed(self) -> None:
        """E28C-D05: zero/bool/string/float schema versions fail pinned."""
        message = _message()
        base = _decode_wire(message)
        with pytest.raises(UnsupportedEvidenceMessageVersionError):
            decode_evidence_message(
                json.dumps({**base, "schema_version": 0}).encode("utf-8")
            )
        with pytest.raises(UnsupportedEvidenceMessageVersionError):
            decode_evidence_message(
                json.dumps({**base, "schema_version": -3}).encode("utf-8")
            )
        for bad in (True, "1", 1.0):
            with pytest.raises(EvidenceMessageValidationError):
                decode_evidence_message(
                    json.dumps({**base, "schema_version": bad}).encode("utf-8")
                )

    def test_d06_version_two_unsupported_version_error(self) -> None:
        """E28C-D06: schema version 2 raises the unsupported-version error."""
        message = _message()
        wire = _decode_wire(message)
        with pytest.raises(UnsupportedEvidenceMessageVersionError) as caught:
            decode_evidence_message(
                json.dumps({**wire, "schema_version": 2}).encode("utf-8")
            )
        assert caught.value.version == 2
        assert caught.value.supported_version == EVIDENCE_MESSAGE_SCHEMA_VERSION

    def test_d07_extra_field_validation_error(self) -> None:
        """E28C-D07: an unknown top-level field fails closed."""
        message = _message()
        wire = _decode_wire(message)
        with pytest.raises(EvidenceMessageValidationError):
            decode_evidence_message(
                json.dumps({**wire, "topic": "evidence"}).encode("utf-8")
            )

    def test_d08_malformed_uuid_validation_error(self) -> None:
        """E28C-D08: a malformed UUID value fails closed."""
        message = _message()
        wire = _decode_wire(message)
        for field in (
            "message_id",
            "evidence_id",
            "datasource_execution_id",
        ):
            with pytest.raises(EvidenceMessageValidationError):
                decode_evidence_message(
                    json.dumps({**wire, field: "not-a-uuid"}).encode("utf-8")
                )

    def test_d09_malformed_timestamp_validation_error(self) -> None:
        """E28C-D09: a malformed timestamp value fails closed."""
        message = _message()
        wire = _decode_wire(message)
        for field in ("retrieved_at", "observed_at"):
            with pytest.raises(EvidenceMessageValidationError):
                decode_evidence_message(
                    json.dumps({**wire, field: "2026-06-01T12:00:00Z garbage"}).encode(
                        "utf-8"
                    )
                )

    def test_d10_wrong_evidence_id_validation_error(self) -> None:
        """E28C-D10: a valid UUID that is not the deterministic Evidence ID fails."""
        message = _message()
        wire = _decode_wire(message)
        with pytest.raises(EvidenceMessageValidationError):
            decode_evidence_message(
                json.dumps({**wire, "evidence_id": str(uuid4())}).encode("utf-8")
            )

    def test_d11_wrong_message_id_validation_error(self) -> None:
        """E28C-D11: a non-deterministic message ID fails closed."""
        message = _message()
        wire = _decode_wire(message)
        with pytest.raises(EvidenceMessageValidationError):
            decode_evidence_message(
                json.dumps({**wire, "message_id": str(uuid4())}).encode("utf-8")
            )

    def test_d12_wrong_candidate_id_validation_error(self) -> None:
        """E28C-D12: a candidate ID not derived from the message ID fails."""
        message = _message()
        wire = _decode_wire(message)
        with pytest.raises(EvidenceMessageValidationError):
            decode_evidence_message(
                json.dumps({**wire, "observation_candidate_id": str(uuid4())}).encode(
                    "utf-8"
                )
            )

    def test_d13_facts_array_validation_error(self) -> None:
        """E28C-D13: facts must be a JSON object, never an array."""
        message = _message()
        wire = _decode_wire(message)
        with pytest.raises(EvidenceMessageValidationError):
            decode_evidence_message(
                json.dumps({**wire, "facts": [{"ioc": "x"}]}).encode("utf-8")
            )

    def test_d14_raw_payload_scalar_validation_error(self) -> None:
        """E28C-D14: raw_payload must be a JSON object or null."""
        message = _message()
        wire = _decode_wire(message)
        for bad in ("scalar", 42, True):
            with pytest.raises(EvidenceMessageValidationError):
                decode_evidence_message(
                    json.dumps({**wire, "raw_payload": bad}).encode("utf-8")
                )

    def test_d15_missing_provenance_validation_error(self) -> None:
        """E28C-D15: missing provenance identity fields fail closed."""
        message = _message()
        wire = _decode_wire(message)
        for field in (
            "datasource_execution_id",
            "datasource_id",
            "source_id",
            "semantic_format",
        ):
            with pytest.raises(EvidenceMessageValidationError):
                decode_evidence_message(
                    json.dumps(
                        {key: value for key, value in wire.items() if key != field}
                    ).encode("utf-8")
                )

    def test_d16_error_text_does_not_echo_raw_payload(self) -> None:
        """E28C-D16: decode errors never echo the raw payload content."""
        message = _message()
        wire = _decode_wire(message)
        secret_fact = "supersecret-ioc-value"
        payload = json.dumps(
            {**wire, "facts": {"ioc": secret_fact}, "extra_corrupt": {"x": True}}
        ).encode("utf-8")
        with pytest.raises(EvidenceMessageValidationError) as caught:
            decode_evidence_message(payload)
        assert secret_fact not in str(caught.value)
        assert payload.decode("utf-8") not in str(caught.value)

    def test_d17_nonstandard_json_constants_decode_error(self) -> None:
        """E28C-D17: NaN/Infinity JSON constants fail as malformed JSON."""
        message = _message()
        text = encode_evidence_message(message).decode("utf-8")
        assert '"facts":{}' in text
        for bad in ("NaN", "Infinity", "-Infinity"):
            poisoned = text.replace('"facts":{}', f'"facts":{{"x":{bad}}}').encode(
                "utf-8"
            )
            with pytest.raises(EvidenceMessageDecodeError):
                decode_evidence_message(poisoned)

    def test_d18_non_string_datasource_id_rejected(self) -> None:
        """E28C-D18: a non-string datasource_id from JSON fails closed."""
        message = _message()
        wire = _decode_wire(message)
        with pytest.raises(EvidenceMessageValidationError):
            decode_evidence_message(
                json.dumps({**wire, "datasource_id": 42}).encode("utf-8")
            )


class TestContractBoundary:
    """E28C-P01..P08: contract exclusions and material-state semantics."""

    def test_p01_no_investigation_identity(self) -> None:
        """E28C-P01: no Investigation identity on the message."""
        message = _message()
        assert not hasattr(message, "investigation_id")
        assert not hasattr(message, "investigation")
        wire = _decode_wire(message)
        assert "investigation_id" not in wire
        assert "investigation" not in wire

    def test_p02_no_subject_entity_association(self) -> None:
        """E28C-P02: no subject or Entity association on the message."""
        message = _message()
        for field in ("subject", "entity_id", "entity"):
            assert not hasattr(message, field)
        wire = _decode_wire(message)
        assert "entity" not in wire
        assert "subject" not in wire

    def test_p03_no_graph_state(self) -> None:
        """E28C-P03: no derived graph state on the message."""
        message = _message()
        for field in ("relationships", "relationship_observations", "geoint"):
            assert not hasattr(message, field)
        decoded = converted_evidence_from_message(message)
        assert not hasattr(decoded, "relationships")
        assert not hasattr(decoded.observation, "relationships")

    def test_p04_no_broker_topology(self) -> None:
        """E28C-P04: no broker topic/partition/offset/group metadata."""
        message = _message()
        for field in ("topic", "partition", "offset", "group", "broker"):
            assert not hasattr(message, field)
        wire = _decode_wire(message)
        for key in ("topic", "partition", "offset", "group_id", "broker"):
            assert key not in wire

    def test_p05_no_generic_metadata_escape_hatch(self) -> None:
        """E28C-P05: no generic metadata dictionary escape hatch."""
        message = _message()
        for field in ("metadata", "headers", "config", "credentials", "extra"):
            assert not hasattr(message, field)
        with pytest.raises(EvidenceMessageValidationError):
            EvidenceMessage(**_override(message, metadata={"x": 1}))

    def test_p06_reconstructed_candidate_has_no_version(self) -> None:
        """E28C-P06: reconstruction never fabricates an Observation version."""
        decoded = converted_evidence_from_message(_message())
        assert not hasattr(decoded.observation, "version")
        assert not hasattr(_message(), "version")

    def test_p07_reconstructed_candidate_has_no_diff(self) -> None:
        """E28C-P07: reconstruction never fabricates an Observation diff."""
        decoded = converted_evidence_from_message(_message())
        assert not hasattr(decoded.observation, "diff")
        assert not hasattr(_message(), "diff")

    def test_p08_only_retrieved_at_changes_material_state_equal(self) -> None:
        """E28C-P08: a changed retrieval time keeps material state equal."""
        execution_id = uuid4()
        early = _message(
            _converted(_context(retrieved_at=_FIXED_TS)),
            context=_context(retrieved_at=_FIXED_TS),
            execution_id=execution_id,
            sequence=0,
        )
        late = _message(
            _converted(_context(retrieved_at=_LATER_TS)),
            context=_context(retrieved_at=_LATER_TS),
            execution_id=execution_id,
            sequence=0,
        )
        assert early.retrieved_at != late.retrieved_at
        assert EvidenceMaterialState.from_candidate(
            converted_evidence_from_message(early).observation
        ) == EvidenceMaterialState.from_candidate(
            converted_evidence_from_message(late).observation
        )


class TestThreatFoxVerticalSlice:
    """E28C-V01..V03: production ThreatFox conversion through the wire."""

    def _threatfox_converted(self, retrieved_at: datetime) -> ConvertedEvidence:
        """Convert the canonical synthetic AsyncRAT record once."""
        record = ThreatFoxRecord.model_validate(asyncrat_domain_record())
        context = EvidenceConversionContext(
            semantic_source=_context(retrieved_at=retrieved_at)
        )
        (converted,) = ThreatFoxToEvidenceConverter().convert(record, context)
        return converted

    def test_v01_semantic_object_wire_reconstruction(self) -> None:
        """E28C-V01: ThreatFox -> converter -> builder -> bytes -> strict decode.

        Asserts the stable Evidence identity, exact source record,
        datasource/source/format provenance, candidate state,
        deterministic IDs, and absence of Investigation/graph state — with
        no DB/network involved.
        """
        record = ThreatFoxRecord.model_validate(asyncrat_domain_record())
        context = _context()
        (converted,) = ThreatFoxToEvidenceConverter().convert(
            record, EvidenceConversionContext(semantic_source=context)
        )
        message = evidence_message_from_converted(
            converted,
            datasource_execution_id=uuid4(),
            semantic_source=context,
            sequence=0,
        )
        decoded = decode_evidence_message(encode_evidence_message(message))
        reconstructed = converted_evidence_from_message(decoded)
        assert decoded == message
        assert reconstructed == converted
        expected_evidence_id = evidence_id_for_source_record(
            SemanticFormatId.THREATFOX, SourceId.THREATFOX, record.id
        )
        assert message.evidence_id == expected_evidence_id
        assert message.source_record_id == record.id == "864201"
        assert message.datasource_id == _DEFINITION.datasource_id
        assert message.source_id is SourceId.THREATFOX
        assert message.semantic_format is SemanticFormatId.THREATFOX
        assert message.evidence_type is EvidenceType.THREAT_INTELLIGENCE
        assert message.observation_candidate_id == (
            evidence_observation_candidate_id(message.message_id)
        )
        assert message.message_id.version == 5
        assert message.observation_candidate_id.version == 5
        assert decoded.facts == converted.observation.facts
        assert decoded.observed_at == converted.observation.observed_at
        assert decoded.source_url == _ENDPOINT
        assert not hasattr(message, "investigation_id")
        assert not hasattr(reconstructed, "relationships")
        assert not hasattr(decoded, "topic")

    def test_v02_replay_same_slot_identical(self) -> None:
        """E28C-V02: replaying one producer slot is fully deterministic."""
        converted = self._threatfox_converted(_FIXED_TS)
        context = _context(retrieved_at=_FIXED_TS)
        execution_id = uuid4()
        first = evidence_message_from_converted(
            converted,
            datasource_execution_id=execution_id,
            semantic_source=context,
            sequence=0,
        )
        payloads = [encode_evidence_message(first) for _ in range(3)]
        assert all(payload == payloads[0] for payload in payloads)
        decoded_messages = [decode_evidence_message(payload) for payload in payloads]
        assert all(decoded == first for decoded in decoded_messages)
        assert all(
            converted_evidence_from_message(decoded) == converted
            for decoded in decoded_messages
        )

    def test_v03_later_unchanged_acquisition(self) -> None:
        """E28C-V03: later unchanged acquisition keeps Evidence identity.

        A new datasource execution with a later retrieval time yields the
        same Evidence ID but distinct message/candidate identities, while
        the material state stays equal (no DB behavior tested here).
        """
        first = self._threatfox_converted(_FIXED_TS)
        later = self._threatfox_converted(_LATER_TS)
        first_message = evidence_message_from_converted(
            first,
            datasource_execution_id=uuid4(),
            semantic_source=_context(retrieved_at=_FIXED_TS),
            sequence=0,
        )
        later_message = evidence_message_from_converted(
            later,
            datasource_execution_id=uuid4(),
            semantic_source=_context(retrieved_at=_LATER_TS),
            sequence=0,
        )
        assert first_message.evidence_id == later_message.evidence_id
        assert first_message.message_id != later_message.message_id
        assert (
            first_message.observation_candidate_id
            != later_message.observation_candidate_id
        )
        assert first_message.retrieved_at != later_message.retrieved_at
        assert EvidenceMaterialState.from_candidate(
            converted_evidence_from_message(first_message).observation
        ) == EvidenceMaterialState.from_candidate(
            converted_evidence_from_message(later_message).observation
        )


class TestPr28F1CanonicalOracle:
    """PR 28F-1 F1-E oracle: canonical V1 bytes stay pinned to the stdlib codec.

    The PR 28F-1 encoder probe proved ``orjson`` emits identical canonical
    bytes for every corpus case except finite float scientific notation
    (stdlib ``1.2e-07`` vs ``orjson`` ``1.2e-7``) and parses integers
    beyond the signed-64/unsigned-64 range as ``float`` instead of exact
    ``int``. The V1 canonical byte contract and decode-equal round trip are
    durable, so the EvidenceMessage codec deliberately retains Python's
    standard-library ``json`` in both directions; these goldens freeze that
    contract so a future engine change cannot silently rewrite the bytes.
    """

    _FIXED_EXECUTION = UUID("11111111-2222-3333-4444-555555555555")

    def test_oracle01_minimal_message_golden_bytes(self) -> None:
        """F1-E01/E07/E09: minimal message golden canonical bytes."""
        message = _message(
            _converted(
                _context(),
                facts={"matches": [{"ioc": "malicious-domain.test"}]},
            ),
            context=_context(),
            execution_id=self._FIXED_EXECUTION,
            sequence=0,
        )
        expected = (
            b'{"datasource_execution_id":"11111111-2222-3333-4444-555555555555",'
            b'"datasource_id":"threatfox-live",'
            b'"evidence_id":"af3ab0fa-c917-5a44-ab42-9f2720c8d755",'
            b'"evidence_type":"urn:ati:evidence:threat_intelligence",'
            b'"facts":{"matches":[{"ioc":"malicious-domain.test"}]},'
            b'"message_id":"bef63adc-e160-51cd-b7e1-ca41f2e6d316",'
            b'"observation_candidate_id":"bbe96988-2cc2-5a6e-8ae7-1cde2a55985e",'
            b'"observed_at":null,"raw_payload":null,'
            b'"retrieved_at":"2026-06-01T12:00:00.000000Z",'
            b'"schema_version":1,'
            b'"semantic_format":"urn:ati:datasource:semanticformat:threatfox",'
            b'"sequence":0,"source_id":"urn:ati:source:threatfox",'
            b'"source_record_id":"record-1",'
            b'"source_url":"https://threatfox-api.abuse.ch/api/v1/"}'
        )
        assert encode_evidence_message(message) == expected
        assert decode_evidence_message(expected) == message

    def test_oracle02_float_scientific_notation_pinned(self) -> None:
        """F1-E05: canonical float notation is stdlib ``1.2e-07``, never ``1.2e-7``.

        This is the exact representation ``orjson`` cannot reproduce, and
        the reason the EvidenceMessage encoder retains stdlib JSON.
        """
        message = _message(
            _converted(_context(), facts={"score": 1.2e-07, "n": 3}),
            context=_context(),
            execution_id=self._FIXED_EXECUTION,
            sequence=1,
        )
        payload = encode_evidence_message(message)
        assert b'"score":1.2e-07' in payload
        assert b"1.2e-7" not in payload
        assert decode_evidence_message(payload) == message

    def test_oracle03_unicode_and_nested_containers_canonical(self) -> None:
        """F1-E02/E03/E04/E06: unsorted keys, Unicode, escapes, nesting."""
        text = '威胁情报 — π ≈ 3.14159 "quoted" \\ path'
        message = _message(
            _converted(
                _context(),
                facts={
                    "z": [{"empty": [], "obj": {}}],
                    "a": {"label": text, "flag": True, "nothing": None},
                },
            ),
            context=_context(),
            execution_id=self._FIXED_EXECUTION,
            sequence=2,
        )
        payload = encode_evidence_message(message)
        assert decode_evidence_message(payload) == message
        # Non-ASCII text is emitted as UTF-8 (ensure_ascii=False), while
        # quote/backslash characters are JSON-escaped (F1-E03/E04).
        assert "威胁情报 — π ≈ 3.14159".encode("utf-8") in payload
        assert b'\\"quoted\\"' in payload  # quotes are JSON-escaped
        # Canonical sorted top-level order is frozen by the golden prefix.
        assert payload.startswith(
            b'{"datasource_execution_id":"11111111-2222-3333-4444-555555555555"'
        )
        # Repeated encoding stays deterministic (F1-E10).
        assert encode_evidence_message(message) == payload
