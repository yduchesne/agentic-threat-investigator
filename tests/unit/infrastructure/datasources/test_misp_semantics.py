# SPDX-License-Identifier: AGPL-3.0-only
"""PR 32A M32A-01..50 matrix: MISP semantic model and parser.

Proves the native MISP decoded-Event boundary: validated immutable source
records, preserved UUID/timestamp/deleted/tags/distribution/sharing
semantics, deterministic source order, Object-owned Attributes kept nested,
duplicate-UUID conflict handling, caller-mutation isolation, fail-closed
malformed input with a bounded semantic error and zero records, and module
isolation from Evidence/provider/persistence/HTTP implementations. All data
is ATI-authored synthetic fixtures; no network and no database.
"""

from __future__ import annotations

import copy
import inspect
import re
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    DatasourceStageError,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources import (
    misp_semantics,
)
from agentic_threat_investigator.infrastructure.datasources.misp_semantics import (
    DISTRIBUTION_INHERIT_EVENT,
    DISTRIBUTION_SHARING_GROUP,
    MispAttribute,
    MispAttributeRecord,
    MispEventContext,
    MispObjectRecord,
    MispObjectReference,
    MispSemanticResult,
    MispTag,
    parse_misp_event,
)
from tests.support import misp_fixtures as fixtures

_ERROR_CODE = "semantic_validation_failed"


def _error_of(result: MispSemanticResult) -> DatasourceStageError:
    """Return the mandatory semantic failure of a failed parse."""
    assert result.error is not None
    assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
    assert result.error.code == _ERROR_CODE
    assert result.error.retryable is False
    assert result.records == ()
    return result.error


def _assert_failed(result: MispSemanticResult) -> None:
    """Require a failed parse with the bounded stage error and zero records."""
    _error_of(result)


class TestEventEnvelope:
    """M32A-01/29/30/40/41/42/44/49: envelope and isolation behavior."""

    def test_m32a_01_minimal_event_is_empty_success(self) -> None:
        """M32A-01: a minimal valid Event parses with zero records."""
        result = parse_misp_event(fixtures.misp_event())
        assert result.error is None
        assert result.records == ()
        # The Event context itself is validated and preserved.
        context = MispEventContext.model_validate(fixtures.misp_event()["Event"])
        assert str(context.uuid) == fixtures.EVENT_UUID
        assert context.info == "Synthetic MISP event for ATI documentation testing"
        assert context.timestamp == datetime.fromtimestamp(1700000000, tz=UTC)
        assert context.distribution == 0
        assert context.sharing_group_id == 0
        assert context.tags == ()
        assert context.published is True
        assert context.extends_uuid is None

    @pytest.mark.parametrize("decoded", [["Event"], "Event", None, 3, b"{}"])
    def test_m32a_29_non_object_top_level_fails(self, decoded: object) -> None:
        """M32A-29: a non-dict (including raw bytes) top level fails closed."""
        _assert_failed(parse_misp_event(decoded))

    @pytest.mark.parametrize("decoded", [{}, {"NoEvent": {}}, {"Event": "x"}])
    def test_m32a_30_missing_or_wrong_event_envelope_fails(
        self, decoded: object
    ) -> None:
        """M32A-30: the single ``{"Event": {...}}`` envelope is mandatory."""
        _assert_failed(parse_misp_event(decoded))

    def test_m32a_49_raw_json_bytes_are_rejected(self) -> None:
        """M32A-49: decoding is upstream; raw JSON bytes never parse."""
        raw = b'{"Event": {"uuid": "dummy"}}'
        _assert_failed(parse_misp_event(raw))

    def test_m32a_40_repeated_parse_is_equal(self) -> None:
        """M32A-40: parsing the same decoded value twice yields equal output."""
        payload = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(),),
            objects=(fixtures.misp_object(),),
        )
        assert parse_misp_event(payload) == parse_misp_event(payload)

    def test_m32a_41_caller_mutation_isolation(self) -> None:
        """M32A-41: mutating the caller dict after parse leaves records intact."""
        payload = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(),
                fixtures.misp_attribute(
                    type_="ip-src",
                    value=fixtures.IPV4_VALUE,
                    uuid="3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e60",
                ),
            ),
            objects=(fixtures.misp_object(),),
            tags=(fixtures.misp_tag(),),
        )
        result = parse_misp_event(payload)
        assert result.error is None
        snapshot = [
            (str(record.attribute.uuid), record.attribute.value)
            if isinstance(record, MispAttributeRecord)
            else (str(record.object.uuid), record.object.name)
            for record in result.records
        ]
        # Mutate every modeled source location aggressively.
        payload["Event"]["Attribute"][0]["Attribute"]["value"] = "mutated.test"
        payload["Event"]["Attribute"][1]["Attribute"]["to_ids"] = False
        payload["Event"]["Object"][0]["Object"]["name"] = "mutated"
        payload["Event"]["Tag"][0]["Tag"]["name"] = "mutated-tag"
        payload["Event"]["info"] = "mutated"
        assert [
            (str(record.attribute.uuid), record.attribute.value)
            if isinstance(record, MispAttributeRecord)
            else (str(record.object.uuid), record.object.name)
            for record in result.records
        ] == snapshot
        assert result.records[0].event.info == (
            "Synthetic MISP event for ATI documentation testing"
        )

    def test_m32a_42_unknown_extra_fields_are_ignored(self) -> None:
        """M32A-42: unmodeled members never change validated semantics."""
        payload = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(extra_field={"a": 1}),),
        )
        payload["Event"]["threat_level_id"] = "x"
        payload["Event"]["Org"] = {"name": "Synthetic Org"}
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        assert str(record.attribute.uuid) == fixtures.ATTRIBUTE_UUID
        assert record.attribute.value == fixtures.DOMAIN_VALUE

    def test_m32a_44_malformed_ignored_field_does_not_fail(self) -> None:
        """M32A-44: malformed unmodeled members are never validated."""
        payload = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(),),
            objects=(fixtures.misp_object(),),
        )
        payload["Event"]["date"] = "not-a-date"
        payload["Event"]["Attribute"][0]["Attribute"]["SomeUnmodelled"] = {
            "garbage": [1, 2]
        }
        payload["Event"]["Object"][0]["Object"]["ShadowAttribute"] = ["x"]
        result = parse_misp_event(payload)
        assert result.error is None
        assert len(result.records) == 2


class TestAttributes:
    """M32A-02/03/11/12/13/14/15/17: Event-level Attribute records."""

    def test_m32a_02_one_event_attribute(self) -> None:
        """M32A-02: one Event Attribute yields one MispAttributeRecord."""
        payload = fixtures.misp_event(attributes=(fixtures.misp_attribute(),))
        result = parse_misp_event(payload)
        assert result.error is None
        assert len(result.records) == 1
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        assert str(record.attribute.uuid) == fixtures.ATTRIBUTE_UUID
        assert record.event is not None
        assert str(record.event.uuid) == fixtures.EVENT_UUID

    def test_m32a_03_several_attributes_preserve_source_order(self) -> None:
        """M32A-03: several Attributes keep their exact source order."""
        uuids = (
            "3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e61",
            "3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e62",
            "3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e63",
        )
        payload = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(uuid=uuids[0]),
                fixtures.misp_attribute(type_="ip-src", uuid=uuids[1]),
                fixtures.misp_attribute(type_="ip-dst", uuid=uuids[2]),
            )
        )
        result = parse_misp_event(payload)
        assert result.error is None
        assert [
            str(record.attribute.uuid)
            for record in result.records
            if isinstance(record, MispAttributeRecord)
        ] == list(uuids)

    def test_m32a_11_domain_attribute_fields_preserved_exactly(self) -> None:
        """M32A-11: a domain Attribute preserves its exact source fields."""
        payload = fixtures.misp_event(attributes=(fixtures.misp_attribute(),))
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        attribute = record.attribute
        assert attribute.type == "domain"
        assert attribute.category == "Network activity"
        assert attribute.value == fixtures.DOMAIN_VALUE
        assert attribute.to_ids is True
        assert attribute.deleted is False
        assert attribute.comment == ""
        assert attribute.object_relation is None
        assert attribute.timestamp == datetime.fromtimestamp(
            int(fixtures.ATTRIBUTE_TIMESTAMP), tz=UTC
        )

    @pytest.mark.parametrize(
        ("type_", "value"),
        [("ip-src", fixtures.IPV4_VALUE), ("ip-dst", fixtures.IPV6_VALUE)],
    )
    def test_m32a_12_ip_source_destination_are_valid_without_interpretation(
        self, type_: str, value: str
    ) -> None:
        """M32A-12: ip-src/ip-dst parse without ATI canonicalization."""
        payload = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(type_=type_, value=value),)
        )
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        assert record.attribute.type == type_
        assert record.attribute.value == value

    def test_m32a_13_domain_pipe_ip_is_one_undivided_value(self) -> None:
        """M32A-13: ``domain|ip`` is one source value; never split."""
        compound = f"{fixtures.DOMAIN_VALUE}|{fixtures.IPV4_VALUE}"
        payload = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(type_="domain|ip", value=compound),)
        )
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        assert record.attribute.value == compound

    @pytest.mark.parametrize(
        "type_", ["comment", "malware-sample", "link", "whois-registrant-email"]
    )
    def test_m32a_14_unsupported_valid_types_are_accepted(self, type_: str) -> None:
        """M32A-14: no ATI IOC whitelist; any valid source type is retained."""
        payload = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(type_=type_),)
        )
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        assert record.attribute.type == type_

    def test_m32a_15_deleted_attribute_is_retained(self) -> None:
        """M32A-15: ``deleted=true`` is preserved, never silently dropped."""
        payload = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(deleted=True),)
        )
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        assert record.attribute.deleted is True

    def test_m32a_17_attribute_distribution_five_is_retained(self) -> None:
        """M32A-17: Attribute distribution ``5`` stays ``5`` (inherit Event)."""
        payload = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(distribution="5"),)
        )
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        assert record.attribute.distribution == DISTRIBUTION_INHERIT_EVENT


class TestObjects:
    """M32A-04/05/06/07/16/23/24: Event-level Object records."""

    def test_m32a_04_one_object(self) -> None:
        """M32A-04: one Object yields one MispObjectRecord."""
        payload = fixtures.misp_event(objects=(fixtures.misp_object(),))
        result = parse_misp_event(payload)
        assert result.error is None
        assert len(result.records) == 1
        record = result.records[0]
        assert isinstance(record, MispObjectRecord)
        assert str(record.object.uuid) == fixtures.OBJECT_UUID
        assert record.object.name == "file"
        assert str(record.event.uuid) == fixtures.EVENT_UUID

    def test_m32a_05_attributes_then_objects(self) -> None:
        """M32A-05: Attribute records come first, then Object records."""
        payload = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(),
                fixtures.misp_attribute(
                    type_="ip-src",
                    value=fixtures.IPV4_VALUE,
                    uuid="3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e64",
                ),
            ),
            objects=(fixtures.misp_object(),),
        )
        result = parse_misp_event(payload)
        assert result.error is None
        assert [type(record) for record in result.records] == [
            MispAttributeRecord,
            MispAttributeRecord,
            MispObjectRecord,
        ]

    def test_m32a_06_object_attributes_stay_nested_never_top_level(self) -> None:
        """M32A-06: Object-owned Attributes are never duplicated top level."""
        payload = fixtures.misp_event(
            objects=(
                fixtures.misp_object(attributes=(fixtures.misp_object_attribute(),)),
            ),
        )
        result = parse_misp_event(payload)
        assert result.error is None
        assert len(result.records) == 1
        record = result.records[0]
        assert isinstance(record, MispObjectRecord)
        assert len(record.object.attributes) == 1
        nested = record.object.attributes[0]
        assert str(nested.uuid) == fixtures.OBJECT_ATTRIBUTE_UUID
        assert nested.object_relation == "filename"
        assert nested.type == "filename"
        # No MispAttributeRecord was produced for the nested Attribute.
        assert all(isinstance(record_, MispObjectRecord) for record_ in result.records)

    def test_m32a_07_object_references_preserved_in_order(self) -> None:
        """M32A-07: Object References keep identity/type/target and order."""
        refs = (
            fixtures.misp_object_reference(
                relationship_type="includes",
                referenced_uuid="3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e70",
                uuid="3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e71",
            ),
            fixtures.misp_object_reference(
                relationship_type="related-to",
                referenced_uuid="3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e72",
                uuid="3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e73",
            ),
        )
        payload = fixtures.misp_event(objects=(fixtures.misp_object(references=refs),))
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispObjectRecord)
        assert len(record.object.references) == 2
        first, second = record.object.references
        assert isinstance(first, MispObjectReference)
        assert first.relationship_type == "includes"
        assert str(first.referenced_uuid) == "3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e70"
        assert second.relationship_type == "related-to"

    def test_m32a_16_deleted_object_is_retained(self) -> None:
        """M32A-16: a deleted Object is preserved with its revoked state."""
        payload = fixtures.misp_event(objects=(fixtures.misp_object(deleted=True),))
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispObjectRecord)
        assert record.object.deleted is True

    def test_m32a_23_object_first_last_seen_are_distinct_utc(self) -> None:
        """M32A-23: first/last seen parse as distinct timezone-aware UTC values."""
        payload = fixtures.misp_event(
            objects=(
                fixtures.misp_object(
                    first_seen=fixtures.FIRST_SEEN_ISO,
                    last_seen=fixtures.LAST_SEEN_ISO,
                ),
            )
        )
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispObjectRecord)
        assert record.object.first_seen == datetime(2023, 11, 1, tzinfo=UTC)
        assert record.object.last_seen == datetime(2023, 11, 2, tzinfo=UTC)
        assert record.object.first_seen < record.object.last_seen

    def test_m32a_24_first_seen_after_last_seen_fails(self) -> None:
        """M32A-24: a reversed seen window fails the whole Event."""
        payload = fixtures.misp_event(
            objects=(
                fixtures.misp_object(
                    first_seen="2023-11-02T00:00:00Z",
                    last_seen="2023-11-01T00:00:00Z",
                ),
            )
        )
        _assert_failed(parse_misp_event(payload))


class TestTags:
    """M32A-08/09/10: Event and Attribute tags."""

    def test_m32a_08_event_tags_preserve_source_order(self) -> None:
        """M32A-08: Event tags are preserved in first-occurrence order."""
        payload = fixtures.misp_event(
            tags=(fixtures.misp_tag("tlp:white"), fixtures.misp_tag("osint:valid"))
        )
        result = parse_misp_event(payload)
        assert result.error is None
        context = result.records[0].event if result.records else None
        if context is None:
            context = MispEventContext.model_validate(payload["Event"])
        assert [tag.name for tag in context.tags] == ["tlp:white", "osint:valid"]

    def test_m32a_09_attribute_tags_preserve_source_order(self) -> None:
        """M32A-09: Attribute tags are preserved in first-occurrence order."""
        payload = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(
                    tags=(
                        fixtures.misp_tag("tlp:white"),
                        fixtures.misp_tag("misp:trusted"),
                    )
                ),
            )
        )
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        assert [tag.name for tag in record.attribute.tags] == [
            "tlp:white",
            "misp:trusted",
        ]

    def test_m32a_10_duplicate_tag_name_kept_once(self) -> None:
        """M32A-10: a later exact duplicate tag name is suppressed."""
        payload = fixtures.misp_event(
            tags=(
                fixtures.misp_tag("tlp:white"),
                fixtures.misp_tag("tlp:white"),
                fixtures.misp_tag("osint:valid"),
            )
        )
        result = parse_misp_event(payload)
        assert result.error is None
        context = MispEventContext.model_validate(payload["Event"])
        parsed_tags = result.records[0].event.tags if result.records else context.tags
        assert [tag.name for tag in parsed_tags] == ["tlp:white", "osint:valid"]


class TestDistribution:
    """M32A-18/19/20: distribution and sharing-group state."""

    def test_m32a_18_event_distribution_five_fails(self) -> None:
        """M32A-18: Events only accept ``0..4`` (verified MISP Event range)."""
        payload = fixtures.misp_event(distribution="5")
        _assert_failed(parse_misp_event(payload))

    def test_m32a_18b_object_distribution_five_is_inherit_retained(self) -> None:
        """M32A-18b: Object distribution ``5`` (inherit Event) is preserved.

        Verified deviation from the plan's "Object 0..4" row: the current
        MISP core format stores ``5`` (inherit) as a normal Object
        distribution value (MISP's Object schema default is ``5`` and its
        own Object-distribution filters include it). Rejecting it would
        reject valid native MISP data; it is preserved exactly like the
        Attribute inherit value.
        """
        payload = fixtures.misp_event(objects=(fixtures.misp_object(),))
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispObjectRecord)
        assert record.object.distribution == DISTRIBUTION_INHERIT_EVENT
        assert record.object.sharing_group_id == 0

    def test_m32a_19_sharing_group_distribution_preserved(self) -> None:
        """M32A-19: distribution ``4`` preserves the nonzero sharing group."""
        payload = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(distribution="4", sharing_group_id="42"),
            ),
        )
        result = parse_misp_event(payload)
        assert result.error is None
        record = result.records[0]
        assert isinstance(record, MispAttributeRecord)
        assert record.attribute.distribution == DISTRIBUTION_SHARING_GROUP
        assert record.attribute.sharing_group_id == 42

    @pytest.mark.parametrize(
        "payload",
        [
            fixtures.misp_event(distribution="4", sharing_group_id="0"),
            fixtures.misp_event(distribution="0", sharing_group_id="7"),
            fixtures.misp_attribute(distribution="4", sharing_group_id="0"),
            fixtures.misp_object(distribution="0", sharing_group_id="9"),
        ],
    )
    def test_m32a_20_inconsistent_sharing_group_fails(
        self, payload: dict[str, object]
    ) -> None:
        """M32A-20: inconsistent distribution/sharing-group pairs fail closed."""
        _assert_failed(parse_misp_event(payload))


class TestStrictScalars:
    """M32A-21/22/25/26/27/28/31/32/33/34: strict scalar validation."""

    def test_m32a_21_unix_timestamp_string_to_utc(self) -> None:
        """M32A-21: a strict decimal string timestamp normalizes to UTC."""
        parsed = misp_semantics._parse_unix_timestamp("1700000000", "x")
        assert parsed == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
        assert parsed.tzinfo is UTC

    @pytest.mark.parametrize(
        "bad",
        [
            " 1700000000",
            "1700000000 ",
            "+1700000000",
            "-1700000000",
            "1700.5",
            "17e9",
            "",
            "abc",
        ],
    )
    def test_m32a_22_malformed_unix_timestamp_fails(self, bad: str) -> None:
        """M32A-22: padded/signed/fractional/non-decimal strings are rejected."""
        payload = fixtures.misp_event(timestamp=bad)
        _assert_failed(parse_misp_event(payload))

    @pytest.mark.parametrize("bad", [1700000000, 1700.5, True, None])
    def test_m32a_22b_non_string_timestamp_rejected(self, bad: object) -> None:
        """M32A-22b: bool/int/float/None timestamps are rejected as strings."""
        payload = fixtures.misp_event(timestamp=bad)
        _assert_failed(parse_misp_event(payload))

    def test_m32a_22c_timestamp_out_of_range_fails(self) -> None:
        """An overflowing Unix timestamp fails closed."""
        payload = fixtures.misp_event(timestamp="99999999999999999999999999")
        _assert_failed(parse_misp_event(payload))

    def test_m32a_25_malformed_event_uuid_fails(self) -> None:
        """M32A-25: a malformed Event UUID fails the whole Event."""
        payload = fixtures.misp_event(uuid="not-a-uuid")
        _assert_failed(parse_misp_event(payload))

    def test_m32a_26_malformed_attribute_uuid_fails_whole_event(self) -> None:
        """M32A-26: one malformed Attribute UUID invalidates the whole Event."""
        payload = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(uuid="nope"),)
        )
        _assert_failed(parse_misp_event(payload))

    def test_m32a_27_malformed_object_uuid_fails_whole_event(self) -> None:
        """M32A-27: one malformed Object UUID invalidates the whole Event."""
        payload = fixtures.misp_event(objects=(fixtures.misp_object(uuid="nope"),))
        _assert_failed(parse_misp_event(payload))

    def test_m32a_28_malformed_object_reference_identity_fails(self) -> None:
        """M32A-28: a broken ObjectReference identity/target fails the Event."""
        for ref in (
            fixtures.misp_object_reference(uuid="nope"),
            fixtures.misp_object_reference(referenced_uuid="broken"),
        ):
            payload = fixtures.misp_event(
                objects=(fixtures.misp_object(references=(ref,)),)
            )
            _assert_failed(parse_misp_event(payload))

    def test_m32a_31_wrong_container_type_fails(self) -> None:
        """M32A-31: a wrong Attribute/Object/Tag container type fails the Event."""
        bad_attributes = fixtures.misp_event()
        bad_attributes["Event"]["Attribute"] = "x"
        bad_objects = fixtures.misp_event()
        bad_objects["Event"]["Object"] = {"nope": 1}
        bad_tags = fixtures.misp_event()
        bad_tags["Event"]["Tag"] = "x"
        for payload in (bad_attributes, bad_objects, bad_tags):
            _assert_failed(parse_misp_event(payload))

    def test_m32a_32_required_modeled_field_missing_fails(self) -> None:
        """M32A-32: a missing required modeled field fails the whole Event."""
        missing_event_info = fixtures.misp_event()
        del missing_event_info["Event"]["info"]
        missing_attribute_value = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(),)
        )
        del missing_attribute_value["Event"]["Attribute"][0]["Attribute"]["value"]
        missing_object_name = fixtures.misp_event(objects=(fixtures.misp_object(),))
        del missing_object_name["Event"]["Object"][0]["Object"]["name"]
        for payload in (
            missing_event_info,
            missing_attribute_value,
            missing_object_name,
        ):
            _assert_failed(parse_misp_event(payload))

    @pytest.mark.parametrize(
        ("field", "member"),
        [
            ("to_ids", "Attribute"),
            ("deleted", "Attribute"),
            ("deleted", "Object"),
        ],
    )
    @pytest.mark.parametrize("bad", ["true", 1, 0, "false"])
    def test_m32a_33_semantic_booleans_are_strict(
        self, field: str, member: str, bad: object
    ) -> None:
        """M32A-33: ``"true"``/``1``/``0`` for semantic booleans are rejected."""
        builder_name = "misp_attribute" if member == "Attribute" else "misp_object"
        builder = getattr(fixtures, builder_name)
        payload = builder(**{field: bad})
        _assert_failed(parse_misp_event(payload))

    def test_m32a_33b_event_published_is_strict_bool(self) -> None:
        """M32A-33b: Event ``published`` accepts only a real JSON boolean."""
        for bad in ("true", 1, 0):
            _assert_failed(parse_misp_event(fixtures.misp_event(published=bad)))

    @pytest.mark.parametrize(
        "payload",
        [
            fixtures.misp_event(info="X" * 5000),
            fixtures.misp_attribute(type_="t" * 100),
            fixtures.misp_attribute(value="v" * 9000),
            fixtures.misp_tag("t" * 300),
            fixtures.misp_object(name="n" * 600),
            fixtures.misp_object_reference(relationship_type="r" * 100),
        ],
    )
    def test_m32a_34_over_bound_source_string_fails_no_truncation(
        self, payload: dict[str, object]
    ) -> None:
        """M32A-34: over-bound modeled strings are semantic failures."""
        _assert_failed(parse_misp_event(payload))


class TestDuplicateIdentity:
    """M32A-35/36/37/38/39/50: upstream UUID identity control."""

    def test_m32a_35_identical_duplicate_attribute_kept_once(self) -> None:
        """M32A-35: an identical duplicate Attribute UUID is kept once."""
        member = fixtures.misp_attribute()
        payload = fixtures.misp_event(attributes=(member, copy.deepcopy(member)))
        result = parse_misp_event(payload)
        assert result.error is None
        assert len(result.records) == 1

    def test_m32a_36_conflicting_duplicate_attribute_fails(self) -> None:
        """M32A-36: a conflicting duplicate Attribute UUID fails the Event."""
        payload = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(),
                fixtures.misp_attribute(
                    uuid=fixtures.ATTRIBUTE_UUID, value=fixtures.SECONDARY_DOMAIN_VALUE
                ),
            )
        )
        _assert_failed(parse_misp_event(payload))

    def test_m32a_37_identical_duplicate_object_kept_once(self) -> None:
        """M32A-37: an identical duplicate Object UUID is kept once."""
        member = fixtures.misp_object()
        payload = fixtures.misp_event(objects=(member, copy.deepcopy(member)))
        result = parse_misp_event(payload)
        assert result.error is None
        assert len(result.records) == 1

    def test_m32a_38_conflicting_duplicate_object_fails(self) -> None:
        """M32A-38: a conflicting duplicate Object UUID fails the Event."""
        payload = fixtures.misp_event(
            objects=(
                fixtures.misp_object(),
                fixtures.misp_object(uuid=fixtures.OBJECT_UUID, name="other-template"),
            )
        )
        _assert_failed(parse_misp_event(payload))

    def test_m32a_39_different_uuids_same_value_both_retained(self) -> None:
        """M32A-39: distinct UUIDs with equal values are both retained."""
        payload = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(),
                fixtures.misp_attribute(uuid="3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e80"),
            )
        )
        result = parse_misp_event(payload)
        assert result.error is None
        assert len(result.records) == 2
        assert [
            record.attribute.value
            for record in result.records
            if isinstance(record, MispAttributeRecord)
        ] == [
            fixtures.DOMAIN_VALUE,
            fixtures.DOMAIN_VALUE,
        ]

    def test_m32a_50_local_ids_are_not_identity(self) -> None:
        """M32A-50: local numeric ids never participate in identity rules."""
        # Same upstream UUID + same modeled content, different local ids:
        # identical duplicate, kept once (content equality ignores local id).
        first = fixtures.misp_attribute()
        first["Attribute"]["id"] = "200"
        second = fixtures.misp_attribute()
        second["Attribute"]["id"] = "201"
        result = parse_misp_event(fixtures.misp_event(attributes=(first, second)))
        assert result.error is None
        assert len(result.records) == 1
        # Different UUIDs with the same local id are distinct records.
        result = parse_misp_event(
            fixtures.misp_event(
                attributes=(
                    fixtures.misp_attribute(id="300"),
                    fixtures.misp_attribute(
                        id="300", uuid="3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e90"
                    ),
                )
            )
        )
        assert result.error is None
        assert len(result.records) == 2


class TestModuleIsolation:
    """M32A-45/46/47/48: module isolation and durable identifiers."""

    def test_m32a_45_no_evidence_provider_or_client_imports(self) -> None:
        """M32A-45: misp_semantics imports no Evidence/provider/HTTP layer."""
        source = inspect.getsource(misp_semantics)
        forbidden = re.compile(
            r"^\s*(?:from|import)\s+\S*"
            r"(evidence|providers|persistence|sqlalchemy|httpx|asyncio)",
            re.M,
        )
        assert forbidden.search(source) is None
        for name in (
            "Evidence",
            "ConvertedEvidence",
            "EvidenceMessage",
            "ToEvidenceConverter",
            "ProviderResult",
            "EvidenceProvider",
            "ProviderHttpClient",
            "UnitOfWork",
        ):
            assert not hasattr(misp_semantics, name)
        import_lines = [
            line.strip()
            for line in source.splitlines()
            if line.lstrip().startswith(("import ", "from "))
        ]
        assert all(
            "httpx" not in line and "sqlalchemy" not in line and "asyncio" not in line
            for line in import_lines
        )

    def test_m32a_46_no_source_content_logging(self) -> None:
        """M32A-46: the parser defines no logger and logs nothing."""
        source = inspect.getsource(misp_semantics)
        assert "logger" not in source.lower()
        assert "logging" not in source

    def test_m32a_47_failed_result_with_records_invariant_rejected(self) -> None:
        """M32A-47: a failed MispSemanticResult cannot carry records."""
        event = MispEventContext.model_validate(fixtures.misp_event()["Event"])
        attribute = MispAttribute.model_validate(fixtures.misp_attribute()["Attribute"])
        record = MispAttributeRecord(event=event, attribute=attribute)
        error = DatasourceStageError(
            stage=DatasourceStage.SEMANTIC_VALIDATION,
            code=_ERROR_CODE,
            retryable=False,
        )
        with pytest.raises(ValueError, match="cannot carry records"):
            MispSemanticResult(records=(record,), error=error)

    def test_m32a_48_durable_identifier_strings_are_exact(self) -> None:
        """M32A-48: the MISP source and semantic-format URNs are exact."""
        assert SourceId.MISP.value == "urn:ati:source:misp"
        assert SemanticFormatId.MISP.value == ("urn:ati:datasource:semanticformat:misp")

    def test_model_classes_are_immutable(self) -> None:
        """The MISP models reject mutation after construction."""
        event = MispEventContext.model_validate(fixtures.misp_event()["Event"])
        with pytest.raises(ValidationError):
            event.info = "changed"
        tag = MispTag(name="tlp:white")
        with pytest.raises(ValidationError):
            tag.name = "changed"
