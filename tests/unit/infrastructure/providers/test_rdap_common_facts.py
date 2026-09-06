# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""RDAP common-fact normalization contract tests.

Object class, status, handle, entity, and event facts must have one stable
normalized shape before they can become evidence: canonical lowercase object
class, trimmed/lowercased/deduplicated statuses with blanks omitted,
trimmed handles with unusable references omitted, events that always carry
a UTC date derived from a valid RFC 3339 timestamp, and ``observed_at``
reflecting only valid ``last changed`` entries.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from agentic_threat_investigator.domain.entities import Entity, EntityType

from .rdap_contract_helpers import (
    _assert_invalid,
    _domain_result,
    _iana_then_authority_handler,
    _investigate,
)
from .rdap_payloads import _bootstrap_registry
from .test_rdap_strict_models import _autnum_payload, _domain_payload, _network_payload


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapHandleNormalization:
    """Top-level and related-entity handles follow one normalization policy."""

    async def test_top_level_handle_surrounding_whitespace_trimmed(self) -> None:
        """A handle with surrounding whitespace is trimmed in facts and provenance."""
        result = await _domain_result(_domain_payload(handle="  DOM-1  "))
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["handle"] == "DOM-1"
        assert result.evidence[0].source_record_id == "DOM-1"

    async def test_whitespace_only_top_level_handle_omitted(self) -> None:
        """A whitespace-only handle emits no fact and falls back to identity."""
        result = await _domain_result(_domain_payload(handle="   "))
        assert len(result.evidence) == 1
        assert "handle" not in result.evidence[0].facts
        assert result.evidence[0].source_record_id == "example.com"

    async def test_blank_handle_fallback_ids_all_object_classes(self) -> None:
        """Blank handles fall back to the documented identity for each class."""
        for payload, bootstrap_payload, entity, expected in (
            (
                _domain_payload(handle=""),
                None,
                Entity(type=EntityType.DOMAIN, value="example.com"),
                "example.com",
            ),
            (
                _network_payload(handle=""),
                _bootstrap_registry([[["198.51.100.0/24"], ["https://rdap.test/"]]]),
                Entity(type=EntityType.IP_ADDRESS, value="198.51.100.1"),
                "198.51.100.0-198.51.100.255",
            ),
            (
                _autnum_payload(handle=""),
                _bootstrap_registry([[["500-600"], ["https://rdap.test/"]]]),
                Entity(type=EntityType.ASN, value="AS500"),
                "AS500-600",
            ),
        ):
            result = await _investigate(
                _iana_then_authority_handler(
                    payload, bootstrap_payload=bootstrap_payload
                ),
                entity,
            )
            assert len(result.evidence) == 1
            assert "handle" not in result.evidence[0].facts
            assert result.evidence[0].source_record_id == expected

    async def test_related_entity_handle_surrounding_whitespace_trimmed(self) -> None:
        """Related-entity handles are trimmed in the compact fact shape."""
        payload = _domain_payload(
            entities=[{"handle": "  REG-1  ", "roles": ["registrant"]}]
        )
        result = await _domain_result(payload)
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["entities"] == (
            {"handle": "REG-1", "roles": ("registrant",)},
        )

    async def test_related_entities_with_absent_or_blank_handles_omitted(self) -> None:
        """Unusable entity references are omitted without failing the lookup."""
        payload = _domain_payload(
            entities=[
                {"roles": ["registrant"]},
                {"handle": "   ", "roles": ["admin"]},
                {
                    "handle": "  GOOD-1 ",
                    "roles": ["tech"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Good Entity"]]],
                },
            ]
        )
        result = await _domain_result(payload)
        assert len(result.evidence) == 1
        # Source order is preserved for the remaining usable references only.
        assert result.evidence[0].facts["entities"] == (
            {
                "handle": "GOOD-1",
                "roles": ("tech",),
                "display_name": "Good Entity",
            },
        )


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapCommonFactNormalization:
    """Stable normalized shapes for object class, status, and event facts."""

    async def test_object_class_fact_canonical(self) -> None:
        """The object_class_name fact is canonical lowercase after validation."""
        result = await _domain_result(_domain_payload(objectClassName="  DOMAIN  "))
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["object_class_name"] == "domain"

    async def test_status_normalization_policy(self) -> None:
        """Statuses are trimmed, lowercased, deduplicated, and order-preserving."""
        payload = _domain_payload(
            status=["  Active ", "", "ACTIVE", "active", "Client Hold", "  "]
        )
        result = await _domain_result(payload)
        assert len(result.evidence) == 1
        facts = result.evidence[0].facts
        assert facts["status"] == ("active", "client hold")

    async def test_blank_statuses_never_enter_evidence(self) -> None:
        """A status list containing only blank values emits no status fact."""
        result = await _domain_result(_domain_payload(status=["", "   "]))
        assert len(result.evidence) == 1
        assert "status" not in result.evidence[0].facts

    async def test_overlong_or_wrong_type_status_rejected(self) -> None:
        """Overlong and wrong-type status entries are schema errors."""
        for bad_status in (["x" * 65], [123]):
            await _assert_invalid(
                _domain_payload(status=bad_status),
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )

    @staticmethod
    async def _single_event_facts(event: dict[str, Any]) -> Any:
        """Investigate a domain whose only event is the supplied entry."""
        result = await _domain_result(_domain_payload(events=[event]))
        assert len(result.evidence) == 1
        return result.evidence[0].facts

    async def test_dateless_events_never_emitted(self) -> None:
        """Missing, blank, malformed, and naive dates never emit an event."""
        for event in (
            {"eventAction": "registration"},
            {"eventAction": "registration", "eventDate": ""},
            {"eventAction": "registration", "eventDate": "   "},
            {"eventAction": "registration", "eventDate": "not-a-date"},
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00"},
        ):
            facts = await self._single_event_facts(event)
            assert "events" not in facts

    async def test_valid_offset_event_dates_normalize_to_utc(self) -> None:
        """A valid offset timestamp is emitted as a UTC date."""
        facts = await self._single_event_facts(
            {
                "eventAction": "registration",
                "eventDate": "2020-05-04T03:02:01+02:00",
            }
        )
        assert facts["events"] == (
            {"action": "registration", "date": "2020-05-04T01:02:01+00:00"},
        )

    async def test_non_rfc3339_event_dates_omitted(self) -> None:
        """Non-RFC 3339 spellings accepted by the ISO parser are omitted."""
        for event_date in (
            # Space date/time separator: ISO 8601, not RFC 3339.
            "2020-01-01 12:00:00+00:00",
            # Numeric offset without the RFC 3339 colon.
            "2020-01-01T12:00:00+0000",
        ):
            facts = await self._single_event_facts(
                {"eventAction": "registration", "eventDate": event_date}
            )
            assert "events" not in facts, event_date

    async def test_valid_rfc3339_event_date_forms_normalize(self) -> None:
        """RFC 3339 spellings all normalize to one UTC fact date."""
        for event_date, expected_utc in (
            ("2020-01-01T12:00:00Z", "2020-01-01T12:00:00+00:00"),
            # RFC 3339 permits lower-case "t" and "z" spellings.
            ("2020-01-01t12:00:00z", "2020-01-01T12:00:00+00:00"),
            ("2020-01-01T12:00:00.250Z", "2020-01-01T12:00:00.250000+00:00"),
            ("2020-01-01T14:00:00+02:00", "2020-01-01T12:00:00+00:00"),
        ):
            facts = await self._single_event_facts(
                {"eventAction": "registration", "eventDate": event_date}
            )
            assert facts["events"] == (
                {"action": "registration", "date": expected_utc},
            ), event_date

    async def test_event_entry_policies(self) -> None:
        """Events lacking a valid RFC 3339 date are omitted; valid ones normalize."""
        result = await _domain_result(
            _domain_payload(
                events=[
                    {"eventAction": "", "eventDate": "2026-01-01T00:00:00Z"},
                    {"eventAction": "registration"},
                    {
                        "eventAction": "last changed",
                        "eventDate": "not-a-date",
                    },
                    {"eventAction": "last changed", "eventDate": "2026-01-10T15:30:00"},
                    {
                        "eventAction": "last changed",
                        "eventDate": "2026-01-10T17:30:00+02:00",
                    },
                ]
            )
        )
        assert len(result.evidence) == 1
        facts = result.evidence[0].facts
        # Only the event with a valid timezone-aware date is emitted; blank
        # actions, date-less events, and naive dates never become evidence.
        assert facts["events"] == (
            {"action": "last changed", "date": "2026-01-10T15:30:00+00:00"},
        )
        assert result.evidence[0].observed_at == datetime(
            2026, 1, 10, 15, 30, 0, tzinfo=UTC
        )

    async def test_non_rfc3339_last_changed_does_not_set_observed_at(self) -> None:
        """A non-RFC 3339 last-changed date never becomes observed_at."""
        result = await _domain_result(
            _domain_payload(
                events=[
                    {
                        "eventAction": "last changed",
                        # Space separator: ISO 8601, but not an RFC 3339 date-time.
                        "eventDate": "2026-01-10 15:30:00+00:00",
                    }
                ]
            )
        )
        assert len(result.evidence) == 1
        assert "events" not in result.evidence[0].facts
        assert result.evidence[0].observed_at is None

    async def test_mixed_valid_and_invalid_last_changed_selection(self) -> None:
        """Only valid RFC 3339 last-changed entries join newest-timestamp selection."""
        result = await _domain_result(
            _domain_payload(
                events=[
                    {
                        "eventAction": "last changed",
                        "eventDate": "2026-01-05T00:00:00Z",
                    },
                    {
                        "eventAction": "last changed",
                        # Non-RFC spelling with a far-future claim must be ignored,
                        # never winning newest-timestamp selection.
                        "eventDate": "2030-01-01 00:00:00+00:00",
                    },
                    {
                        "eventAction": "last changed",
                        "eventDate": "2026-01-10T15:30:00Z",
                    },
                ]
            )
        )
        assert len(result.evidence) == 1
        facts = result.evidence[0].facts
        assert facts["events"] == (
            {"action": "last changed", "date": "2026-01-05T00:00:00+00:00"},
            {"action": "last changed", "date": "2026-01-10T15:30:00+00:00"},
        )
        assert result.evidence[0].observed_at == datetime(
            2026, 1, 10, 15, 30, 0, tzinfo=UTC
        )

    async def test_common_facts_deeply_immutable(self) -> None:
        """Normalized common facts cannot be mutated at any nesting level."""
        payload = _domain_payload(
            status=["Active", "client hold"],
            events=[
                {
                    "eventAction": "registration",
                    "eventDate": "2020-01-01T00:00:00Z",
                }
            ],
        )
        result = await _domain_result(payload)
        facts = result.evidence[0].facts
        assert isinstance(facts["status"], tuple)
        assert isinstance(facts["events"], tuple)
        with pytest.raises(TypeError):
            facts["status"] = ("mutated",)
        with pytest.raises(TypeError):
            facts["events"][0]["action"] = "mutated"
