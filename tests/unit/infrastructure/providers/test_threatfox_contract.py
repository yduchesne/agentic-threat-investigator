# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Strict response-record schema and IOC identity-matching contract tests.

Pure validation and matching rules for the ThreatFox provider, exercised
against ATI-authored synthetic records; no test performs HTTP I/O and no
test contacts the real ThreatFox service.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.infrastructure.providers.threatfox import (
    ThreatFoxRecord,
    parse_source_ip_ioc,
    record_matches_query,
)
from tests.support.threatfox_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    CANONICAL_ASYNCRAT_IP,
    CANONICAL_ASYNCRAT_MALWARE,
    CANONICAL_ASYNCRAT_PRINTABLE,
    REMOVED,
    asyncrat_domain_record,
    asyncrat_ip_port_record,
)

pytestmark = pytest.mark.unit

# Consumed required members whose explicit null or absence is malformed.
_REQUIRED_RECORD_MEMBERS = (
    "id",
    "ioc",
    "threat_type",
    "threat_type_desc",
    "ioc_type",
    "malware",
    "confidence_level",
    "first_seen",
)

# Consumed members whose documented null values are valid source facts.
_NULLABLE_RECORD_MEMBERS = (
    "malware_printable",
    "malware_alias",
    "malware_malpedia",
    "last_seen",
    "reference",
    "tags",
)

# Documented upstream members that ATI deliberately ignores.
_IGNORED_RECORD_MEMBERS = (
    "reporter",
    "comment",
    "credits",
    "malware_samples",
)


@pytest.mark.unit
class TestThreatFoxRecordSchema:
    """Strict response-record schema tests for ``ThreatFoxRecord``."""

    def test_fully_populated_record_parses(self) -> None:
        """A fully populated canonical record parses into normalized members."""
        parsed = ThreatFoxRecord.model_validate(asyncrat_domain_record())
        assert parsed.id == "864201"
        assert parsed.ioc == CANONICAL_ASYNCRAT_DOMAIN
        assert parsed.threat_type == "botnet_cc"
        assert parsed.ioc_type == "domain"
        assert parsed.malware == CANONICAL_ASYNCRAT_MALWARE
        assert parsed.malware_printable == CANONICAL_ASYNCRAT_PRINTABLE
        assert parsed.malware_alias is None
        assert parsed.malware_malpedia is None
        assert parsed.confidence_level == 100
        assert parsed.first_seen == datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)
        assert parsed.last_seen == datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)
        assert parsed.reference is None
        assert parsed.tags == ["AsyncRAT"]

    @pytest.mark.parametrize("member", _REQUIRED_RECORD_MEMBERS)
    def test_null_required_member_rejected(self, member: str) -> None:
        """An explicit null for any required non-nullable member is malformed."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(asyncrat_domain_record(**{member: None}))

    @pytest.mark.parametrize("member", _REQUIRED_RECORD_MEMBERS)
    def test_missing_required_member_rejected(self, member: str) -> None:
        """A missing required non-nullable member is malformed."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(asyncrat_domain_record(**{member: REMOVED}))

    @pytest.mark.parametrize("member", _NULLABLE_RECORD_MEMBERS)
    def test_null_nullable_member_retained(self, member: str) -> None:
        """The documented null values of nullable members are valid."""
        parsed = ThreatFoxRecord.model_validate(
            asyncrat_domain_record(**{member: None})
        )
        assert getattr(parsed, member) is None

    @pytest.mark.parametrize(
        "bad",
        [None, 41, 41.0, True, "", " 41", "41 ", "41a", "-41", "0x41", "1" * 17],
    )
    def test_malformed_id_rejected(self, bad: Any) -> None:
        """The id accepts only the official bounded decimal string form."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(asyncrat_domain_record(id=bad))

    @pytest.mark.parametrize("value", ["41", "864201", "0"])
    def test_valid_ids_accepted(self, value: str) -> None:
        """Bounded decimal identifier strings are accepted verbatim."""
        parsed = ThreatFoxRecord.model_validate(asyncrat_domain_record(id=value))
        assert parsed.id == value

    @pytest.mark.parametrize(
        "bad",
        [
            None,
            "",
            " ",
            "AsyncRAT",
            "win asyncrat",
            " win.asyncrat",
            42,
            True,
            "a" * 129,
        ],
    )
    def test_malformed_malware_identifier_rejected(self, bad: Any) -> None:
        """The malware member accepts only bounded lowercase machine labels."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(asyncrat_domain_record(malware=bad))

    @pytest.mark.parametrize(
        "value", ["win.asyncrat", "js.magecart", "elf.mirai", "win.cobalt_strike", "a"]
    )
    def test_valid_malware_identifiers_accepted(self, value: str) -> None:
        """Bounded lowercase machine identifiers are accepted verbatim."""
        parsed = ThreatFoxRecord.model_validate(asyncrat_domain_record(malware=value))
        assert parsed.malware == value

    @pytest.mark.parametrize("bad", [42, True, "", " ", " padded", "x" * 257])
    def test_malformed_malware_printable_rejected(self, bad: Any) -> None:
        """A non-null printable name must be a nonblank bounded unpadded string."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(
                asyncrat_domain_record(malware_printable=bad)
            )


@pytest.mark.unit
class TestThreatFoxRecordMemberValues:
    """Value-level validation tests for individual record members."""

    def test_confidence_level_bounds(self) -> None:
        """The source confidence level accepts only strict integers 0..100."""
        for value in (0, 100):
            parsed = ThreatFoxRecord.model_validate(
                asyncrat_domain_record(confidence_level=value)
            )
            assert parsed.confidence_level == value
        for bad in (-1, 101, True, False, 50.0, "50", None, [50]):
            with pytest.raises(ValidationError):
                ThreatFoxRecord.model_validate(
                    asyncrat_domain_record(confidence_level=bad)
                )

    @pytest.mark.parametrize(
        "bad",
        [
            "2026-08-20T12:00:00Z",
            "2026-08-20T12:00:00+00:00",
            "2026-08-20 12:00:00",
            "2026-08-20 12:00:00 utc",
            " 2026-08-20 12:00:00 UTC",
            "2026-08-20 12:00:00 UTC ",
            "2026-13-01 00:00:00 UTC",
            "2026-02-30 00:00:00 UTC",
            1545344114,
            True,
        ],
    )
    def test_malformed_first_seen_rejected(self, bad: Any) -> None:
        """Only the official ``YYYY-MM-DD HH:MM:SS UTC`` form is accepted."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(asyncrat_domain_record(first_seen=bad))

    @pytest.mark.parametrize(
        "bad",
        [
            "2026-08-20T12:00:00Z",
            "2026-08-20 12:00:00",
            "not-a-date",
            1545344114,
            True,
        ],
    )
    def test_malformed_last_seen_rejected(self, bad: Any) -> None:
        """A non-null last_seen must use the official timestamp form."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(asyncrat_domain_record(last_seen=bad))

    def test_last_seen_before_first_seen_rejected(self) -> None:
        """A last_seen earlier than first_seen is malformed."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(
                asyncrat_domain_record(
                    first_seen="2026-08-21 12:00:00 UTC",
                    last_seen="2026-08-20 12:00:00 UTC",
                )
            )

    def test_last_seen_equal_to_first_seen_accepted(self) -> None:
        """A last_seen equal to first_seen is valid."""
        parsed = ThreatFoxRecord.model_validate(
            asyncrat_domain_record(
                first_seen="2026-08-20 12:00:00 UTC",
                last_seen="2026-08-20 12:00:00 UTC",
            )
        )
        assert parsed.last_seen == parsed.first_seen

    @pytest.mark.parametrize(
        "bad",
        ["ftp://example.com/ref", "https://", "/relative/path", "not a url", 42],
    )
    def test_malformed_reference_rejected(self, bad: Any) -> None:
        """A non-null reference must be a bounded http(s) URL."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(asyncrat_domain_record(reference=bad))

    @pytest.mark.parametrize(
        "value",
        ["https://twitter.com/synthetic/status/1", "http://example.com/reference"],
    )
    def test_valid_references_accepted(self, value: str) -> None:
        """Bounded http(s) references are retained verbatim."""
        parsed = ThreatFoxRecord.model_validate(asyncrat_domain_record(reference=value))
        assert parsed.reference == value

    @pytest.mark.parametrize(
        "bad",
        ["AsyncRAT", 42, [42], [None], [""], ["x" * 65], [True], {"tag": 1}],
    )
    def test_malformed_tags_rejected(self, bad: Any) -> None:
        """Tags accept only the documented null or bounded-string list form."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(asyncrat_domain_record(tags=bad))

    @pytest.mark.parametrize("value", [[], ["AsyncRAT"], ["a", "b"]])
    def test_valid_tags_accepted(self, value: list[str]) -> None:
        """Explicit bounded tag lists are retained in source order."""
        parsed = ThreatFoxRecord.model_validate(asyncrat_domain_record(tags=value))
        assert parsed.tags == value

    @pytest.mark.parametrize("bad", ["gopher://x", "not a url", 42, "https://"])
    def test_malformed_malpedia_rejected(self, bad: Any) -> None:
        """A non-null malware_malpedia member must be a bounded http(s) URL."""
        with pytest.raises(ValidationError):
            ThreatFoxRecord.model_validate(asyncrat_domain_record(malware_malpedia=bad))

    def test_unknown_members_ignored(self) -> None:
        """Unknown members are ignored and never copied into the model."""
        record = asyncrat_domain_record(unknownMember="value", newField=[1, 2])
        parsed = ThreatFoxRecord.model_validate(record)
        assert not hasattr(parsed, "unknownMember")
        assert not hasattr(parsed, "newField")

    def test_ignored_members_never_enter_model(self) -> None:
        """Documented ignored members never appear in the retained model."""
        record = asyncrat_domain_record(
            comment="synthetic ignored comment",
            credits=[{"credits_from": "ThreatFox", "credits_amount": 5}],
            malware_samples=[
                {
                    "time_stamp": "2026-08-20 12:00:00 UTC",
                    "md5_hash": "0" * 32,
                    "sha256_hash": "0" * 64,
                    "malware_bazaar": "https://bazaar.example.com/sample/",
                }
            ],
        )
        dumped = ThreatFoxRecord.model_validate(record).model_dump()
        for member in (*_IGNORED_RECORD_MEMBERS, "malware_bazaar"):
            assert member not in str(dumped)

    def test_record_model_is_frozen(self) -> None:
        """The record model is immutable."""
        parsed = ThreatFoxRecord.model_validate(asyncrat_domain_record())
        with pytest.raises(ValidationError):
            parsed.malware = "win.other"


# -- IOC identity matching ---------------------------------------------------


@pytest.mark.unit
class TestIocIdentityMatching:
    """Pure identity-matching tests for source IOC parsing and equality."""

    def test_parse_bare_ipv4(self) -> None:
        """A bare IPv4 value parses with no port."""
        assert parse_source_ip_ioc("203.0.113.42") == ("203.0.113.42", None)

    def test_parse_bare_ipv6(self) -> None:
        """A bare IPv6 value parses canonically with no port."""
        assert parse_source_ip_ioc("2001:0DB8:0000::1") == ("2001:db8::1", None)

    def test_parse_ipv4_with_port(self) -> None:
        """An IPv4 ip:port pair parses host and port."""
        assert parse_source_ip_ioc("203.0.113.42:443") == ("203.0.113.42", 443)

    def test_parse_bracketed_ipv6_with_port(self) -> None:
        """A bracketed RFC 3986 IPv6 ip:port pair parses host and port."""
        assert parse_source_ip_ioc("[2001:db8::1]:443") == ("2001:db8::1", 443)
        assert parse_source_ip_ioc("[2001:0DB8:0::1]:65535") == ("2001:db8::1", 65535)

    def test_parse_port_bounds(self) -> None:
        """Ports must be integers in 1..65535."""
        for bad_port in ("0", "65536", "-1", "abc", ""):
            assert parse_source_ip_ioc(f"203.0.113.42:{bad_port}") is None
            assert parse_source_ip_ioc(f"[2001:db8::1]:{bad_port}") is None

    def test_parse_unbracketed_ipv6_with_port_never_guesses(self) -> None:
        """An unbracketed IPv6-plus-port spelling is never split to infer a port."""
        # The whole value parses only as a bare (different) IPv6 address, so
        # it can never match the queried shorter address.
        parsed = parse_source_ip_ioc("2001:db8::1:443")
        assert parsed is not None
        assert parsed[1] is None
        assert parsed[0] == "2001:db8::1:443"

    def test_parse_malformed_values_rejected(self) -> None:
        """Malformed, non-IP, and ambiguous values are rejected."""
        for bad in (
            "",
            "not-an-ip",
            "999.999.999.999",
            "203.0.113.42:",
            ":443",
            "[2001:db8::1",
            "[203.0.113.42]:443",
            "203.0.113.42:443:1",
        ):
            assert parse_source_ip_ioc(bad) is None

    def test_domain_match_canonical_equality(self) -> None:
        """Returned domains canonicalize under ATI rules and require equality."""
        record = ThreatFoxRecord.model_validate(asyncrat_domain_record())
        assert record_matches_query(record, EntityType.DOMAIN, "malicious-domain.test")
        # Case-insensitive and terminal-dot variants canonicalize equally.
        upper = ThreatFoxRecord.model_validate(
            asyncrat_domain_record(ioc="MALICIOUS-DOMAIN.TEST")
        )
        assert record_matches_query(upper, EntityType.DOMAIN, "malicious-domain.test")
        dotted = ThreatFoxRecord.model_validate(
            asyncrat_domain_record(ioc="malicious-domain.test.")
        )
        assert record_matches_query(dotted, EntityType.DOMAIN, "malicious-domain.test")

    def test_domain_mismatch_rejected(self) -> None:
        """A different domain never matches the queried identity."""
        record = ThreatFoxRecord.model_validate(asyncrat_domain_record())
        assert not record_matches_query(record, EntityType.DOMAIN, "other.test")

    def test_ioc_type_must_agree_with_syntax(self) -> None:
        """The record ioc_type must agree with the actual IOC syntax and query."""
        domain_value_record = ThreatFoxRecord.model_validate(asyncrat_domain_record())
        # A domain-typed record does not satisfy an IP query...
        assert not record_matches_query(
            domain_value_record, EntityType.IP_ADDRESS, CANONICAL_ASYNCRAT_IP
        )
        # ...and an ip:port-typed record carrying a domain does not satisfy a
        # domain query.
        mislabeled = ThreatFoxRecord.model_validate(
            asyncrat_ip_port_record(ioc=CANONICAL_ASYNCRAT_DOMAIN)
        )
        assert not record_matches_query(
            mislabeled, EntityType.DOMAIN, "malicious-domain.test"
        )

    def test_ip_port_match_host_equality(self) -> None:
        """An ip:port record matches when the parsed host equals the query."""
        record = ThreatFoxRecord.model_validate(asyncrat_ip_port_record())
        assert record_matches_query(
            record, EntityType.IP_ADDRESS, CANONICAL_ASYNCRAT_IP
        )

    def test_bare_ip_record_matches_ip_query(self) -> None:
        """A bare IP record with the ip:port source type matches the query."""
        record = ThreatFoxRecord.model_validate(
            asyncrat_ip_port_record(ioc=CANONICAL_ASYNCRAT_IP)
        )
        assert record_matches_query(
            record, EntityType.IP_ADDRESS, CANONICAL_ASYNCRAT_IP
        )

    def test_wrong_ip_rejected(self) -> None:
        """A record about a different address never matches."""
        record = ThreatFoxRecord.model_validate(
            asyncrat_ip_port_record(ioc="203.0.113.43:443")
        )
        assert not record_matches_query(
            record, EntityType.IP_ADDRESS, CANONICAL_ASYNCRAT_IP
        )

    def test_ipv6_records_match(self) -> None:
        """Bare and bracketed IPv6 records match their queried identity."""
        bracketed = ThreatFoxRecord.model_validate(
            asyncrat_ip_port_record(ioc="[2001:db8::1]:443")
        )
        assert record_matches_query(bracketed, EntityType.IP_ADDRESS, "2001:db8::1")
        bare = ThreatFoxRecord.model_validate(
            asyncrat_ip_port_record(ioc="2001:0DB8:0000::1")
        )
        assert record_matches_query(bare, EntityType.IP_ADDRESS, "2001:db8::1")

    def test_url_type_records_never_match(self) -> None:
        """URL-typed records match neither DOMAIN nor IP_ADDRESS queries."""
        record = ThreatFoxRecord.model_validate(
            asyncrat_domain_record(ioc_type="url", ioc="http://malicious-domain.test/")
        )
        assert not record_matches_query(
            record, EntityType.DOMAIN, "malicious-domain.test"
        )
        assert not record_matches_query(record, EntityType.IP_ADDRESS, "203.0.113.42")

    def test_unknown_ioc_type_rejected(self) -> None:
        """Record types outside the supported source set never match."""
        record = ThreatFoxRecord.model_validate(
            asyncrat_domain_record(ioc_type="filename", ioc="payload.dll")
        )
        assert not record_matches_query(
            record, EntityType.DOMAIN, "malicious-domain.test"
        )

    def test_unsupported_entity_type_rejected(self) -> None:
        """Unsupported queried entity types never match."""
        record = ThreatFoxRecord.model_validate(asyncrat_domain_record())
        assert not record_matches_query(record, EntityType.URL, "http://x/")
