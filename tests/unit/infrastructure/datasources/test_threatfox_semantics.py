# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27C ThreatFox semantic-format parser tests.

Matrix IDs D27C-T01..T20 pin the extracted semantic parser: no-result and
empty-data empty successes, typed record output in source order, duplicate
and conflicting-ID rules, unrelated-record rejection, malformed
timestamp/URL/domain failures, body-encoded ``ratelimited`` as an
operational failure, IP:port and IPv6 canonical matching, UTC timestamps,
determinism, and the absence of any Evidence/provider dependency. All
payloads are ATI-authored synthetic fixtures; no test contacts the real
ThreatFox service.
"""

from __future__ import annotations

import inspect
import re
from datetime import UTC, datetime
from typing import Any

import pytest

from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    DatasourceStageError,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.infrastructure.datasources import (
    threatfox_semantics as semantics,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
    canonical_record_domain,
    parse_source_ip_ioc,
    parse_threatfox_response,
    record_matches_query,
)
from tests.support.threatfox_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    CANONICAL_ASYNCRAT_IP,
    CANONICAL_ASYNCRAT_IP_PORT,
    asyncrat_domain_record,
    asyncrat_ip_port_record,
    threatfox_no_result_response,
    threatfox_search_response,
)

_DOMAIN_ENTITY = EntityType.DOMAIN
_IP_ENTITY = EntityType.IP_ADDRESS


def _parse(
    payload: Any,
    *,
    entity_type: EntityType = _DOMAIN_ENTITY,
    canonical_value: str = CANONICAL_ASYNCRAT_DOMAIN,
) -> semantics.ThreatFoxSemanticResult:
    """Parse one deterministic decoded response through the production parser."""
    return parse_threatfox_response(
        payload, entity_type=entity_type, canonical_value=canonical_value
    )


class TestEmptyOutcomes:
    """D27C-T01/T02: valid no-result and empty-data outcomes."""

    def test_t01_no_result_is_empty_success(self) -> None:
        """D27C-T01: ``no_result`` is an empty success, never an error."""
        result = _parse(threatfox_no_result_response())
        assert result.error is None
        assert result.records == ()

    def test_t02_ok_with_empty_data_is_empty_success(self) -> None:
        """D27C-T02: ``ok`` with an empty data array is an empty success."""
        result = _parse(threatfox_search_response())
        assert result.error is None
        assert result.records == ()


class TestValidRecords:
    """D27C-T03/T04/T18/T19: typed records, order, timestamps, determinism."""

    def test_t03_one_valid_matching_record(self) -> None:
        """D27C-T03: one valid matching record yields one typed record."""
        result = _parse(threatfox_search_response(asyncrat_domain_record()))
        assert result.error is None
        assert len(result.records) == 1
        record = result.records[0]
        assert isinstance(record, ThreatFoxRecord)
        assert record.id == "864201"
        assert record.ioc == CANONICAL_ASYNCRAT_DOMAIN
        assert record.malware == "win.asyncrat"

    def test_t04_multiple_records_preserve_source_order(self) -> None:
        """D27C-T04: valid records are emitted in source order."""
        payload = threatfox_search_response(
            asyncrat_domain_record(id="864201"),
            asyncrat_domain_record(id="864202", ioc="malicious-domain.test"),
        )
        result = _parse(payload)
        assert result.error is None
        assert [record.id for record in result.records] == ["864201", "864202"]

    def test_t18_timestamps_are_utc(self) -> None:
        """D27C-T18: parsed source timestamps are timezone-aware UTC."""
        result = _parse(threatfox_search_response(asyncrat_domain_record()))
        record = result.records[0]
        assert record.first_seen.tzinfo is UTC
        assert record.first_seen == datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)
        assert record.last_seen == datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)

    def test_t19_repeated_parse_is_equal(self) -> None:
        """D27C-T19: the same decoded value parses to an equal result."""
        payload = threatfox_search_response(asyncrat_domain_record())
        assert _parse(payload) == _parse(payload)


class TestDuplicateRules:
    """D27C-T05/T06: identical and conflicting duplicate source IDs."""

    def test_t05_identical_duplicate_id_kept_once(self) -> None:
        """D27C-T05: an identical duplicate ID is retained once (first wins)."""
        payload = threatfox_search_response(
            asyncrat_ip_port_record(id="864202"),
            asyncrat_ip_port_record(id="864202"),
        )
        result = _parse(
            payload, entity_type=_IP_ENTITY, canonical_value=CANONICAL_ASYNCRAT_IP
        )
        assert result.error is None
        assert [record.id for record in result.records] == ["864202"]

    def test_t05b_duplicate_id_with_ignored_field_change_is_exact_duplicate(
        self,
    ) -> None:
        """Ignored-field differences do not conflict or create extra records."""
        payload = threatfox_search_response(
            asyncrat_ip_port_record(id="864202"),
            asyncrat_ip_port_record(
                id="864202",
                reporter="other_reporter",
                malware_samples=[],
            ),
        )
        result = _parse(
            payload, entity_type=_IP_ENTITY, canonical_value=CANONICAL_ASYNCRAT_IP
        )
        assert result.error is None
        assert [record.id for record in result.records] == ["864202"]

    def test_t06_conflicting_duplicate_id_fails_whole_response(self) -> None:
        """D27C-T06: a conflicting duplicate ID fails the whole response."""
        payload = threatfox_search_response(
            asyncrat_ip_port_record(id="864202", confidence_level=75),
            asyncrat_ip_port_record(id="864202", confidence_level=100),
        )
        result = _parse(
            payload, entity_type=_IP_ENTITY, canonical_value=CANONICAL_ASYNCRAT_IP
        )
        assert result.records == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert result.error.code == "semantic_validation_failed"


class TestFailures:
    """D27C-T07..T13: malformed, unrelated, and unknown inputs fail closed."""

    def test_t07_unrelated_ioc_fails_whole_response(self) -> None:
        """D27C-T07: an unrelated returned IOC fails the whole response."""
        payload = threatfox_search_response(
            asyncrat_domain_record(id="864201"),
            asyncrat_domain_record(id="864299", ioc="unrelated-domain.test"),
        )
        result = _parse(payload)
        assert result.records == ()
        assert result.error is not None

    def test_t08_malformed_timestamp_fails(self) -> None:
        """D27C-T08: a malformed source timestamp fails the parse."""
        payload = threatfox_search_response(
            asyncrat_domain_record(first_seen="2026-08-20T12:00:00Z")
        )
        result = _parse(payload)
        assert result.records == ()
        assert result.error is not None

    def test_t09_malformed_reference_url_fails(self) -> None:
        """D27C-T09: a malformed reference URL member fails the parse."""
        payload = threatfox_search_response(
            asyncrat_domain_record(reference="file:///etc/passwd")
        )
        result = _parse(payload)
        assert result.records == ()
        assert result.error is not None

    def test_t11_unknown_status_fails(self) -> None:
        """D27C-T11: an unknown query_status is never success."""
        result = _parse({"query_status": "some_future_status"})
        assert result.records == ()
        assert result.error is not None
        assert result.error.code == "semantic_validation_failed"

    @pytest.mark.parametrize(
        "payload",
        [
            [],
            ["ok"],
            {},
            {"query_status": 42},
            {"query_status": ""},
            {"query_status": None},
        ],
    )
    def test_t12_non_object_top_level_fails(self, payload: Any) -> None:
        """D27C-T12: a missing/non-object top level fails the parse."""
        result = _parse(payload)
        assert result.records == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION

    @pytest.mark.parametrize(
        "payload",
        [
            {"query_status": "ok"},
            {"query_status": "ok", "data": None},
            {"query_status": "ok", "data": {"id": "1"}},
            {"query_status": "ok", "data": "records"},
        ],
    )
    def test_t13_data_not_array_fails(self, payload: Any) -> None:
        """D27C-T13: ``ok`` without an array data member fails the parse."""
        result = _parse(payload)
        assert result.records == ()
        assert result.error is not None

    def test_t17_malformed_returned_domain_cannot_match(self) -> None:
        """D27C-T17: a malformed returned domain can never match a query."""
        assert canonical_record_domain("malicious-domain.test..") is None
        payload = threatfox_search_response(
            asyncrat_domain_record(ioc="malicious-domain.test..")
        )
        result = _parse(payload)
        assert result.records == ()
        assert result.error is not None


class TestBodyEncodedRateLimit:
    """D27C-T10: the body ``ratelimited`` status is operational, not semantic."""

    def test_t10_ratelimited_is_operational_failure_with_no_objects(self) -> None:
        """D27C-T10: ``ratelimited`` yields an acquisition error, no objects."""
        result = _parse({"query_status": "ratelimited"})
        assert result.records == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.ACQUISITION
        assert result.error.code == "rate_limited"
        assert result.error.retryable is True


class TestIpIocMatching:
    """D27C-T14..T16: canonical ip:port and IPv6 identity matching."""

    def test_t14_ip_port_canonical_match_accepted(self) -> None:
        """D27C-T14: an ip:port record canonical-matches the queried IP."""
        payload = threatfox_search_response(asyncrat_ip_port_record())
        result = _parse(
            payload, entity_type=_IP_ENTITY, canonical_value=CANONICAL_ASYNCRAT_IP
        )
        assert result.error is None
        assert result.records[0].ioc == CANONICAL_ASYNCRAT_IP_PORT
        assert parse_source_ip_ioc("203.0.113.42:443") == ("203.0.113.42", 443)

    def test_t15_bracketed_ipv6_port_accepted(self) -> None:
        """D27C-T15: a bracketed RFC 3986 IPv6:port form canonicalizes."""
        assert parse_source_ip_ioc("[2001:0DB8:0000::1]:8443") == (
            "2001:db8::1",
            8443,
        )
        payload = threatfox_search_response(
            asyncrat_ip_port_record(id="864250", ioc="[2001:0DB8:0000::1]:8443")
        )
        result = _parse(
            payload,
            entity_type=_IP_ENTITY,
            canonical_value="2001:db8::1",
        )
        assert result.error is None
        assert result.records[0].id == "864250"

    def test_t16_ambiguous_unbracketed_ipv6_port_rejected(self) -> None:
        """D27C-T16: an ambiguous unbracketed IPv6-plus-port never matches."""
        # A multi-colon unbracketed value is never split to infer a port;
        # either it fails to parse or it canonicalizes to a different
        # address, so the record cannot match the queried bare IPv6 identity.
        if parse_source_ip_ioc("2001:db8::1:443") is not None:
            matched = record_matches_query(
                ThreatFoxRecord.model_validate(
                    asyncrat_ip_port_record(id="864251", ioc="2001:db8::1:443")
                ),
                _IP_ENTITY,
                "2001:db8::1",
            )
            assert matched is False
        else:
            assert parse_source_ip_ioc("2001:db8::1:443") is None
        payload = threatfox_search_response(
            asyncrat_ip_port_record(id="864251", ioc="2001:db8::1:443")
        )
        result = _parse(
            payload,
            entity_type=_IP_ENTITY,
            canonical_value="2001:db8::1",
        )
        assert result.records == ()
        assert result.error is not None


class TestModuleIsolation:
    """D27C-T20: the semantic module has no Evidence/provider dependency."""

    def test_t20_semantic_module_imports_no_evidence_dependency(self) -> None:
        """D27C-T20: the semantic module never imports Evidence or providers."""
        source = inspect.getsource(semantics)
        import_lines = [
            line.strip()
            for line in source.splitlines()
            if line.lstrip().startswith(("import ", "from "))
        ]
        for line in import_lines:
            assert "evidence" not in line
            assert "app.providers" not in line
        # Module surface exposes only the semantic contract objects.
        assert not hasattr(semantics, "Evidence")
        assert not hasattr(semantics, "ProviderResult")
        assert not hasattr(semantics, "ProviderErrorCode")
        # The parser implementation never logs source payloads.
        assert "logger" not in source.lower()

    def test_record_matches_query_is_pure(self) -> None:
        """record_matches_query rejects unsupported and unrelated identities."""
        record = ThreatFoxRecord.model_validate(asyncrat_domain_record())
        assert record_matches_query(record, _DOMAIN_ENTITY, CANONICAL_ASYNCRAT_DOMAIN)
        assert not record_matches_query(record, _DOMAIN_ENTITY, "unrelated-domain.test")
        assert not record_matches_query(record, _IP_ENTITY, CANONICAL_ASYNCRAT_IP)

    def test_timestamp_parser_rejects_iso_and_padded_forms(self) -> None:
        """Only the strict official ThreatFox UTC timestamp form is accepted."""
        assert semantics.parse_threatfox_timestamp("2026-08-20 12:00:00 UTC") == (
            datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)
        )
        for bad in (" 2026-08-20 12:00:00 UTC", "2026-08-20T12:00:00Z", 20260820):
            with pytest.raises(ValueError, match="source timestamp"):
                semantics.parse_threatfox_timestamp(bad)

    def test_canonical_record_domain_handles_idna_and_padding(self) -> None:
        """The strict DNS validator governs returned-domain matching."""
        assert canonical_record_domain("example.test") == "example.test"
        assert canonical_record_domain("under_score.example.test") is None
        assert canonical_record_domain("example.test..") is None


def test_semantic_result_invariant_rejects_failed_records() -> None:
    """A failed ThreatFox parse cannot also carry records."""
    with pytest.raises(ValueError, match="cannot carry records"):
        semantics.ThreatFoxSemanticResult(
            records=(ThreatFoxRecord.model_validate(asyncrat_domain_record()),),
            error=DatasourceStageError(
                stage=DatasourceStage.SEMANTIC_VALIDATION,
                code="semantic_validation_failed",
                retryable=False,
            ),
        )


def test_import_lines_do_not_reference_evidence() -> None:
    """Belt-and-braces: no import statement names an Evidence module."""
    source = inspect.getsource(semantics)
    forbidden = re.compile(r"^\s*(?:from|import)\s+\S*(?:evidence|providers)", re.M)
    assert forbidden.search(source) is None
