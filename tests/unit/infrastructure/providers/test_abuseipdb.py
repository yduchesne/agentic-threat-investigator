# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Strict response-schema tests for the AbuseIPDB check response models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.infrastructure.providers.abuseipdb import (
    AbuseIpdbCheckResponse,
    AbuseIpdbReport,
)
from tests.support.abuseipdb_fixtures import (
    REMOVED,
    REPORT_ENTRY,
    SYNTHETIC_IPV4,
    check_data,
)

# Required members whose explicit null or absence is a malformed response.
_REQUIRED_DATA_MEMBERS = (
    "ipAddress",
    "isPublic",
    "ipVersion",
    "abuseConfidenceScore",
    "isTor",
    "totalReports",
    "numDistinctUsers",
    "reports",
)

# Required members whose documented null values are valid source facts.
_NULLABLE_DATA_MEMBERS = ("isWhitelisted", "lastReportedAt")

# Documented upstream members that ATI deliberately ignores.
_IGNORED_DATA_MEMBERS = (
    "countryCode",
    "countryName",
    "usageType",
    "isp",
    "domain",
    "hostnames",
)

# Documented report-entry members that ATI deliberately ignores.
_IGNORED_REPORT_MEMBERS = (
    "comment",
    "reporterId",
    "reporterCountryCode",
    "reporterCountryName",
)


@pytest.mark.unit
class TestAbuseIpdbSchema:
    """Strict response-schema tests for the check response model."""

    def test_fully_populated_response_parses(self) -> None:
        """A fully populated canonical response parses into canonical members."""
        parsed = AbuseIpdbCheckResponse.model_validate(check_data())
        assert parsed.ip_address == SYNTHETIC_IPV4
        assert parsed.is_public is False
        assert parsed.ip_version == 4
        assert parsed.is_whitelisted is False
        assert parsed.abuse_confidence_score == 100
        assert parsed.is_tor is False
        assert parsed.total_reports == 1
        assert parsed.num_distinct_users == 1
        assert parsed.last_reported_at == datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        assert len(parsed.reports) == 1
        report = parsed.reports[0]
        assert report.reported_at == datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        assert report.categories == [18, 22]

    @pytest.mark.parametrize("member", _REQUIRED_DATA_MEMBERS)
    def test_null_required_member_rejected(self, member: str) -> None:
        """An explicit null for any required non-nullable member is malformed."""
        with pytest.raises(ValidationError):
            AbuseIpdbCheckResponse.model_validate(check_data(**{member: None}))

    @pytest.mark.parametrize("member", _REQUIRED_DATA_MEMBERS)
    def test_missing_required_member_rejected(self, member: str) -> None:
        """A missing required non-nullable member is malformed."""
        with pytest.raises(ValidationError):
            AbuseIpdbCheckResponse.model_validate(check_data(**{member: REMOVED}))

    @pytest.mark.parametrize(
        ("member", "field"),
        [("isWhitelisted", "is_whitelisted"), ("lastReportedAt", "last_reported_at")],
    )
    def test_null_nullable_member_retained(self, member: str, field: str) -> None:
        """The documented null values of nullable members are valid and retained."""
        parsed = AbuseIpdbCheckResponse.model_validate(check_data(**{member: None}))
        assert getattr(parsed, field) is None

    def test_unknown_members_ignored(self) -> None:
        """Unknown members are ignored and never copied into the model."""
        data = check_data()
        data["unknownMember"] = "value"
        data["reports"][0]["unknownEntryMember"] = 42
        parsed = AbuseIpdbCheckResponse.model_validate(data)
        assert not hasattr(parsed, "unknownMember")
        assert not hasattr(parsed.reports[0], "unknownEntryMember")

    def test_ignored_members_never_enter_model(self) -> None:
        """Documented ignored members never appear in the retained model."""

        def _dump(data: dict[str, Any]) -> dict[str, Any]:
            return AbuseIpdbCheckResponse.model_validate(data).model_dump()

        dumped = _dump(check_data())
        serialized = str(dumped)
        for member in (*_IGNORED_DATA_MEMBERS, *_IGNORED_REPORT_MEMBERS):
            assert member not in serialized
        assert "comment" not in serialized
        assert "Documentation Network" not in serialized

    @pytest.mark.parametrize("ignored", _IGNORED_DATA_MEMBERS)
    @pytest.mark.parametrize(
        "wrong", [None, 1, True, 3.5, "", "   ", [], ["x"], {"a": 1}, "x" * 300]
    )
    def test_ignored_members_wrong_shapes_ignored(
        self, ignored: str, wrong: Any
    ) -> None:
        """Ignored members of any shape are ignored, never validated."""
        parsed = AbuseIpdbCheckResponse.model_validate(check_data(**{ignored: wrong}))
        assert not hasattr(parsed, ignored)
        assert ignored not in str(parsed.model_dump())

    def test_score_boundaries(self) -> None:
        """The abuse score accepts only integers 0..100."""
        assert (
            AbuseIpdbCheckResponse.model_validate(
                check_data(abuseConfidenceScore=0)
            ).abuse_confidence_score
            == 0
        )
        assert (
            AbuseIpdbCheckResponse.model_validate(
                check_data(abuseConfidenceScore=100)
            ).abuse_confidence_score
            == 100
        )
        for bad in (-1, 101, True, False, 50.0, "50", None, [50]):
            with pytest.raises(ValidationError):
                AbuseIpdbCheckResponse.model_validate(
                    check_data(abuseConfidenceScore=bad)
                )

    def test_report_counts_nonnegative(self) -> None:
        """Report counts accept only nonnegative integers."""
        for member in ("totalReports", "numDistinctUsers"):
            assert (
                AbuseIpdbCheckResponse.model_validate(check_data(**{member: 0}))
                is not None
            )
            for bad in (-1, True, 1.5, "1", None, [1]):
                with pytest.raises(ValidationError):
                    AbuseIpdbCheckResponse.model_validate(check_data(**{member: bad}))

    def test_boolean_members_strict(self) -> None:
        """``isPublic`` and ``isTor`` accept only strict booleans."""
        for member in ("isPublic", "isTor"):
            for bad in (0, 1, "true", None, [True]):
                with pytest.raises(ValidationError):
                    AbuseIpdbCheckResponse.model_validate(check_data(**{member: bad}))

    def test_ip_version_members(self) -> None:
        """``ipVersion`` accepts only 4 or 6."""
        assert (
            AbuseIpdbCheckResponse.model_validate(check_data(ipVersion=6)).ip_version
            == 6
        )
        for bad in (3, 46, True, "4", None, [4]):
            with pytest.raises(ValidationError):
                AbuseIpdbCheckResponse.model_validate(check_data(ipVersion=bad))

    def test_snake_case_aliases_do_not_populate_source_fields(self) -> None:
        """Only exact external camel-case member names affect parsing."""
        # ATI-side snake-case names are not source members: the model has no
        # populate_by_name, so every snake-case key is an ignored unknown
        # member and the real required camelCase members stay missing.
        snake_case_only = {
            "ip": SYNTHETIC_IPV4,
            "is_public": True,
            "ip_version": 4,
            "is_whitelisted": False,
            "abuse_confidence_score": 0,
            "is_tor": False,
            "total_reports": 0,
            "num_distinct_users": 0,
            "last_reported_at": "2026-01-15T12:00:00+00:00",
            "reports": [
                {
                    "reported_at": "2026-01-15T12:00:00+00:00",
                    "categories": [14],
                }
            ],
        }
        with pytest.raises(ValidationError):
            AbuseIpdbCheckResponse.model_validate(snake_case_only)

        # A snake-case report entry does not satisfy the required camelCase
        # members of a report.
        with pytest.raises(ValidationError):
            AbuseIpdbCheckResponse.model_validate(
                check_data(reports=[{"reported_at": "2026-01-15T12:00:00+00:00"}])
            )
        # The camelCase-only report validates and no snake-case key leaked
        # into the parsed model.
        parsed = AbuseIpdbCheckResponse.model_validate(
            check_data(
                reports=[
                    {
                        "reportedAt": "2026-01-15T12:00:00+00:00",
                        "categories": [14],
                    }
                ]
            )
        )
        assert parsed.reports[0].categories == [14]

    def test_timestamps_normalized_to_utc(self) -> None:
        """Source timestamps accept offsets and Z, normalizing to UTC."""
        parsed = AbuseIpdbCheckResponse.model_validate(
            check_data(
                lastReportedAt="2026-01-15T13:00:00+01:00",
                reports=[
                    {
                        "reportedAt": "2026-01-15T12:00:00Z",
                        "categories": [14],
                    }
                ],
            )
        )
        assert parsed.last_reported_at == datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        assert parsed.reports[0].reported_at == datetime(
            2026, 1, 15, 12, 0, 0, tzinfo=UTC
        )

    @pytest.mark.parametrize(
        "bad",
        [
            "not-a-date",
            "2026-01-15 12:00:00x",
            "2026-01-15T12:00:00",  # naive
            " 2026-01-15T12:00:00+00:00",  # leading space
            "2026-01-15T12:00:00+00:00 ",  # trailing space
            "\t2026-01-15T12:00:00+00:00",  # tab
            "\n2026-01-15T12:00:00+00:00",  # newline
            "2026-01-15T12:00:00+00:00\n",  # trailing newline
            1545344114,
            True,
        ],
    )
    def test_malformed_last_reported_at_rejected(self, bad: Any) -> None:
        """Naive, padded, unparseable, and non-string timestamps are rejected."""
        with pytest.raises(ValidationError):
            AbuseIpdbCheckResponse.model_validate(check_data(lastReportedAt=bad))

    def test_reports_empty_array_valid(self) -> None:
        """An explicitly empty ``reports`` array is valid under the verbose contract."""
        parsed = AbuseIpdbCheckResponse.model_validate(
            check_data(reports=[], lastReportedAt=None)
        )
        assert parsed.reports == []

    @pytest.mark.parametrize(
        "bad",
        [
            None,  # null is not the documented empty array
            {},  # wrong shape
            "reports",
            3,
            True,
            [42],
            [{"reportedAt": 1, "categories": [14]}],
            [{"categories": [14]}],  # missing reportedAt
            [{"reportedAt": "2026-01-15T12:00:00+00:00"}],  # missing categories
        ],
    )
    def test_reports_wrong_shapes_rejected(self, bad: Any) -> None:
        """A missing, null, or wrongly shaped ``reports`` member is malformed."""
        with pytest.raises(ValidationError):
            AbuseIpdbCheckResponse.model_validate(check_data(reports=bad))

    def test_response_model_is_frozen(self) -> None:
        """The response model is immutable."""
        parsed = AbuseIpdbCheckResponse.model_validate(check_data())
        with pytest.raises(ValidationError):
            parsed.abuse_confidence_score = 0

    def test_ip_canonicalization(self) -> None:
        """The returned IP canonicalizes and accepts both families."""
        parsed = AbuseIpdbCheckResponse.model_validate(
            check_data(ipAddress="2001:0DB8:0000:0000:0000:0000:0000:0001", ipVersion=6)
        )
        assert parsed.ip_address == "2001:db8::1"
        for bad in ("999.999.999.999", "", "not-an-ip"):
            with pytest.raises(ValidationError):
                AbuseIpdbCheckResponse.model_validate(check_data(ipAddress=bad))


# -- Nullable required members ----------------------------------------------


@pytest.mark.unit
class TestAbuseIpdbNullableMembersSchema:
    """Schema tests for required members whose null values are valid facts."""

    @pytest.mark.parametrize("value", [True, False, None])
    def test_is_whitelisted_values_retained(self, value: bool | None) -> None:
        """Whitelist state true/false/null is retained as a source fact."""
        parsed = AbuseIpdbCheckResponse.model_validate(check_data(isWhitelisted=value))
        assert parsed.is_whitelisted is value

    @pytest.mark.parametrize("bad", ["true", 0, 1, [True], {"w": True}])
    def test_is_whitelisted_invalid_types_rejected(self, bad: Any) -> None:
        """Whitelist state accepts only strict booleans and null."""
        with pytest.raises(ValidationError):
            AbuseIpdbCheckResponse.model_validate(check_data(isWhitelisted=bad))

    def test_last_reported_at_missing_rejected(self) -> None:
        """A missing ``lastReportedAt`` member is malformed even though null is valid."""
        with pytest.raises(ValidationError):
            AbuseIpdbCheckResponse.model_validate(check_data(lastReportedAt=REMOVED))

    def test_last_reported_at_null_retained(self) -> None:
        """An explicit null ``lastReportedAt`` is valid and retained as ``None``."""
        parsed = AbuseIpdbCheckResponse.model_validate(check_data(lastReportedAt=None))
        assert parsed.last_reported_at is None


# -- Report entry schema ---------------------------------------------------


@pytest.mark.unit
class TestAbuseIpdbReportSchema:
    """Strict schema tests for the normalized report entry model."""

    def test_report_missing_required_members_rejected(self) -> None:
        """A report without ``reportedAt`` or without ``categories`` fails."""
        with pytest.raises(ValidationError):
            AbuseIpdbReport.model_validate({"categories": [14]})
        with pytest.raises(ValidationError):
            AbuseIpdbReport.model_validate({"reportedAt": "2026-01-15T12:00:00+00:00"})
        # The same holds through the full check-response path.
        for report in (
            {"categories": [14]},
            {"reportedAt": "2026-01-15T12:00:00+00:00"},
        ):
            with pytest.raises(ValidationError):
                AbuseIpdbCheckResponse.model_validate(check_data(reports=[report]))

    @pytest.mark.parametrize("bad", [0, -1, -100])
    def test_report_nonpositive_category_integers_rejected(self, bad: int) -> None:
        """Category codes must be positive integers; zero and negatives fail."""
        with pytest.raises(ValidationError):
            AbuseIpdbReport.model_validate(
                {
                    "reportedAt": "2026-01-15T12:00:00+00:00",
                    "categories": [14, bad],
                }
            )

    @pytest.mark.parametrize("bad", [True, False, 1.5, "18", None, [18], {"c": 18}])
    def test_report_category_non_integers_rejected(self, bad: Any) -> None:
        """Booleans, floats, strings, null, objects, and nested lists fail."""
        with pytest.raises(ValidationError):
            AbuseIpdbReport.model_validate(
                {
                    "reportedAt": "2026-01-15T12:00:00+00:00",
                    "categories": [bad],
                }
            )

    def test_report_category_one_and_positive_values_accepted(self) -> None:
        """Category code 1 and arbitrary positive identifiers are accepted."""
        report = AbuseIpdbReport.model_validate(
            {
                "reportedAt": "2026-01-15T12:00:00+00:00",
                "categories": [1, 23, 99, 1000],
            }
        )
        assert report.categories == [1, 23, 99, 1000]

    def test_report_categories_preserve_order_and_duplicates(self) -> None:
        """Category identifiers keep source order, including duplicates."""
        report = AbuseIpdbReport.model_validate(
            {
                "reportedAt": "2026-01-15T12:00:00+00:00",
                "categories": [22, 18, 22, 14, 14],
            }
        )
        assert report.categories == [22, 18, 22, 14, 14]

    def test_report_empty_categories_allowed(self) -> None:
        """A report may carry zero category codes."""
        report = AbuseIpdbReport.model_validate(
            {"reportedAt": "2026-01-15T12:00:00+00:00", "categories": []}
        )
        assert report.categories == []

    def test_report_comment_and_reporter_metadata_ignored(self) -> None:
        """Unconsumed report members never enter the normalized model."""
        report = AbuseIpdbReport.model_validate(dict(REPORT_ENTRY))
        assert not hasattr(report, "comment")
        assert not hasattr(report, "reporter_id")
        assert not hasattr(report, "reporter_country_code")
        assert not hasattr(report, "reporter_country_name")

    @pytest.mark.parametrize("ignored", _IGNORED_REPORT_MEMBERS)
    @pytest.mark.parametrize("wrong", [None, 1, True, [], ["US"], {"a": 1}])
    def test_report_ignored_members_wrong_shapes_ignored(
        self, ignored: str, wrong: Any
    ) -> None:
        """Ignored report members of any shape are ignored, never validated."""
        report = AbuseIpdbReport.model_validate(
            {
                "reportedAt": "2026-01-15T12:00:00+00:00",
                "categories": [14],
                ignored: wrong,
            }
        )
        assert not hasattr(report, ignored)


@pytest.mark.unit
class TestAbuseIpdbCheckResponseModel:
    """Model-level behavior tests for the check response model."""

    def test_empty_object_rejected(self) -> None:
        """An empty data object is malformed."""
        with pytest.raises(ValidationError):
            AbuseIpdbCheckResponse.model_validate({})

    def test_non_object_data_rejected(self) -> None:
        """Non-mapping data payloads are malformed."""
        bad_values: list[Any] = [[], "text", 1, True, None]
        for bad in bad_values:
            with pytest.raises(ValidationError):
                AbuseIpdbCheckResponse.model_validate(bad)
