# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Host-response URL identity-contract unit tests for the URLhaus provider.

Every host-response ``urls[]`` URL must pass the complete shared ATI
``canonicalize_url()`` identity contract: one malformed or unrelated URL
invalidates the entire response, and accepted records emit canonical URL
facts.
"""

# The URLhaus test modules deliberately mirror the established
# provider-family test shapes (see ThreatFox/AbuseIPDB); per-block R0801
# suppression is not supported by Pylint, so duplicate-code is disabled at
# module scope for the deliberately accepted duplication.
# pylint: disable=duplicate-code

from __future__ import annotations

import httpx
import pytest

from tests.support.urlhaus_fixtures import (
    CANONICAL_URLHAUS_IPV4,
    FIXED_KEY,
    investigate,
    urlhaus_host_response,
    urlhaus_host_url_record,
    urlhaus_url_record,
)
from tests.unit.infrastructure.providers.test_urlhaus import (
    _DOMAIN_ENTITY,
    _IPV4_ENTITY,
    _URL_ENTITY,
    _assert_invalid_response,
)

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


@pytest.mark.unit
class TestHostRecordUrlIdentityContract:
    """Every host-response URL must pass the complete ATI URL contract."""

    @pytest.mark.parametrize(
        "malformed_url",
        [
            "ftp://malicious-domain.test/x",
            "http://user@malicious-domain.test/x",
            "http://user:pass@malicious-domain.test/x",
            "http://malicious-domain.test/x#fragment",
            "http://malicious-domain.test/x#",
            "http://malicious-domain.test/%zz",
            "http://malicious-domain.test/%2",
            "http://malicious-domain.test/pa th",
            "http://malicious-domain.test:0/x",
        ],
    )
    async def test_malformed_host_record_url_is_typed_error(
        self, malformed_url: str
    ) -> None:
        """A host record URL outside the identity contract invalidates all."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(url=malformed_url), url_count="1"
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_invalid_response(result)
        # The error never carries the returned URL or the Auth-Key.
        assert malformed_url not in result.errors[0].message
        assert FIXED_KEY not in result.errors[0].message

    async def test_mixed_valid_and_malformed_records_no_partial_evidence(
        self,
    ) -> None:
        """One malformed record invalidates the response beside a valid one."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(),
            urlhaus_host_url_record(id="556678", url="http://malicious-domain.test/x#"),
            url_count="2",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_invalid_response(result)

    async def test_canonical_equivalent_host_record_url_accepted(self) -> None:
        """An equivalent spelling is accepted and emitted in canonical form."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(
                url="HTTP://MALICIOUS-domain.test:80/download/payload.bin"
            ),
            url_count="1",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.errors == ()
        match = result.evidence[0].facts["matches"][0]
        assert match["url"] == "http://malicious-domain.test/download/payload.bin"
        assert match["host"] is None

    async def test_host_record_preserves_significant_url_components(self) -> None:
        """Path, query order, non-default ports, and escapes are preserved."""
        source_url = "http://malicious-domain.test:8080/a%20b?b=2&a=1"
        payload = urlhaus_host_response(
            urlhaus_host_url_record(url=source_url), url_count="1"
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.errors == ()
        match = result.evidence[0].facts["matches"][0]
        assert match["url"] == source_url

    async def test_valid_ipv4_host_record_url_remains_accepted(self) -> None:
        """A canonical IPv4-host record URL remains a valid host hit."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(url="http://203.0.113.42/payload.bin"),
            url_count="1",
            host=CANONICAL_URLHAUS_IPV4,
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_IPV4_ENTITY
        )
        assert result.errors == ()
        match = result.evidence[0].facts["matches"][0]
        assert match["url"] == "http://203.0.113.42/payload.bin"

    async def test_direct_match_url_is_emitted_canonically(self) -> None:
        """The direct lookup also emits the canonical URL fact."""
        record = urlhaus_url_record(
            url="HTTP://MALICIOUS-domain.test:80/download/payload.bin"
        )
        result = await investigate(httpx.Response(200, json=record), entity=_URL_ENTITY)
        assert result.errors == ()
        assert (
            result.evidence[0].facts["matches"][0]["url"]
            == "http://malicious-domain.test/download/payload.bin"
        )


# -- Remediation 03: duplicate comparison on consumed normalized content --------


@pytest.mark.unit
class TestCanonicalEquivalentDuplicateRecords:
    """Same-ID duplicates compare consumed normalized content, not raw URLs."""

    async def test_canonical_equivalent_duplicate_is_omitted(self) -> None:
        """Same-ID records differing only by canonical URL equivalence collapse."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(
                id="556677",
                url="HTTP://MALICIOUS-domain.test:80/download/payload.bin",
            ),
            urlhaus_host_url_record(id="556677"),
            url_count="1",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.errors == ()
        assert len(result.evidence) == 1
        matches = result.evidence[0].facts["matches"]
        assert len(matches) == 1
        match = matches[0]
        # First occurrence keeps the output position; the emitted URL is
        # the canonical lowercase HTTP form without the default port.
        assert match["urlhaus_id"] == "556677"
        assert match["url"] == "http://malicious-domain.test/download/payload.bin"

    async def test_terminal_root_dot_duplicate_is_omitted(self) -> None:
        """A terminal DNS root dot is canonical equivalence, not a conflict."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(
                id="556677",
                url="http://malicious-domain.test./download/payload.bin",
            ),
            urlhaus_host_url_record(id="556677"),
            url_count="1",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        assert result.errors == ()
        matches = result.evidence[0].facts["matches"]
        assert len(matches) == 1
        assert matches[0]["url"] == "http://malicious-domain.test/download/payload.bin"

    async def test_default_port_duplicate_on_ipv4_host_is_omitted(self) -> None:
        """The default-port omission is canonical equivalence for IPv4 URLs."""
        result = await investigate(
            httpx.Response(
                200,
                json=urlhaus_host_response(
                    urlhaus_host_url_record(
                        id="556678", url="http://203.0.113.42:80/payload.bin"
                    ),
                    urlhaus_host_url_record(
                        id="556678", url="http://203.0.113.42/payload.bin"
                    ),
                    url_count="1",
                    host=CANONICAL_URLHAUS_IPV4,
                ),
            ),
            entity=_IPV4_ENTITY,
        )
        assert result.errors == ()
        matches = result.evidence[0].facts["matches"]
        assert len(matches) == 1
        assert matches[0]["url"] == "http://203.0.113.42/payload.bin"

    @pytest.mark.parametrize(
        ("first_url", "second_url"),
        [
            (
                "http://malicious-domain.test/download/payload-a.bin",
                "http://malicious-domain.test/download/payload-b.bin",
            ),
            (
                "http://malicious-domain.test/p?a=1&b=2",
                "http://malicious-domain.test/p?b=2&a=1",
            ),
            (
                "http://malicious-domain.test/p%2fx",
                "http://malicious-domain.test/p%2Fx",
            ),
        ],
    )
    async def test_meaningful_url_difference_still_conflicts(
        self, first_url: str, second_url: str
    ) -> None:
        """Security-significant canonical URL differences remain conflicts."""
        payload = urlhaus_host_response(
            urlhaus_host_url_record(id="556677", url=first_url),
            urlhaus_host_url_record(id="556677", url=second_url),
            url_count="2",
        )
        result = await investigate(
            httpx.Response(200, json=payload), entity=_DOMAIN_ENTITY
        )
        _assert_invalid_response(result)
        assert "556677" not in result.errors[0].message
        assert first_url not in result.errors[0].message
        assert FIXED_KEY not in result.errors[0].message
