# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""RDAP domain identity contract tests for LDH and Unicode name members.

Every supplied domain identity member (``ldhName`` and ``unicodeName``)
must canonicalize to the queried canonical domain; malformed or
contradictory identity data must never become evidence.
"""

from __future__ import annotations

import pytest

from agentic_threat_investigator.domain.entities import Entity, EntityType

from .rdap_contract_helpers import _assert_invalid_with_request_budget, _domain_result
from .test_rdap_strict_models import _domain_payload


@pytest.mark.unit
@pytest.mark.provider_contract
@pytest.mark.asyncio
class TestRdapDomainIdentityContract:
    """Domain identity must hold for every supplied LDH/Unicode name member."""

    async def test_unicode_only_response_matching_idna_query(self) -> None:
        """A Unicode-only response matching the IDNA query yields evidence."""
        payload = _domain_payload(handle="")
        del payload["ldhName"]
        payload["unicodeName"] = "exämple.com"
        result = await _domain_result(payload, value="exämple.com")
        assert len(result.evidence) == 1
        facts = result.evidence[0].facts
        assert facts["unicode_name"] == "exämple.com"
        assert "ldh_name" not in facts
        assert result.evidence[0].source_record_id == "xn--exmple-cua.com"

    async def test_unicode_name_preserves_trimmed_provider_form(self) -> None:
        """The unicode_name fact keeps the trimmed provider Unicode form."""
        payload = _domain_payload(
            ldhName="xn--exmple-cua.com", unicodeName="  Exämple.com  "
        )
        result = await _domain_result(payload, value="exämple.com")
        assert len(result.evidence) == 1
        assert result.evidence[0].facts["unicode_name"] == "Exämple.com"
        assert result.evidence[0].facts["ldh_name"] == "xn--exmple-cua.com"

    async def test_unicode_only_response_for_different_domain_rejected(self) -> None:
        """A Unicode name identifying another domain is INVALID_RESPONSE."""
        # Only the bootstrap and the single authoritative lookup; no retries
        # and no additional lookups after the contradictory identity.
        await _assert_invalid_with_request_budget(
            _domain_payload(ldhName=None, unicodeName="other.com"),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )

    async def test_malformed_unicode_dns_syntax_rejected(self) -> None:
        """Malformed Unicode DNS syntax is a schema error, never evidence."""
        for bad_unicode in ["bad label.com", "a..b.com", "   ", "bad_label.com"]:
            await _assert_invalid_with_request_budget(
                _domain_payload(ldhName=None, unicodeName=bad_unicode),
                Entity(type=EntityType.DOMAIN, value="example.com"),
            )

    async def test_matching_ldh_and_unicode_forms_accepted(self) -> None:
        """Both names supplied in agreement canonicalize to one identity."""
        payload = _domain_payload(
            ldhName="xn--exmple-cua.com", unicodeName="exämple.com"
        )
        result = await _domain_result(payload, value="exämple.com")
        assert len(result.evidence) == 1
        facts = result.evidence[0].facts
        assert facts["ldh_name"] == "xn--exmple-cua.com"
        assert facts["unicode_name"] == "exämple.com"

    async def test_contradictory_ldh_and_unicode_forms_rejected(self) -> None:
        """LDH and Unicode names identifying different domains are INVALID_RESPONSE."""
        await _assert_invalid_with_request_budget(
            _domain_payload(ldhName="example.com", unicodeName="other.com"),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )

    async def test_wrong_unicode_idna_query_mismatch_rejected(self) -> None:
        """A Unicode identity that mismatchs the queried IDNA form is rejected."""
        await _assert_invalid_with_request_budget(
            _domain_payload(ldhName=None, unicodeName="exämple.com"),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )

    async def test_ldh_only_identity_mismatch_still_rejected(self) -> None:
        """The pre-existing LDH-only identity check continues to reject."""
        await _assert_invalid_with_request_budget(
            _domain_payload(ldhName="other.com"),
            Entity(type=EntityType.DOMAIN, value="example.com"),
        )
