# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for application-layer provider contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.providers import (
    ProviderError,
    ProviderErrorCode,
    ProviderResult,
    validate_investigation_entity,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from tests.support.providers import FakeEvidenceProvider


class TestProviderErrorCode:
    """ProviderErrorCode enum values and retryable semantics."""

    def test_retryable_codes(self) -> None:
        """Timeout, rate-limited, and unavailable are inherently retryable."""
        assert ProviderErrorCode.TIMEOUT.retryable is True
        assert ProviderErrorCode.RATE_LIMITED.retryable is True
        assert ProviderErrorCode.PROVIDER_UNAVAILABLE.retryable is True

    def test_non_retryable_codes(self) -> None:
        """Authentication, forbidden, not-found, unsupported, and invalid are not."""
        assert ProviderErrorCode.AUTHENTICATION_FAILED.retryable is False
        assert ProviderErrorCode.FORBIDDEN.retryable is False
        assert ProviderErrorCode.NOT_FOUND.retryable is False
        assert ProviderErrorCode.UNSUPPORTED_INDICATOR.retryable is False
        assert ProviderErrorCode.INVALID_RESPONSE.retryable is False


class TestProviderError:
    """ProviderError model validation."""

    def test_minimal_valid(self) -> None:
        """A basic provider error with required fields is accepted."""
        err = ProviderError(
            provider="urn:ati:source:test",
            code=ProviderErrorCode.TIMEOUT,
            message="request timed out",
            retryable=True,
        )
        assert err.provider == "urn:ati:source:test"
        assert err.retry_after_seconds is None

    def test_retry_after_nonnegative(self) -> None:
        """A nonnegative retry_after_seconds is accepted."""
        err = ProviderError(
            provider="urn:ati:source:test",
            code=ProviderErrorCode.RATE_LIMITED,
            message="rate limited",
            retryable=True,
            retry_after_seconds=30,
        )
        assert err.retry_after_seconds == 30

    def test_negative_retry_after_rejected(self) -> None:
        """A negative retry_after_seconds is rejected."""
        with pytest.raises(ValidationError, match="nonnegative"):
            ProviderError(
                provider="urn:ati:source:test",
                code=ProviderErrorCode.RATE_LIMITED,
                message="rate limited",
                retryable=True,
                retry_after_seconds=-1,
            )

    def test_blank_provider_rejected(self) -> None:
        """A blank provider value is rejected."""
        with pytest.raises(ValidationError, match="blank"):
            ProviderError(
                provider="",
                code=ProviderErrorCode.TIMEOUT,
                message="timeout",
                retryable=True,
            )

    def test_blank_message_rejected(self) -> None:
        """A blank message is rejected."""
        with pytest.raises(ValidationError, match="blank"):
            ProviderError(
                provider="urn:ati:source:test",
                code=ProviderErrorCode.TIMEOUT,
                message="",
                retryable=True,
            )

    def test_retryable_natural_consistency_timeout(self) -> None:
        """A TIMEOUT with retryable=False is rejected."""
        with pytest.raises(ValidationError, match="inherently retryable"):
            ProviderError(
                provider="urn:ati:source:test",
                code=ProviderErrorCode.TIMEOUT,
                message="timeout",
                retryable=False,
            )

    def test_non_urn_provider_rejected(self) -> None:
        """Provider identifiers must be stable ATI source URNs."""
        with pytest.raises(ValidationError, match="ATI source URN"):
            ProviderError(
                provider="not-a-urn",
                code=ProviderErrorCode.NOT_FOUND,
                message="not found",
                retryable=False,
            )
        with pytest.raises(ValidationError, match="ATI source URN"):
            ProviderResult(provider="not-a-urn")

    def test_retryable_natural_consistency_not_found(self) -> None:
        """A NOT_FOUND with retryable=True is rejected."""
        with pytest.raises(ValidationError, match="not retryable"):
            ProviderError(
                provider="urn:ati:source:test",
                code=ProviderErrorCode.NOT_FOUND,
                message="not found",
                retryable=True,
            )

    def test_frozen(self) -> None:
        """ProviderError instances are frozen."""
        err = ProviderError(
            provider="urn:ati:source:test",
            code=ProviderErrorCode.TIMEOUT,
            message="timeout",
            retryable=True,
        )
        with pytest.raises(ValidationError):
            err.message = "changed"


class TestProviderResult:
    """ProviderResult model validation."""

    def test_valid_empty(self) -> None:
        """A valid empty result with no evidence and no errors is accepted."""
        result = ProviderResult(provider="urn:ati:source:test")
        assert result.evidence == ()
        assert result.errors == ()

    def test_evidence_provider_mismatch_rejected(self) -> None:
        """Evidence with a different source than the result provider is rejected."""
        inv_id = uuid4()
        evidence = Evidence(
            investigation_id=inv_id,
            type=EvidenceType.DNS,
            subject=EvidenceEntityRef(type=EntityType.DOMAIN, value="example.com"),
            source="urn:ati:source:other",
            retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
            facts={"query_name": "example.com", "query_type": "A"},
        )
        with pytest.raises(ValidationError, match="does not match"):
            ProviderResult(provider="urn:ati:source:rdap", evidence=(evidence,))

    def test_error_provider_mismatch_rejected(self) -> None:
        """Errors with a different provider than the result are rejected."""
        err = ProviderError(
            provider="urn:ati:source:other",
            code=ProviderErrorCode.TIMEOUT,
            message="timeout",
            retryable=True,
        )
        with pytest.raises(ValidationError, match="does not match"):
            ProviderResult(provider="urn:ati:source:rdap", errors=(err,))

    def test_frozen(self) -> None:
        """ProviderResult instances are frozen."""
        result = ProviderResult(provider="urn:ati:source:test")
        with pytest.raises(ValidationError):
            result.provider = "changed"

    def test_extra_fields_forbidden(self) -> None:
        """Extra fields on ProviderResult are rejected."""
        with pytest.raises(ValidationError, match="extra"):
            ProviderResult(
                provider="urn:ati:source:test",
                extra_field="x",  # type: ignore[call-arg]
            )

    def test_valid_mixed_result_with_evidence_and_errors(self) -> None:
        """A result containing both evidence and errors from the same provider is valid."""
        inv_id = uuid4()
        evidence = Evidence(
            investigation_id=inv_id,
            type=EvidenceType.DNS,
            subject=EvidenceEntityRef(type=EntityType.DOMAIN, value="example.com"),
            source="urn:ati:source:test",
            retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
            facts={"query_name": "example.com", "query_type": "A"},
        )
        err = ProviderError(
            provider="urn:ati:source:test",
            code=ProviderErrorCode.TIMEOUT,
            message="timeout on secondary query",
            retryable=True,
        )
        result = ProviderResult(
            provider="urn:ati:source:test",
            evidence=(evidence,),
            errors=(err,),
        )
        assert len(result.evidence) == 1
        assert len(result.errors) == 1


class TestFakeEvidenceProviderContract:
    """The fake must honor the behavioral contract of the ABC."""

    @staticmethod
    def _canned_evidence() -> Evidence:
        """Build one Evidence record attributed to the fake provider."""
        return Evidence(
            investigation_id=uuid4(),
            type=EvidenceType.DNS,
            subject=EvidenceEntityRef(type=EntityType.DOMAIN, value="example.com"),
            source=FakeEvidenceProvider.SOURCE_URN,
            retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
            facts={"query_name": "example.com", "query_type": "A"},
        )

    @pytest.mark.asyncio
    async def test_supported_call_returns_canned_result(self) -> None:
        """A supported, valid entity receives the configured canned result."""
        result = ProviderResult(
            provider=FakeEvidenceProvider.SOURCE_URN,
            evidence=(self._canned_evidence(),),
        )
        provider = FakeEvidenceProvider(result=result, record_calls=True)
        got = await provider.investigate(
            uuid4(), Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert got == result
        assert len(got.evidence) == 1

    @pytest.mark.asyncio
    async def test_unsupported_call_returns_error_never_canned_evidence(self) -> None:
        """An unsupported entity type yields one UNSUPPORTED_INDICATOR, no evidence."""
        result = ProviderResult(
            provider=FakeEvidenceProvider.SOURCE_URN,
            evidence=(self._canned_evidence(),),
        )
        provider = FakeEvidenceProvider(result=result)
        got = await provider.investigate(
            uuid4(), Entity(type=EntityType.IP_ADDRESS, value="1.1.1.1")
        )
        assert len(got.errors) == 1
        assert got.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert got.errors[0].retryable is False
        assert got.errors[0].provider == FakeEvidenceProvider.SOURCE_URN
        assert len(got.evidence) == 0

    @pytest.mark.asyncio
    async def test_invalid_supported_value_returns_unsupported_indicator(self) -> None:
        """A supported type with a non-canonicalizable value is also rejected."""
        provider = FakeEvidenceProvider()
        got = await provider.investigate(
            uuid4(), Entity(type=EntityType.DOMAIN, value="   ")
        )
        assert len(got.errors) == 1
        assert got.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert len(got.evidence) == 0

    @pytest.mark.asyncio
    async def test_call_recording_covers_unsupported_dispatches(self) -> None:
        """Every invocation is recorded when recording is enabled."""
        provider = FakeEvidenceProvider(record_calls=True)
        inv_id = uuid4()
        await provider.investigate(
            inv_id, Entity(type=EntityType.DOMAIN, value="example.com")
        )
        unsupported = Entity(type=EntityType.IP_ADDRESS, value="1.1.1.1")
        await provider.investigate(inv_id, unsupported)
        assert len(provider.calls) == 2
        assert provider.calls[0][0] == inv_id
        assert provider.calls[1][1] == unsupported

    @pytest.mark.asyncio
    async def test_no_recording_by_default(self) -> None:
        """Calls are not recorded when recording is disabled."""
        provider = FakeEvidenceProvider()
        await provider.investigate(
            uuid4(), Entity(type=EntityType.DOMAIN, value="example.com")
        )
        assert provider.calls == ()

    def test_mismatched_canned_provider_rejected(self) -> None:
        """A canned result from another provider is rejected at construction."""
        result = ProviderResult(provider="urn:ati:source:other")
        with pytest.raises(ValueError, match="does not match"):
            FakeEvidenceProvider(result=result)


class TestSharedDomainValidationOrdering:
    """Shared validation inspects original domain values strictly.

    The domain path must use strict DNS-name validation on the original
    entity value so valid case/whitespace/single-root-dot/IDNA renderings
    canonicalize while repeated terminal dots are rejected before the lossy
    persistence-oriented canonicalizer can silently repair them.
    """

    @pytest.mark.parametrize(
        ("raw", "canonical"),
        [
            ("example.com", "example.com"),
            ("  EXAMPLE.COM  ", "example.com"),
            ("Example.COM.", "example.com"),
            ("Bücher.Example.", "xn--bcher-kva.example"),
            ("COM.", "com"),
        ],
    )
    def test_valid_domain_forms_canonicalize(self, raw: str, canonical: str) -> None:
        """Valid renderings return the strict canonical value, no error."""
        value, error_result = validate_investigation_entity(
            FakeEvidenceProvider(), Entity(type=EntityType.DOMAIN, value=raw)
        )
        assert error_result is None
        assert value == canonical

    @pytest.mark.parametrize(
        "raw",
        ["example.com..", "example.com...", "bücher.example.."],
    )
    def test_repeated_terminal_dots_rejected(self, raw: str) -> None:
        """Repeated terminal dots yield one non-retryable UNSUPPORTED_INDICATOR."""
        value, error_result = validate_investigation_entity(
            FakeEvidenceProvider(), Entity(type=EntityType.DOMAIN, value=raw)
        )
        assert value is None
        assert error_result is not None
        assert error_result.provider == FakeEvidenceProvider.SOURCE_URN
        assert error_result.evidence == ()
        [error] = error_result.errors
        assert error.provider == FakeEvidenceProvider.SOURCE_URN
        assert error.code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert error.retryable is False

    @pytest.mark.asyncio
    async def test_repeated_terminal_dots_never_receive_canned_result(self) -> None:
        """An invalid domain through the ABC never returns canned evidence."""
        result = ProviderResult(
            provider=FakeEvidenceProvider.SOURCE_URN,
            evidence=(
                Evidence(
                    investigation_id=uuid4(),
                    type=EvidenceType.DNS,
                    subject=EvidenceEntityRef(
                        type=EntityType.DOMAIN, value="example.com"
                    ),
                    source=FakeEvidenceProvider.SOURCE_URN,
                    retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
                    facts={"query_name": "example.com", "query_type": "A"},
                ),
            ),
        )
        provider = FakeEvidenceProvider(result=result)
        got = await provider.investigate(
            uuid4(), Entity(type=EntityType.DOMAIN, value="example.com..")
        )
        assert len(got.evidence) == 0
        assert len(got.errors) == 1
        assert got.errors[0].code == ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert got.errors[0].retryable is False


class TestEvidenceProvider:
    """EvidenceProvider ABC contract."""

    @pytest.mark.asyncio
    async def test_supports_deterministic(self) -> None:
        """The fake provider supports only DOMAIN entities."""
        provider = FakeEvidenceProvider()
        domain = Entity(type=EntityType.DOMAIN, value="example.com")
        ip = Entity(type=EntityType.IP_ADDRESS, value="1.1.1.1")
        assert provider.supports(domain) is True
        assert provider.supports(ip) is False

    @pytest.mark.asyncio
    async def test_investigate_returns_result(self) -> None:
        """Investigate returns the configured ProviderResult."""
        result = ProviderResult(
            provider="urn:ati:source:test",
            errors=(
                ProviderError(
                    provider="urn:ati:source:test",
                    code=ProviderErrorCode.TIMEOUT,
                    message="timeout",
                    retryable=True,
                ),
            ),
        )
        provider = FakeEvidenceProvider(result=result)
        domain = Entity(type=EntityType.DOMAIN, value="example.com")
        got = await provider.investigate(uuid4(), domain)
        assert got == result
        assert len(got.errors) == 1

    @pytest.mark.asyncio
    async def test_id_is_stable(self) -> None:
        """The provider ID is a stable identifier."""
        provider = FakeEvidenceProvider()
        assert provider.id == "urn:ati:source:test"
