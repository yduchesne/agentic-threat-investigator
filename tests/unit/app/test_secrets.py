# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the documented secret-resolution abstraction."""

from __future__ import annotations

import pytest

from agentic_threat_investigator.app.secrets import (
    EnvVarSecretsResolver,
    SecretNotFoundError,
    SecretsResolver,
)

_FAKE_SECRET_VALUE = "fake-test-credential"


class _MappingResolver(SecretsResolver):
    """Deterministic resolver backed by an explicit in-memory mapping."""

    def __init__(self, values: dict[str, str]) -> None:
        """Initialize with the reference-to-value mapping."""
        self._values = values

    def get(self, name: str) -> str | None:
        """Return the mapping value for a reference name."""
        return self._values.get(name)


class TestSecretsResolverContract:
    """The SecretsResolver contract behavior required by CONFIGURATION.md."""

    def test_get_returns_mapped_value(self) -> None:
        """``get`` returns the mapped value for a known reference name."""
        resolver = _MappingResolver({"SECRET_REF": _FAKE_SECRET_VALUE})
        assert resolver.get("SECRET_REF") == _FAKE_SECRET_VALUE

    def test_get_returns_none_for_absent_name(self) -> None:
        """``get`` returns ``None`` for an unknown reference name."""
        resolver = _MappingResolver({})
        assert resolver.get("MISSING_REF") is None

    def test_require_returns_existing_value(self) -> None:
        """``require`` returns the mapped value for a known reference name."""
        resolver = _MappingResolver({"SECRET_REF": _FAKE_SECRET_VALUE})
        assert resolver.require("SECRET_REF") == _FAKE_SECRET_VALUE

    def test_require_raises_for_absent_name(self) -> None:
        """``require`` raises ``SecretNotFoundError`` for an unknown name."""
        resolver = _MappingResolver({})
        with pytest.raises(SecretNotFoundError):
            resolver.require("MISSING_REF")

    def test_not_found_error_names_only_the_reference(self) -> None:
        """The error names the reference, never a resolved value."""
        error = SecretNotFoundError("SECRET_REF")
        assert "SECRET_REF" in str(error)
        assert _FAKE_SECRET_VALUE not in str(error)


class TestEnvVarSecretsResolver:
    """The environment-backed v0.1 resolver."""

    def test_get_returns_environment_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``get`` reads the reference from the injected environment mapping."""
        monkeypatch.setenv("SECRET_REF", _FAKE_SECRET_VALUE)
        resolver = EnvVarSecretsResolver()
        assert resolver.get("SECRET_REF") == _FAKE_SECRET_VALUE

    def test_get_returns_none_without_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``get`` returns ``None`` when the environment lacks the reference."""
        monkeypatch.delenv("SECRET_REF", raising=False)
        resolver = EnvVarSecretsResolver()
        assert resolver.get("SECRET_REF") is None

    def test_injected_mapping_used_deterministically(self) -> None:
        """An injected mapping resolves deterministically without process env."""
        resolver = EnvVarSecretsResolver(env={"SECRET_REF": _FAKE_SECRET_VALUE})
        assert resolver.require("SECRET_REF") == _FAKE_SECRET_VALUE
        assert resolver.get("OTHER_REF") is None
