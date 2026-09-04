# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests pinning the application service compatibility exports."""

from agentic_threat_investigator import app
from agentic_threat_investigator.app import identity
from agentic_threat_investigator.app.services import (
    authentication,
    password,
    rate_limit,
    session,
)


def test_document_indexing_contracts_are_public() -> None:
    """PR 10 application ports and service are available from the public API."""
    assert app.EmbeddingClient.__name__ == "EmbeddingClient"
    assert app.DocumentBuilder.__name__ == "DocumentBuilder"
    assert app.DocumentIndexingService.__name__ == "DocumentIndexingService"
    assert app.TokenBoundedChunker.__name__ == "TokenBoundedChunker"


def test_authentication_service_reexports_identity_symbols() -> None:
    """The authentication service module re-exports the identity services."""
    assert authentication.AuthenticationError is identity.AuthenticationError
    assert authentication.AuthenticationService is identity.AuthenticationService


def test_password_service_reexports_hashers() -> None:
    """The password service module re-exports the hashing ports."""
    assert password.Argon2idPasswordHasher is identity.Argon2idPasswordHasher
    assert password.PasswordHasher is identity.PasswordHasher


def test_session_service_reexports_the_token_service() -> None:
    """The session service module re-exports the token service."""
    assert session.SessionTokenService is identity.SessionTokenService


def test_rate_limit_module_imports_without_members() -> None:
    """The compatibility rate-limit module imports cleanly."""
    assert rate_limit.__doc__ is not None
