# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 31F-2 failure-diagnostic utilities.

Covers the deterministic root-cause traversal (explicit cause, implicit
context, ``from None`` suppression, cycles, depth bounds, empty-message
fallback) and the ``ErrorMessageSanitizer`` pipeline (configured secret
values, Bearer/JWT/assignment/private-key/credential-URL redaction, control
characters, redaction-before-truncation, SQL/HTML text preservation).

All secret material used here is a conspicuous synthetic sentinel; no real
credential ever appears.
"""

from __future__ import annotations

from agentic_threat_investigator.app.error_messages import (
    REDACTED,
    ErrorMessageSanitizer,
    root_cause_exception,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    MAX_TIMELINE_ERROR_MESSAGE_LENGTH,
)

SENTINEL = "SENTINEL_SUPER_SECRET_7f3a"


def test_root_cause_unchained_exception_is_itself() -> None:
    """RC01: an unchained exception selects itself as the root cause."""
    error = ValueError("bad input")
    assert root_cause_exception(error) is error


def test_root_cause_follows_explicit_cause() -> None:
    """RC02: ``raise Outer from Inner`` selects the explicit inner cause."""
    try:
        try:
            raise ValueError("root")
        except ValueError as inner:
            raise RuntimeError("outer") from inner
    except RuntimeError as error:
        assert str(root_cause_exception(error)) == "root"


def test_root_cause_follows_implicit_context() -> None:
    """RC03: an implicit context chain selects the deepest context."""
    try:
        try:
            raise ValueError("root")
        except ValueError:
            # The implicit __context__ chaining is the behavior under test;
            # the outer raise must therefore not carry an explicit ``from``.
            raise RuntimeError("outer")  # noqa: B904 - implicit context is the point
    except RuntimeError as error:
        assert str(root_cause_exception(error)) == "root"


def test_root_cause_respects_suppressed_context() -> None:
    """RC04: ``raise ... from None`` never reveals the suppressed context."""
    try:
        try:
            raise ValueError("sensitive-inner-secret")
        except ValueError:
            raise RuntimeError("safe") from None
    except RuntimeError as error:
        assert str(root_cause_exception(error)) == "safe"


def test_root_cause_prefers_explicit_cause_over_context() -> None:
    """RC05: when both cause and context exist, the explicit cause wins."""
    error: RuntimeError
    try:
        try:
            raise ValueError("explicit-root")
        except ValueError as cause:
            try:
                raise LookupError("context-only") from None
            except LookupError:
                raise RuntimeError("outer") from cause
    except RuntimeError as caught:
        error = caught
    assert error.__cause__ is not None
    assert error.__context__ is not None
    assert str(root_cause_exception(error)) == "explicit-root"


def test_root_cause_terminates_on_cycle() -> None:
    """RC07: a pathological cycle terminates deterministically."""
    inner = ValueError("cycle")
    try:
        raise RuntimeError("outer") from inner
    except RuntimeError as error:
        chain = error
    inner.__cause__ = chain  # deliberately forge a cycle
    assert root_cause_exception(chain) is chain


def test_root_cause_stops_at_depth_bound() -> None:
    """RC08: a chain beyond the traversal bound stops deterministically."""
    head: BaseException = ValueError("deep-0")
    current = head
    for index in range(1, 60):
        try:
            raise RuntimeError(f"deep-{index}") from current
        except RuntimeError as error:
            current = error
    deepest = root_cause_exception(current, max_depth=8)
    # The traversal must terminate and never loop; the exact selected depth
    # is bounded by ``max_depth`` but the helper never raises.
    assert isinstance(deepest, BaseException)


def test_from_exception_uses_exception_type_fallback_for_blank_message() -> None:
    """RC06: an empty root message falls back to a safe type-based message."""

    class _BlankError(Exception):
        """Test-only blank exception."""

    sanitizer = ErrorMessageSanitizer()
    assert sanitizer.from_exception(_BlankError()) == "unexplained failure"


def test_sanitize_preserves_ordinary_text() -> None:
    """S01: ordinary diagnostic text is preserved."""
    sanitizer = ErrorMessageSanitizer()
    assert sanitizer.sanitize("provider returned an unexpected status") == (
        "provider returned an unexpected status"
    )


def test_sanitize_preserves_multiline_text() -> None:
    """S02: multiline ordinary text is preserved safely."""
    sanitizer = ErrorMessageSanitizer()
    assert sanitizer.sanitize("first line\nsecond line\tindented") == (
        "first line\nsecond line\tindented"
    )


def test_sanitize_redacts_configured_secret_values() -> None:
    """S03: an explicitly configured secret literal is redacted everywhere."""
    sanitizer = ErrorMessageSanitizer(known_secrets=(SENTINEL,))
    out = sanitizer.sanitize(f"connection failed with {SENTINEL} included")
    assert SENTINEL not in out
    assert REDACTED in out


def test_sanitize_redacts_bearer_tokens() -> None:
    """S04: ``Bearer <token>`` and ``Authorization: Bearer`` are redacted."""
    sanitizer = ErrorMessageSanitizer()
    out = sanitizer.sanitize(
        "HTTP 401 from Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    )
    assert "abcdefghijklmnopqrstuvwxyz0123456789" not in out
    assert "Bearer " + REDACTED in out


def test_sanitize_redacts_credential_assignments() -> None:
    """S05: password/api_key/apikey/token/secret assignments are redacted."""
    sanitizer = ErrorMessageSanitizer()
    out = sanitizer.sanitize(
        "login refused password=correct-horse-battery "
        "api_key=ak_test_123 token=ttt secret=sv "
        "apikey=xyzzy AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY"
    )
    for secret_literal in (
        "correct-horse-battery",
        "ak_test_123",
        "ttt",
        "sv",
        "xyzzy",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCY",
    ):
        assert secret_literal not in out
    assert "password " + REDACTED in out
    assert "api_key " + REDACTED in out


def test_sanitize_redacts_jwt_looking_tokens() -> None:
    """S06: compact JWT-looking tokens are redacted."""
    sanitizer = ErrorMessageSanitizer()
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXQiOiJ9.eyJmbXQiOiJmbXQiOiJ9"
    out = sanitizer.sanitize(f"decoded jwt {token} from callback")
    assert token not in out
    assert REDACTED in out


def test_sanitize_redacts_aws_access_key() -> None:
    """S07: AWS access-key identifiers are redacted."""
    sanitizer = ErrorMessageSanitizer()
    out = sanitizer.sanitize("s3 error key AKIAIOSFODNN7EXAMPLE bucket")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert REDACTED in out


def test_sanitize_redacts_pem_private_key_blocks() -> None:
    """S08: PEM private-key blocks/markers are redacted wholesale."""
    sanitizer = ErrorMessageSanitizer()
    block = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
        "-----END PRIVATE KEY-----"
    )
    out = sanitizer.sanitize(f"stored {block} locally")
    assert "MIIEvQIBADAN" not in out
    assert REDACTED in out
    assert "BEGIN PRIVATE KEY" not in out


def test_sanitize_redacts_credential_urls_only() -> None:
    """S09: user:password@ in URLs is redacted; host/path survive."""
    sanitizer = ErrorMessageSanitizer()
    out = sanitizer.sanitize("fetch https://alice:hunter2@example.test/path failed")
    assert "alice:hunter2@" not in out
    assert "hunter2" not in out
    assert "https://" + REDACTED + "@example.test/path" in out


def test_sanitize_keeps_sql_looking_text() -> None:
    """S10: SQL-looking text is retained, never keyword-stripped."""
    sanitizer = ErrorMessageSanitizer()
    sql = "insert into users (name) values ('bob'); select * from audit;"
    assert sanitizer.sanitize(sql) == sql


def test_sanitize_keeps_markup_looking_text() -> None:
    """S11: HTML/script-looking text is stored as text, not stripped."""
    sanitizer = ErrorMessageSanitizer()
    markup = "<script>alert('x')</script> <b>bold</b>&copy;"
    assert sanitizer.sanitize(markup) == markup


def test_sanitize_normalizes_control_characters() -> None:
    """S12: terminal/control characters are normalized/removed."""
    sanitizer = ErrorMessageSanitizer()
    out = sanitizer.sanitize("line1\x00\x1b[31mline2\x07\r\nline3")
    assert "\x00" not in out
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "\r" not in out
    assert "\n" in out
    assert "line1" in out and "line2" in out and "line3" in out


def test_sanitize_redacts_before_truncation() -> None:
    """S13: a secret near the end is redacted before truncation applies."""
    sanitizer = ErrorMessageSanitizer()
    text = "A" * (MAX_TIMELINE_ERROR_MESSAGE_LENGTH + 100) + " password=tail-secret"
    out = sanitizer.sanitize(text)
    assert len(out) <= MAX_TIMELINE_ERROR_MESSAGE_LENGTH
    assert "tail-secret" not in out
    assert out.endswith("…")


def test_sanitize_returns_blank_for_blank_input() -> None:
    """S14: empty/whitespace text never becomes a non-blank diagnostic."""
    sanitizer = ErrorMessageSanitizer()
    assert sanitizer.sanitize("") == ""
    assert sanitizer.sanitize("   \n\t ") == ""


def test_sanitize_preserves_unicode_within_bound() -> None:
    """S15: Unicode diagnostics survive within the bound."""
    sanitizer = ErrorMessageSanitizer()
    text = "détection d'intrusion ✔ — 已分析"
    assert sanitizer.sanitize(text) == text


def test_sanitize_bounds_over_limit_text_without_secret() -> None:
    """Truncation applies the deterministic marker and never exceeds the max."""
    sanitizer = ErrorMessageSanitizer(max_length=64)
    out = sanitizer.sanitize("z" * 200)
    assert len(out) == 64
    assert out.endswith("…")
    assert out == "z" * 63 + "…"


def test_sanitizer_ignores_blank_known_secrets() -> None:
    """Blank configured secret values never affect the pipeline."""
    sanitizer = ErrorMessageSanitizer(known_secrets=("", "  "))
    assert sanitizer.sanitize("plain text") == "plain text"
