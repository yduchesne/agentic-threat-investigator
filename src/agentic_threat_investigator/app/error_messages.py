# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-owned failure diagnostic derivation and sanitization (PR 31F-2).

Two narrow, deterministic helpers live here:

- :func:`root_cause_exception` selects the legitimate root cause of an
  exception chain, honoring Python's explicit ``__cause__`` /
  ``__context__`` chaining semantics, ``__suppress_context__`` (``raise ...
  from None``), and defensive cycle/depth bounds. It never serializes the
  chain or a traceback.
- :class:`ErrorMessageSanitizer` turns one diagnostic message (or one caught
  exception) into a bounded, secret-free string that is safe to persist and
  display on analyst-facing surfaces within the documented threat model.

Invariants:

- Sanitization happens **before** persistence and **before** truncation.
- The sanitizer performs deterministic defense-in-depth redaction of common
  credential/token shapes and of explicitly supplied known secret values. It
  is not a DLP system and makes no claim of perfect secret recognition.
- Ordinary diagnostic text — including SQL-looking or HTML-looking prose —
  is never keyword-stripped. Injection safety remains contextual (bounded
  parameterized persistence, text rendering in React).
- Unsafe control characters are normalized/removed; ordinary printable
  Unicode and line breaks are preserved so multiline diagnostics display.
- No logging, persistence, configuration lookup, or side effects live here.

Cancellation is deliberately never converted into a diagnostic: callers must
continue to let ``asyncio.CancelledError`` propagate.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence

from agentic_threat_investigator.domain.investigation_timeline import (
    MAX_TIMELINE_ERROR_MESSAGE_LENGTH,
)

#: Deterministic marker for redacted secret material.
REDACTED = "<redacted>"

#: Deterministic truncation marker appended when a diagnostic exceeds the
#: persisted maximum. The final value never exceeds the domain maximum.
TRUNCATION_MARKER = "…"

#: Default hard bound on root-cause chain traversal. Normal chains are short;
#: the bound exists purely to defeat pathological/deeply nested chains.
DEFAULT_ROOT_CAUSE_MAX_DEPTH = 16

# Fallback surfaced when the selected root cause has an empty message.
_EMPTY_MESSAGE_FALLBACK = "unexplained failure"

# The assignment-name vocabulary redacted by the deterministic pattern. Each
# name is matched case-insensitively with word boundaries and flexible
# separators (``api_key``, ``api-key``, ``APIKEY`` all match).
_SECRET_ASSIGNMENT_NAMES = (
    "password",
    "passwd",
    "pwd",
    "api[_-]?key",
    "apikey",
    "access[_-]?key",
    "access[_-]?token",
    "refresh[_-]?token",
    "auth[_-]?token",
    "client[_-]?secret",
    "aws[_-]?access[_-]?key[_-]?id",
    "aws[_-]?secret[_-]?access[_-]?key",
    "token",
    "secret",
)

_BEARER_TOKEN_RE = re.compile(
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+",
)
"""Bearer-prefixed credential tokens (``Authorization: Bearer ...``)."""

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(" + "|".join(_SECRET_ASSIGNMENT_NAMES) + r")\b\s*[=:]\s*\S+",
)
"""Case-insensitive ``name=value`` credential assignments."""

_JWT_RE = re.compile(
    r"(?i)\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
)
"""Compact JWT-looking tokens (three dot-separated base64url segments)."""

_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
"""AWS access-key identifiers (deterministic well-known prefix)."""

_PEM_PRIVATE_KEY_RE = re.compile(
    r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
"""PEM private-key blocks from BEGIN to END marker inclusive."""

_CREDENTIAL_URL_RE = re.compile(r"(?i)\b(https?://)([^/\s:@]+):([^/\s:@]+)@")
"""Credential-bearing URLs (``scheme://user:password@host``)."""


def root_cause_exception(
    error: BaseException, *, max_depth: int = DEFAULT_ROOT_CAUSE_MAX_DEPTH
) -> BaseException:
    """Return the legitimate root cause of an exception chain.

    Traversal honors Python exception chaining semantics: an explicit
    ``__cause__`` always wins; otherwise the implicit ``__context__`` is
    followed only when it is not suppressed (``raise ... from None``). A
    cycle is detected by object identity, and traversal stops at
    ``max_depth``, so pathological chains terminate deterministically.

    The returned exception is the deepest legitimate cause, never a
    serialized chain or traceback.
    """
    current = error
    seen: set[int] = set()
    depth = 0
    while depth < max_depth:
        if id(current) in seen:
            break
        seen.add(id(current))
        cause = current.__cause__
        if cause is not None:
            current = cause
            depth += 1
            continue
        context = current.__context__
        if (
            context is not None
            and not current.__suppress_context__
            and context is not current
        ):
            current = context
            depth += 1
            continue
        break
    return current


def _normalize_control_characters(message: str) -> str:
    """Normalize line endings and remove unsafe control characters.

    ``\\r\\n``/``\\r`` become ``\\n``; tabs and newlines survive so multiline
    diagnostics display; every other C0 control character and every Unicode
    control/format character (Cc/Cf/Cs/Co/Cn) is removed. Ordinary printable
    Unicode is preserved.
    """
    normalized = message.replace("\r\n", "\n").replace("\r", "\n")
    if not any(
        ord(character) < 32 or not _is_safe(character) for character in normalized
    ):
        return normalized
    return "".join(
        character
        for character in normalized
        if character in ("\n", "\t") or (ord(character) >= 32 and _is_safe(character))
    )


def _is_safe(character: str) -> bool:
    """Return True only for printable, non-control Unicode code points."""
    return unicodedata.category(character) not in {
        "Cc",
        "Cf",
        "Cs",
        "Co",
        "Cn",
    }


class ErrorMessageSanitizer:
    """Deterministic secret-free diagnostic sanitizer (PR 31F-2).

    One pipeline turns root-cause text into safe persisted prose:

    ``normalize control characters -> redact known secret values ->
    redact bounded credential patterns -> bound whitespace -> truncate``

    The sanitizer is a small immutable service object: known secret values
    are supplied at construction and never logged or persisted. It performs
    no network I/O, no environment access, no logging, and no HTML/SQL/shell
    escaping — the returned value is safe for bounding persistence and text
    rendering only.
    """

    def __init__(
        self,
        *,
        known_secrets: Sequence[str] = (),
        max_length: int = MAX_TIMELINE_ERROR_MESSAGE_LENGTH,
    ) -> None:
        """Bind the known secret values and the persisted maximum length.

        ``known_secrets`` is a bounded collection of already-resolved secret
        values from the composition/configuration boundary. Blank values are
        ignored. ``max_length`` bounds the persisted diagnostic; the
        marker-based truncation never exceeds it.
        """
        secrets = tuple(
            value for value in known_secrets if isinstance(value, str) and value.strip()
        )
        self._known_secrets = secrets
        self._max_length = max(max_length, 1)

    def sanitize(self, message: str) -> str:
        """Return the bounded, secret-free diagnostic for one message.

        ``message`` is treated as untrusted runtime text. Empty or
        whitespace-only input returns ``""`` (callers persist ``None`` or use
        :meth:`from_exception` for the exception-boundary fallback).
        """
        if not message.strip():
            return ""
        cleaned = _normalize_control_characters(message)
        cleaned = self._redact_known_secrets(cleaned)
        cleaned = _redact_patterns(cleaned)
        cleaned = self._bound_whitespace(cleaned)
        return self._truncate(cleaned)

    def from_exception(self, error: BaseException) -> str:
        """Return the sanitized diagnostic for one caught exception.

        The legitimate root cause is selected first; when its message is
        empty or whitespace-only, a safe exception-type fallback is used so
        the persisted diagnostic is never blank. The result is bounded and
        secret-free.
        """
        root = root_cause_exception(error)
        message = str(root).strip()
        if not message:
            message = _EMPTY_MESSAGE_FALLBACK
        return self.sanitize(message)

    def _redact_known_secrets(self, message: str) -> str:
        """Replace every occurrence of each known secret value."""
        for secret in self._known_secrets:
            message = message.replace(secret, REDACTED)
        return message

    @staticmethod
    def _bound_whitespace(message: str) -> str:
        """Trim outer whitespace and collapse pathological blank runs.

        Ordinary internal whitespace and single/double line breaks are
        preserved; runs of three or more newlines collapse to two so a
        diagnostic cannot become an unbounded vertical wall.
        """
        trimmed = message.strip()
        return re.sub(r"\n{3,}", "\n\n", trimmed)

    def _truncate(self, message: str) -> str:
        """Truncate to the persisted maximum with a deterministic marker.

        Redaction already happened: a secret can never be cut in half by
        truncation in a way that leaks more than the bounded text itself.
        """
        if len(message) <= self._max_length:
            return message
        return message[: self._max_length - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def _redact_patterns(message: str) -> str:
    """Apply the deterministic bounded credential/token redaction patterns.

    Each pattern is intentionally conservative and independent: misses are
    acceptable defense-in-depth, false-stripping of ordinary text is not.
    """
    message = _SECRET_ASSIGNMENT_RE.sub(r"\1 " + REDACTED, message)
    message = _BEARER_TOKEN_RE.sub("Bearer " + REDACTED, message)
    message = _JWT_RE.sub(REDACTED, message)
    message = _AWS_ACCESS_KEY_RE.sub(REDACTED, message)
    message = _PEM_PRIVATE_KEY_RE.sub(REDACTED, message)
    return _CREDENTIAL_URL_RE.sub(_redact_credential_url, message)


def _redact_credential_url(match: re.Match[str]) -> str:
    """Replace the userinfo of one credential-bearing URL with the redaction marker.

    The scheme and the host/path continue to be useful analyst diagnostics;
    only ``user:password@`` is replaced by the redaction marker.
    """
    return f"{match.group(1)}{REDACTED}@"
